// Package docintel is a small REST client for Azure Document Intelligence's
// prebuilt-read model, used to turn a scanned PDF into a searchable one.
//
// There is no Azure SDK dependency, by project policy: three plain HTTP
// calls (submit, poll, fetch) don't need one. The caller supplies an
// *http.Client that already carries a bearer token (see cmd/scan2graph),
// and a context whose deadline bounds the whole operation - this package
// never sets its own timeout.
package docintel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

// Client talks to one Document Intelligence resource.
type Client struct {
	HTTP       *http.Client // must carry the bearer token
	Endpoint   string       // https://<resource>.cognitiveservices.azure.com, no trailing slash
	APIVersion string       // e.g. "2024-11-30"

	// sleep replaces time.Sleep in tests; nil uses the real, ctx-aware wait.
	sleep func(ctx context.Context, d time.Duration)
}

// ErrPermanent marks a failure the caller should not retry: a non-429 4xx
// response, or the API reporting that analysis itself failed or was
// canceled. Wrapped with %w so errors.Is(err, ErrPermanent) is true; the
// pipeline uses that to decide between failing the job and trying again
// later.
var ErrPermanent = errors.New("docintel: permanent failure")

// Tuning constants. Not operator-configurable: no realistic deployment of
// this appliance benefits from changing them.
const (
	maxAttempts  = 4 // per logical request, shared by all three calls
	baseBackoff  = 500 * time.Millisecond
	maxWait      = 30 * time.Second // clamp for both backoff and Retry-After
	pollInterval = 3 * time.Second  // fallback cadence when the API sends no Retry-After
)

// SearchablePDF submits pdf to the prebuilt-read model with output=pdf,
// polls the resulting operation to completion, and streams the resulting
// searchable PDF to out.
//
// pdf is read into memory once, up front: unlike the result (which can be
// streamed straight through), the request body must be resendable if the
// initial submission itself needs a retry, and io.Reader gives no way to
// rewind. Scans handled by this appliance are tens of megabytes at most, so
// that is a deliberate, bounded trade-off rather than a general buffering
// policy - the searchable result, which can be just as large, is never
// buffered.
func (c *Client) SearchablePDF(ctx context.Context, pdf io.Reader, out io.Writer) error {
	body, err := io.ReadAll(pdf)
	if err != nil {
		return fmt.Errorf("docintel: read document: %w", err)
	}

	resp, err := c.do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.analyzeURL(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/pdf")
		return req, nil
	})
	if err != nil {
		return err
	}
	opLoc := resp.Header.Get("Operation-Location")
	resp.Body.Close()
	if opLoc == "" {
		return errors.New("docintel: analyze response has no Operation-Location header")
	}

	resultID, err := c.poll(ctx, opLoc)
	if err != nil {
		return err
	}

	resp, err = c.do(ctx, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.fetchURL(resultID), nil)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("docintel: stream searchable pdf: %w", err)
	}
	return nil
}

func (c *Client) analyzeURL() string {
	q := url.Values{"api-version": {c.APIVersion}, "output": {"pdf"}}
	return c.Endpoint + "/documentintelligence/documentModels/prebuilt-read:analyze?" + q.Encode()
}

func (c *Client) fetchURL(resultID string) string {
	q := url.Values{"api-version": {c.APIVersion}}
	return c.Endpoint + "/documentintelligence/documentModels/prebuilt-read/analyzeResults/" + url.PathEscape(resultID) + "/pdf?" + q.Encode()
}

// apiError is the {"error":{"message":...}} envelope Document Intelligence
// uses both for HTTP-level failures and for a failed/canceled operation.
type apiError struct {
	Message string `json:"message"`
}

// operationStatus is the subset of the operation-status body this client
// needs; the (large) analyzeResult payload is deliberately not modeled.
type operationStatus struct {
	Status string    `json:"status"` // notStarted, running, succeeded, failed, canceled
	Error  *apiError `json:"error"`
}

// poll GETs opLoc until the operation reaches a terminal state, returning
// the result id (parsed out of opLoc itself) on success.
func (c *Client) poll(ctx context.Context, opLoc string) (string, error) {
	for {
		resp, err := c.do(ctx, func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, opLoc, nil)
		})
		if err != nil {
			return "", err
		}
		var st operationStatus
		decErr := json.NewDecoder(resp.Body).Decode(&st)
		wait := retryAfter(resp.Header, pollInterval)
		resp.Body.Close()
		if decErr != nil {
			return "", fmt.Errorf("docintel: decode operation status: %w", decErr)
		}

		switch st.Status {
		case "succeeded":
			return resultIDFromLocation(opLoc)
		case "failed", "canceled":
			msg := "no details provided"
			if st.Error != nil && st.Error.Message != "" {
				msg = st.Error.Message
			}
			return "", fmt.Errorf("%w: analysis %s: %s", ErrPermanent, st.Status, msg)
		}
		if !c.wait(ctx, wait) {
			return "", ctx.Err()
		}
	}
}

func resultIDFromLocation(opLoc string) (string, error) {
	u, err := url.Parse(opLoc)
	if err != nil {
		return "", fmt.Errorf("docintel: parse Operation-Location: %w", err)
	}
	id := path.Base(u.Path)
	if id == "" || id == "." || id == "/" {
		return "", fmt.Errorf("docintel: Operation-Location has no result id")
	}
	return id, nil
}

// do sends one logical request, retrying on 429, 5xx and network errors up
// to maxAttempts times and honouring Retry-After. newReq builds a fresh
// *http.Request on every call, since a request (and its body) is used up
// after one attempt. On success the response is returned with its body
// open, for the caller to read and close. A non-429 4xx is permanent and
// returned immediately, wrapped in ErrPermanent; context cancellation is
// never retried.
func (c *Client) do(ctx context.Context, newReq func(context.Context) (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := newReq(ctx)
		if err != nil {
			return nil, fmt.Errorf("docintel: build request: %w", err)
		}
		resp, err := c.HTTP.Do(req)

		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("docintel: %s %s: %w", req.Method, req.URL.Path, err)
		case resp.StatusCode < 300:
			return resp, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("docintel: %s %s: %s", req.Method, req.URL.Path, apiErrorMessage(resp))
		default:
			return nil, fmt.Errorf("%w: %s %s: %s", ErrPermanent, req.Method, req.URL.Path, apiErrorMessage(resp))
		}

		if attempt == maxAttempts {
			break
		}
		wait := backoff(attempt)
		if resp != nil {
			wait = retryAfter(resp.Header, wait)
		}
		if !c.wait(ctx, wait) {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("docintel: giving up after %d attempts: %w", maxAttempts, lastErr)
}

// apiErrorMessage reads and closes resp.Body, returning the API's own error
// message where the body carries one and the HTTP status line otherwise.
func apiErrorMessage(resp *http.Response) string {
	defer resp.Body.Close()
	var body struct {
		Error apiError `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) == nil && body.Error.Message != "" {
		return body.Error.Message
	}
	return resp.Status
}

// retryAfter parses the Retry-After header (seconds or an HTTP date),
// falling back to d when absent or unparsable, and clamps the result to
// maxWait.
func retryAfter(h http.Header, fallback time.Duration) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return fallback
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return fallback
		}
		return min(time.Duration(secs)*time.Second, maxWait)
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(time.Until(t), 0), maxWait)
	}
	return fallback
}

// backoff is the wait before retry attempt+1 when the response carries no
// Retry-After: exponential, capped at maxWait.
func backoff(attempt int) time.Duration {
	return min(baseBackoff<<(attempt-1), maxWait)
}

// wait pauses for d, returning false (without waiting out d) as soon as ctx
// is done.
func (c *Client) wait(ctx context.Context, d time.Duration) bool {
	sleep := c.sleep
	if sleep == nil {
		sleep = ctxSleep
	}
	sleep(ctx, d)
	return ctx.Err() == nil
}

func ctxSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
