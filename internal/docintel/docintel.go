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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/georg-jung/scan2graph/internal/msapi"
)

// Client talks to one Document Intelligence resource.
type Client struct {
	HTTP       *http.Client // must carry the bearer token
	Endpoint   string       // https://<resource>.cognitiveservices.azure.com, no trailing slash
	APIVersion string       // e.g. "2024-11-30"

	// sleep replaces time.Sleep in tests; nil uses the real, ctx-aware wait.
	sleep func(ctx context.Context, d time.Duration)
}

// pollInterval is the fallback cadence between polls when the API sends no
// Retry-After. Not operator-configurable, like the shared retry tuning in
// msapi.
const pollInterval = 3 * time.Second

// SearchablePDF submits pdf to the prebuilt-read model with output=pdf,
// polls the resulting operation to completion, and streams the resulting
// searchable PDF to out. pdf must support seeking back to the start, since
// the submission may need a retry.
func (c *Client) SearchablePDF(ctx context.Context, pdf io.ReadSeeker, out io.Writer) error {
	size, err := pdf.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("docintel: seek document: %w", err)
	}

	resp, err := c.do(ctx, func(ctx context.Context) (*http.Request, error) {
		if _, err := pdf.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.analyzeURL(), pdf)
		if err != nil {
			return nil, err
		}
		req.ContentLength = size
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

	resultURL, err := c.poll(ctx, opLoc)
	if err != nil {
		return err
	}

	resp, err = c.do(ctx, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, resultURL, nil)
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

// apiError is the {"error":{"message":...}} envelope Document Intelligence
// uses for a failed/canceled operation.
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
// the URL of the searchable PDF result on success: the same
// Operation-Location the analyze call gave us, with /pdf appended to its
// path, which is where analyzeResults exposes the rendered output.
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
		wait := msapi.RetryAfter(resp.Header, pollInterval)
		resp.Body.Close()
		if decErr != nil {
			return "", fmt.Errorf("docintel: decode operation status: %w", decErr)
		}

		switch st.Status {
		case "succeeded":
			u, err := url.Parse(opLoc)
			if err != nil {
				return "", fmt.Errorf("docintel: parse Operation-Location: %w", err)
			}
			u.Path += "/pdf"
			return u.String(), nil
		case "failed", "canceled":
			msg := "no details provided"
			if st.Error != nil && st.Error.Message != "" {
				msg = st.Error.Message
			}
			return "", fmt.Errorf("docintel: analysis %s: %s", st.Status, msg)
		}
		if !c.api().Wait(ctx, wait) {
			return "", ctx.Err()
		}
	}
}

// api returns the shared HTTP+retry plumbing for this client.
func (c *Client) api() *msapi.Client {
	return &msapi.Client{HTTP: c.HTTP, Sleep: c.sleep}
}

// do sends one logical request through the shared msapi retry loop and
// wraps any error so it is clear which client failed.
func (c *Client) do(ctx context.Context, newReq func(context.Context) (*http.Request, error)) (*http.Response, error) {
	resp, err := c.api().Do(ctx, newReq)
	if err != nil {
		return nil, fmt.Errorf("docintel: %w", err)
	}
	return resp, nil
}
