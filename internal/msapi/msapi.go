// Package msapi is the shared HTTP plumbing for the two Microsoft REST
// clients in this codebase, docintel and graphmail, and nothing more: a
// small bounded retry loop with Retry-After support and a context-aware
// sleep.
package msapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Tuning constants. Not operator-configurable: no realistic deployment of
// this appliance benefits from changing them.
const (
	maxAttempts = 4 // per logical request
	baseBackoff = 500 * time.Millisecond
	maxWait     = 30 * time.Second // clamp for both backoff and Retry-After
)

// Client is the retry plumbing wrapped around one *http.Client.
type Client struct {
	HTTP *http.Client // must carry the bearer token

	// Sleep replaces time.Sleep in tests; nil uses the real, ctx-aware wait.
	Sleep func(ctx context.Context, d time.Duration)
}

// Do sends one logical request, retrying on 429, 5xx and network errors up
// to maxAttempts times and honouring Retry-After. newReq builds a fresh
// *http.Request on every call, since a request (and its body) is used up
// after one attempt. On success the response is returned with its body
// open, for the caller to read and close. A non-429 4xx is returned
// immediately, without retrying; context cancellation is never retried.
func (c *Client) Do(ctx context.Context, newReq func(context.Context) (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := newReq(ctx)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		resp, err := c.HTTP.Do(req)

		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
		case resp.StatusCode < 300:
			return resp, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s %s: %s", req.Method, req.URL.Path, apiErrorMessage(resp))
		default:
			return nil, fmt.Errorf("%s %s: %s", req.Method, req.URL.Path, apiErrorMessage(resp))
		}

		if attempt == maxAttempts {
			break
		}
		wait := backoff(attempt)
		if resp != nil {
			wait = RetryAfter(resp.Header, wait)
		}
		if !c.Wait(ctx, wait) {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", maxAttempts, lastErr)
}

// apiError is the {"error":{"message":...}} envelope both APIs use for
// HTTP-level failures.
type apiError struct {
	Message string `json:"message"`
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

// RetryAfter parses the Retry-After header (seconds or an HTTP date),
// falling back to d when absent or unparsable, and clamps the result to
// maxWait. Exported for docintel's poll, which uses it for its own polling
// cadence, not just the retry-on-error loop above.
func RetryAfter(h http.Header, fallback time.Duration) time.Duration {
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

// Wait pauses for d, returning false (without waiting out d) as soon as ctx
// is done. Exported for callers, like docintel's poll, that need the same
// context-aware, test-injectable pause outside of Do's own retry loop.
func (c *Client) Wait(ctx context.Context, d time.Duration) bool {
	sleep := c.Sleep
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
