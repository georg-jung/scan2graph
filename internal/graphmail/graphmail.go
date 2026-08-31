// Package graphmail sends the finished scan out through Microsoft Graph.
//
// The printer's original MIME message is long gone by the time Send is
// called: this package composes a fresh RFC 5322 message and posts it,
// base64-encoded, to Graph's MIME sendMail endpoint
// (POST /users/{sender}/sendMail, Content-Type: text/plain). That single
// form is why there is no separate small-attachment vs. upload-session code
// path here -- Graph parses recipients, subject and attachments straight
// out of the MIME headers, up to a size limit Send checks before ever
// making a request.
package graphmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// maxGraphMessageBytes is Graph's documented limit on the MIME sendMail
// request body (~4 MB). A constant, not configuration: it is a property of
// the API, not something an operator can usefully change.
const maxGraphMessageBytes = 4 * 1024 * 1024

// maxAttempts bounds the retry loop, including the first try.
const maxAttempts = 4

// ErrTooLarge is returned by Send when the composed message would exceed
// Graph's size limit. The caller sends a notice instead.
var ErrTooLarge = errors.New("graphmail: message exceeds Graph's size limit")

// Client sends mail through one Microsoft Graph mailbox.
type Client struct {
	HTTP    *http.Client // must already carry a bearer token
	BaseURL string       // e.g. https://graph.microsoft.com/v1.0, no trailing slash
	Sender  string       // the mailbox to send from; also the message's From
}

// Message is one email to compose and send. Attachments, if any, are
// streamed from disk while sending.
type Message struct {
	To          []string
	Subject     string
	Body        string // text/plain, a few lines
	Attachments []Attachment
}

// Attachment is one file to attach, sent as application/pdf.
type Attachment struct {
	Name string // Content-Disposition filename
	Path string // file to read on disk
}

// Send composes m into an RFC 5322 message From c.Sender and posts it to
// Graph. A Message with no Attachments is how a notice is sent -- there is
// no second code path for that.
func (c *Client) Send(ctx context.Context, m Message) error {
	raw, err := buildMessage(c.Sender, m)
	if err != nil {
		return err
	}
	if n := base64.StdEncoding.EncodedLen(len(raw)); n > maxGraphMessageBytes {
		return fmt.Errorf("graphmail: message is %d bytes encoded, limit is %d: %w", n, maxGraphMessageBytes, ErrTooLarge)
	}
	body := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(body, raw)
	return c.post(ctx, body)
}

// post sends the already-encoded body to sendMail, retrying transient
// failures. 429 and 5xx are retried, honouring Retry-After; any other 4xx
// is permanent. Context cancellation always wins and is never retried.
func (c *Client) post(ctx context.Context, body []byte) error {
	endpoint := c.BaseURL + "/users/" + url.PathEscape(c.Sender) + "/sendMail"

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("graphmail: build request: %w", err)
		}
		req.Header.Set("Content-Type", "text/plain")

		resp, err := c.HTTP.Do(req)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			lastErr = fmt.Errorf("graphmail: send: %w", err)
			if attempt == maxAttempts {
				return lastErr
			}
			if err := wait(ctx, 0); err != nil {
				return err
			}
			continue
		}

		if resp.StatusCode == http.StatusAccepted {
			resp.Body.Close()
			return nil
		}

		lastErr = graphError(resp)
		retryAfter := resp.Header.Get("Retry-After")
		resp.Body.Close()

		if !retryableStatus(resp.StatusCode) || attempt == maxAttempts {
			return lastErr
		}
		if err := wait(ctx, retryDelay(retryAfter)); err != nil {
			return err
		}
	}
	return lastErr
}

func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// retryDelay parses a Retry-After header (seconds, or an HTTP date) and
// defaults to no extra wait when it is absent or unparseable -- attempts
// are already bounded by maxAttempts.
func retryDelay(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// wait pauses for d, or returns ctx's error if it is cancelled first.
func wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// graphError turns a non-202 response into an error, pulling Graph's
// error.code/error.message out of the JSON body when present.
func graphError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &parsed) == nil && parsed.Error.Message != "" {
		return fmt.Errorf("graphmail: graph error %s: %s: %s", resp.Status, parsed.Error.Code, parsed.Error.Message)
	}
	return fmt.Errorf("graphmail: graph error %s", resp.Status)
}
