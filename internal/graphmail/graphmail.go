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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/georg-jung/scan2graph/internal/msapi"
)

// maxGraphMessageBytes is Graph's documented limit on the MIME sendMail
// request body (~4 MB). A constant, not configuration: it is a property of
// the API, not something an operator can usefully change.
const maxGraphMessageBytes = 4 * 1024 * 1024

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
	body := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	if len(body) > maxGraphMessageBytes {
		return fmt.Errorf("graphmail: message is %d bytes encoded, limit is %d: %w", len(body), maxGraphMessageBytes, ErrTooLarge)
	}
	base64.StdEncoding.Encode(body, raw)
	return c.post(ctx, body)
}

// post sends the already-encoded body to sendMail through the shared msapi
// retry loop, wrapping any error so it is clear which service failed.
func (c *Client) post(ctx context.Context, body []byte) error {
	endpoint := c.BaseURL + "/users/" + url.PathEscape(c.Sender) + "/sendMail"
	resp, err := (&msapi.Client{HTTP: c.HTTP}).Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "text/plain")
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("graphmail: %w", err)
	}
	resp.Body.Close()
	return nil
}
