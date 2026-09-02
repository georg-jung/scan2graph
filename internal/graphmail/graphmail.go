// Package graphmail sends the finished scan out through Microsoft Graph.
//
// The printer's original MIME message is long gone by the time Send is
// called: this package composes a fresh RFC 5322 message and posts it,
// base64-encoded, to Graph's MIME sendMail endpoint
// (POST /users/{sender}/sendMail, Content-Type: text/plain). Graph parses
// recipients, subject and attachments straight out of the MIME headers,
// in one request that needs no more than the Mail.Send permission.
//
// That request body is capped at ~4 MB, though, and two rounds of base64
// eat most of it before the first page, which a colour scan clears easily.
// So there is a second path, in upload.go: a draft, an upload session per
// attachment, and a send. Send routes to it by size, and only when
// LargeScans says the token carries Mail.ReadWrite - writing a draft is a
// write to the mailbox, and a deployment that never sends a big scan
// should not have to grant that.
package graphmail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/georg-jung/scan2graph/internal/msapi"
)

// maxGraphMessageBytes is Graph's documented limit on the MIME sendMail
// request body (~4 MB). A constant, not configuration: it is a property of
// the API, not something an operator can usefully change.
const maxGraphMessageBytes = 4 * 1024 * 1024

// MaxAttachmentBytes is how much scan one sendMail message can carry, and
// the number a notice quotes to the user. The MIME message base64-encodes
// every attachment and Graph's request body base64-encodes that message
// again, so two encodings' worth of the limit above is gone before the
// first page. Past this, Send needs the upload path.
const MaxAttachmentBytes = maxGraphMessageBytes * 9 / 16

// ErrTooLarge is returned by Send when the composed message would exceed
// Graph's size limit. The caller sends a notice instead. With LargeScans
// on, an attachment past MaxAttachmentBytes goes up in chunks instead, so
// the only scans that still land here are ones the SMTP cap already let
// through -- which is to say none.
var ErrTooLarge = errors.New("graphmail: message exceeds Graph's size limit")

// Client sends mail through one Microsoft Graph mailbox.
type Client struct {
	HTTP    *http.Client // must already carry a bearer token
	BaseURL string       // e.g. https://graph.microsoft.com/v1.0, no trailing slash
	Sender  string       // the mailbox to send from; also the message's From

	// LargeScans decides which path Send takes past MaxAttachmentBytes.
	// Derived at startup from the access token's roles, not configured: true
	// exactly when Mail.ReadWrite is granted.
	LargeScans bool
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
	// Stat the attachments before composing: a scan that cannot fit would
	// otherwise be base64-encoded into memory twice over, only to be thrown
	// away here.
	var attached int64
	for _, a := range m.Attachments {
		fi, err := os.Stat(a.Path)
		if err != nil {
			return fmt.Errorf("graphmail: open attachment %q: %w", a.Name, err)
		}
		attached += fi.Size()
	}
	if attached > MaxAttachmentBytes {
		if !c.LargeScans {
			return fmt.Errorf("graphmail: attachments are %d bytes, limit is %d: %w", attached, int64(MaxAttachmentBytes), ErrTooLarge)
		}
		return c.sendLarge(ctx, m)
	}

	raw, err := buildMessage(c.Sender, m)
	if err != nil {
		return err
	}
	// The stat above is an estimate: MaxAttachmentBytes cannot know what the
	// headers cost, nor the CRLF lineWrap adds every 76 characters inside the
	// inner base64. So a scan just under it can still compose too big, and
	// this is the check that knows for certain. With the upload path
	// available that is a reason to take it, not to refuse the scan - the
	// band between the two is some 60 KB wide, and a notice for a scan the
	// appliance was configured to send would be the wrong answer in it.
	if n := base64.StdEncoding.EncodedLen(len(raw)); n > maxGraphMessageBytes {
		if c.LargeScans {
			return c.sendLarge(ctx, m)
		}
		return fmt.Errorf("graphmail: message is %d bytes encoded, limit is %d: %w", n, maxGraphMessageBytes, ErrTooLarge)
	}
	body := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(body, raw)
	return c.post(ctx, body)
}

// mailboxURL is the Graph resource every call in this package hangs off.
func (c *Client) mailboxURL() string {
	return c.BaseURL + "/users/" + url.PathEscape(c.Sender)
}

// post sends the already-encoded body to sendMail.
func (c *Client) post(ctx context.Context, body []byte) error {
	resp, err := (&msapi.Client{HTTP: c.HTTP}).Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.mailboxURL()+"/sendMail", bytes.NewReader(body))
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
