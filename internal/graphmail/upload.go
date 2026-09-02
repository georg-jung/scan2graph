package graphmail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/georg-jung/scan2graph/internal/msapi"
)

// uploadChunkBytes is how much of a scan one PUT carries. Graph wants every
// chunk but the last to be a multiple of 320 KiB, and the request to stay
// under 4 MB: 12 * 320 KiB is 3.75 MiB, the largest multiple that fits. A
// constant, not a knob -- the only numbers that work here are Graph's.
const uploadChunkBytes = 12 * 320 * 1024

// uploadClient is the only client the chunk PUTs may use, and it is
// deliberately not c.HTTP.
//
// A session's uploadUrl is already authorized and points at a host Graph
// picks (*.outlook.com today), not at graph.microsoft.com. Sending it a
// request from c.HTTP would hand the appliance's Graph token -- which reads
// and writes every mailbox in the tenant -- to a host the appliance never
// chose. So this one is plain: no credentials, its own timeout, and a
// redirect surfaced as a failed response rather than chased somewhere else.
// Do not "simplify" the upload onto c.HTTP; that is the whole point of it.
var uploadClient = &http.Client{
	Timeout: 2 * time.Minute, // one chunk, not the whole scan
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// sendLarge delivers m the long way round: create it as a draft, stream
// each attachment into it through its own upload session, then send the
// draft. Four calls instead of sendMail's one, and Mail.ReadWrite instead
// of Mail.Send, which is why Send only comes here for a scan that cannot
// fit in a single request.
//
// A failure part way through leaves an unsent draft in the sender's
// mailbox. Nothing half-composed reaches the recipient, which is what
// matters; deleting it would be a fifth call for something the operator can
// see in Drafts.
func (c *Client) sendLarge(ctx context.Context, m Message) error {
	id, err := c.createDraft(ctx, m)
	if err != nil {
		return err
	}
	for _, a := range m.Attachments {
		if err := c.uploadAttachment(ctx, id, a); err != nil {
			return err
		}
	}
	return c.postJSON(ctx, "/messages/"+url.PathEscape(id)+"/send", nil, nil)
}

// createDraft creates m as a draft message and returns its id. The draft is
// the same mail the MIME path composes, minus the attachments, which only
// exist on the mailbox side once their upload sessions complete.
func (c *Client) createDraft(ctx context.Context, m Message) (string, error) {
	to := make([]any, len(m.To))
	for i, addr := range m.To {
		to[i] = map[string]any{"emailAddress": map[string]string{"address": addr}}
	}
	var out struct {
		ID string `json:"id"`
	}
	err := c.postJSON(ctx, "/messages", map[string]any{
		"subject": m.Subject,
		// Text, not HTML: Graph renders the body as written, and these
		// bodies are the same few plain lines the MIME path sends.
		"body":         map[string]string{"contentType": "Text", "content": m.Body},
		"toRecipients": to,
	}, &out)
	if err != nil {
		return "", err
	}
	return out.ID, nil
}

// uploadAttachment opens an upload session for a and feeds the file into it
// one chunk at a time, reusing a single buffer so a scan is never held in
// memory whole.
func (c *Client) uploadAttachment(ctx context.Context, draftID string, a Attachment) error {
	f, err := os.Open(a.Path)
	if err != nil {
		return fmt.Errorf("graphmail: open attachment %q: %w", a.Name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("graphmail: stat attachment %q: %w", a.Name, err)
	}
	size := fi.Size()

	var session struct {
		UploadURL string `json:"uploadUrl"`
	}
	err = c.postJSON(ctx, "/messages/"+url.PathEscape(draftID)+"/attachments/createUploadSession", map[string]any{
		"AttachmentItem": map[string]any{"attachmentType": "file", "name": a.Name, "size": size},
	}, &session)
	if err != nil {
		return err
	}
	if session.UploadURL == "" {
		return fmt.Errorf("graphmail: upload session for %q carries no uploadUrl", a.Name)
	}

	api := &msapi.Client{HTTP: uploadClient}
	buf := make([]byte, uploadChunkBytes)
	for off := int64(0); off < size; {
		n := int(min(int64(len(buf)), size-off))
		if _, err := io.ReadFull(f, buf[:n]); err != nil {
			return fmt.Errorf("graphmail: read attachment %q: %w", a.Name, err)
		}
		contentRange := fmt.Sprintf("bytes %d-%d/%d", off, off+int64(n)-1, size)
		resp, err := api.Do(ctx, func(ctx context.Context) (*http.Request, error) {
			// Read the chunk out of buf, not out of f: Do rebuilds the
			// request on every attempt, and a reader the first attempt
			// consumed would upload nothing on the second.
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, session.UploadURL, bytes.NewReader(buf[:n]))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Content-Range", contentRange)
			return req, nil
		})
		if err != nil {
			return fmt.Errorf("graphmail: upload attachment %q: %w", a.Name, err)
		}
		resp.Body.Close()
		off += int64(n)
	}
	return nil
}

// postJSON POSTs body, if any, to a path under the sender's mailbox and
// decodes the response into out, which may be nil to discard it.
func (c *Client) postJSON(ctx context.Context, path string, body, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return fmt.Errorf("graphmail: encode %s request: %w", path, err)
		}
	}
	resp, err := (&msapi.Client{HTTP: c.HTTP}).Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.mailboxURL()+path, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		if raw != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("graphmail: %w", err)
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("graphmail: decode %s response: %w", path, err)
	}
	return nil
}
