package graphmail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"os"
	"strings"
	"time"
)

// buildMessage renders m as a raw RFC 5322 message From sender: a single
// text/plain part when there are no attachments, otherwise
// multipart/mixed with the text part first and one application/pdf part
// per attachment.
func buildMessage(sender string, m Message) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("From: " + sender + "\r\n")
	buf.WriteString("To: " + strings.Join(m.To, ", ") + "\r\n")
	buf.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", m.Subject) + "\r\n")
	buf.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")

	if len(m.Attachments) == 0 {
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		buf.WriteString(m.Body)
		return buf.Bytes(), nil
	}

	mw := multipart.NewWriter(&buf)
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", mw.Boundary())

	tw, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, fmt.Errorf("graphmail: build message: %w", err)
	}
	if _, err := tw.Write([]byte(m.Body)); err != nil {
		return nil, fmt.Errorf("graphmail: build message: %w", err)
	}

	for _, a := range m.Attachments {
		if err := attachFile(mw, a); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("graphmail: build message: %w", err)
	}
	return buf.Bytes(), nil
}

// attachFile streams a's file into one application/pdf part, base64
// encoding it as it goes so the file is never held in memory whole.
func attachFile(mw *multipart.Writer, a Attachment) error {
	f, err := os.Open(a.Path)
	if err != nil {
		return fmt.Errorf("graphmail: open attachment %q: %w", a.Name, err)
	}
	defer f.Close()

	h := textproto.MIMEHeader{
		"Content-Type":              {"application/pdf"},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {fmt.Sprintf(`attachment; filename="%s"`, mime.QEncoding.Encode("utf-8", a.Name))},
	}
	pw, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("graphmail: build message: %w", err)
	}

	enc := base64.NewEncoder(base64.StdEncoding, &lineWrap{w: pw})
	if _, err := io.Copy(enc, f); err != nil {
		return fmt.Errorf("graphmail: read attachment %q: %w", a.Name, err)
	}
	return enc.Close()
}

// lineWrap inserts a CRLF every 76 encoded bytes, as RFC 2045 requires of
// base64 body content (and as real SMTP line-length limits require in
// practice, since Graph relays this message on).
type lineWrap struct {
	w   io.Writer
	col int
}

func (l *lineWrap) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(76-l.col, len(p))
		if _, err := l.w.Write(p[:n]); err != nil {
			return written, err
		}
		written += n
		l.col += n
		p = p[n:]
		if l.col == 76 {
			if _, err := l.w.Write([]byte("\r\n")); err != nil {
				return written, err
			}
			l.col = 0
		}
	}
	return written, nil
}
