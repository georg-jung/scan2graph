package graphmail_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georg-jung/scan2graph/internal/graphmail"
)

// testSender stands in for the configured Graph mailbox. A plain address so
// path-escaping is a no-op and request-path assertions stay simple.
const testSender = "scanner@example.test"

func writeTemp(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// scriptedResponse is one canned reply for TestSend_HTTPBehavior's server.
type scriptedResponse struct {
	status     int
	retryAfter string
	body       []byte
}

func TestSend_MessageShape(t *testing.T) {
	pdfA := []byte("%PDF-1.4 fake pdf A, some bytes to tell it apart from B\n%%EOF\n")
	pdfB := []byte("%PDF-1.4 fake pdf B, longer content so the sizes also differ\nmore lines\n%%EOF\n")
	pathA := writeTemp(t, "a.pdf", pdfA)
	pathB := writeTemp(t, "b.pdf", pdfB)

	type wantPDF struct {
		name    string
		content []byte
	}

	cases := []struct {
		name        string
		msg         graphmail.Message
		wantSubject string
		wantPDFs    []wantPDF
	}{
		{
			name:        "no attachments",
			msg:         graphmail.Message{To: []string{"alice@corp.example"}, Subject: "Scan", Body: "Your scan is attached.\n"},
			wantSubject: "Scan",
		},
		{
			name: "two attachments",
			msg: graphmail.Message{
				To: []string{"alice@corp.example"}, Subject: "Two scans", Body: "Two documents attached.\n",
				Attachments: []graphmail.Attachment{{Name: "a.pdf", Path: pathA}, {Name: "b.pdf", Path: pathB}},
			},
			wantSubject: "Two scans",
			wantPDFs:    []wantPDF{{"a.pdf", pdfA}, {"b.pdf", pdfB}},
		},
		{
			name: "non-ASCII attachment filename",
			msg: graphmail.Message{
				To: []string{"alice@corp.example"}, Subject: "Scan", Body: "Your scan is attached.\n",
				Attachments: []graphmail.Attachment{{Name: "Bericht für Müller.pdf", Path: pathA}},
			},
			wantSubject: "Scan",
			wantPDFs:    []wantPDF{{"Bericht für Müller.pdf", pdfA}},
		},
		{
			name: "notice body with several lines",
			msg: graphmail.Message{
				To: []string{"alice@corp.example"}, Subject: "Scan not delivered",
				Body: "Text recognition failed.\n\nYou can download it here:\nhttps://scan.example.invalid/scan/abc\n",
			},
			wantSubject: "Scan not delivered",
		},
		{
			name:        "non-ASCII subject",
			msg:         graphmail.Message{To: []string{"alice@corp.example"}, Subject: "Bericht für Müller", Body: "Anbei der Scan.\n"},
			wantSubject: "Bericht für Müller",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath, gotContentType string
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				gotContentType = r.Header.Get("Content-Type")
				gotBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer srv.Close()

			c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
			if err := c.Send(context.Background(), tc.msg); err != nil {
				t.Fatalf("Send: %v", err)
			}

			if gotMethod != http.MethodPost {
				t.Errorf("method = %q, want POST", gotMethod)
			}
			if want := "/users/" + testSender + "/sendMail"; gotPath != want {
				t.Errorf("path = %q, want %q", gotPath, want)
			}
			if gotContentType != "text/plain" {
				t.Errorf("Content-Type = %q, want text/plain", gotContentType)
			}

			raw, err := base64.StdEncoding.DecodeString(string(gotBody))
			if err != nil {
				t.Fatalf("request body did not base64-decode: %v", err)
			}
			m, err := mail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("decoded body is not a valid RFC 5322 message: %v", err)
			}

			if got := m.Header.Get("From"); got != testSender {
				t.Errorf("From = %q, want %q", got, testSender)
			}
			if got := m.Header.Get("To"); got != strings.Join(tc.msg.To, ", ") {
				t.Errorf("To = %q, want %q", got, strings.Join(tc.msg.To, ", "))
			}
			if got := m.Header.Get("MIME-Version"); got != "1.0" {
				t.Errorf("MIME-Version = %q, want 1.0", got)
			}
			if _, err := mail.ParseDate(m.Header.Get("Date")); err != nil {
				t.Errorf("Date = %q does not parse: %v", m.Header.Get("Date"), err)
			}

			wd := mime.WordDecoder{}
			gotSubject, err := wd.DecodeHeader(m.Header.Get("Subject"))
			if err != nil {
				t.Fatalf("decode Subject header: %v", err)
			}
			if gotSubject != tc.wantSubject {
				t.Errorf("Subject = %q, want %q", gotSubject, tc.wantSubject)
			}

			// The body goes in with plain "\n" line breaks and must come out
			// with the CRLFs the rest of the message uses.
			wantBody := strings.ReplaceAll(tc.msg.Body, "\n", "\r\n")

			if len(tc.wantPDFs) == 0 {
				body, _ := io.ReadAll(m.Body)
				if string(body) != wantBody {
					t.Errorf("body = %q, want %q", body, wantBody)
				}
				return
			}

			mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
			if err != nil || !strings.HasPrefix(mt, "multipart/") {
				t.Fatalf("Content-Type = %q (parse err %v), want multipart/*", m.Header.Get("Content-Type"), err)
			}
			mr := multipart.NewReader(m.Body, params["boundary"])

			textPart, err := mr.NextPart()
			if err != nil {
				t.Fatalf("read text part: %v", err)
			}
			textBody, _ := io.ReadAll(textPart)
			if string(textBody) != wantBody {
				t.Errorf("text part = %q, want %q", textBody, wantBody)
			}

			for _, want := range tc.wantPDFs {
				p, err := mr.NextPart()
				if err != nil {
					t.Fatalf("read attachment part for %s: %v", want.name, err)
				}
				if ct := p.Header.Get("Content-Type"); ct != "application/pdf" {
					t.Errorf("attachment %s Content-Type = %q, want application/pdf", want.name, ct)
				}
				if cte := p.Header.Get("Content-Transfer-Encoding"); cte != "base64" {
					t.Errorf("attachment %s Content-Transfer-Encoding = %q, want base64", want.name, cte)
				}
				_, dparams, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
				if err != nil {
					t.Fatalf("parse Content-Disposition for %s: %v", want.name, err)
				}
				// Compared raw: a filename parameter is RFC 2231 encoded, and a
				// receiving parser hands back an RFC 2047 encoded word verbatim.
				if dparams["filename"] != want.name {
					t.Errorf("attachment filename = %q, want %q", dparams["filename"], want.name)
				}
				decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
				if err != nil {
					t.Fatalf("base64-decode attachment %s: %v", want.name, err)
				}
				if !bytes.Equal(decoded, want.content) {
					t.Errorf("attachment %s content differs from source file", want.name)
				}
			}
			if _, err := mr.NextPart(); err != io.EOF {
				t.Errorf("message carries an unexpected extra part (err = %v)", err)
			}
		})
	}
}

// A subject the store let through at its 200 rune cap must not produce a
// header line past RFC 5322's 998 octet limit: mime.QEncoding joins its
// encoded words with a plain space, which is not a fold.
func TestSend_LongSubjectIsFolded(t *testing.T) {
	subject := strings.Repeat("請求書", 66) + "領収" // 200 runes, ~600 octets encoded well past 998

	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
	if err := c.Send(context.Background(), graphmail.Message{
		To: []string{"alice@corp.example"}, Subject: subject, Body: "Your scan is attached.\n",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(string(gotBody))
	if err != nil {
		t.Fatalf("request body did not base64-decode: %v", err)
	}
	for i, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("line %d is %d octets, RFC 5322 allows at most 998", i+1, len(line))
		}
	}

	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("folded message no longer parses: %v", err)
	}
	got, err := (&mime.WordDecoder{}).DecodeHeader(m.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("decode Subject header: %v", err)
	}
	if got != subject {
		t.Errorf("Subject did not survive folding:\n got %q\nwant %q", got, subject)
	}
}

func TestSend_HTTPBehavior(t *testing.T) {
	accessDenied := []byte(`{"error":{"code":"ErrorAccessDenied","message":"Access is denied. Check credentials and try again."}}`)

	cases := []struct {
		name         string
		responses    []scriptedResponse
		wantRequests int32
		wantErr      bool
		wantContains string
	}{
		{
			name:         "429 then 202",
			responses:    []scriptedResponse{{status: http.StatusTooManyRequests, retryAfter: "0"}, {status: http.StatusAccepted}},
			wantRequests: 2,
		},
		{
			name:         "500 then 202",
			responses:    []scriptedResponse{{status: http.StatusInternalServerError, retryAfter: "0"}, {status: http.StatusAccepted}},
			wantRequests: 2,
		},
		{
			name: "retry budget exhausted",
			responses: []scriptedResponse{
				{status: http.StatusServiceUnavailable, retryAfter: "0"},
				{status: http.StatusServiceUnavailable, retryAfter: "0"},
				{status: http.StatusServiceUnavailable, retryAfter: "0"},
				{status: http.StatusServiceUnavailable, retryAfter: "0"},
			},
			wantRequests: 4,
			wantErr:      true,
		},
		{
			name:         "403 surfaces Graph's error message and does not retry",
			responses:    []scriptedResponse{{status: http.StatusForbidden, body: accessDenied}},
			wantRequests: 1,
			wantErr:      true,
			wantContains: "Access is denied",
		},
	}

	for _, tc := range cases {
		// In parallel: every retry now waits out at least msapi's base
		// backoff, so running these four one after another would be the
		// slowest thing in the suite.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var n int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := int(atomic.AddInt32(&n, 1)) - 1
				if i >= len(tc.responses) {
					t.Fatalf("unexpected request %d, only %d responses scripted", i+1, len(tc.responses))
				}
				resp := tc.responses[i]
				if resp.retryAfter != "" {
					w.Header().Set("Retry-After", resp.retryAfter)
				}
				if len(resp.body) > 0 {
					w.Header().Set("Content-Type", "application/json")
				}
				w.WriteHeader(resp.status)
				w.Write(resp.body)
			}))
			defer srv.Close()

			c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
			err := c.Send(context.Background(), graphmail.Message{To: []string{"alice@corp.example"}, Subject: "Scan", Body: "hi\n"})

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantContains != "" && (err == nil || !strings.Contains(err.Error(), tc.wantContains)) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantContains)
			}
			if got := atomic.LoadInt32(&n); got != tc.wantRequests {
				t.Errorf("requests = %d, want %d", got, tc.wantRequests)
			}
		})
	}
}

func TestSend_TooLarge(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
	// ~4 MiB of body text alone base64-encodes past the limit, no attachment needed.
	huge := strings.Repeat("a", 4*1024*1024)
	err := c.Send(context.Background(), graphmail.Message{To: []string{"alice@corp.example"}, Subject: "Scan", Body: huge})

	if !errors.Is(err, graphmail.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Errorf("requests = %d, want 0 (no request should be made)", got)
	}
}

// A scan that cannot fit must be refused from the file size alone. Composing
// the message first would hold the whole thing base64-encoded in memory,
// twice over, just to throw it away.
func TestSend_TooLargeAttachmentIsNeverComposed(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Sparse, so the test costs no disk and no time; only its size matters.
	path := filepath.Join(t.TempDir(), "huge.pdf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(graphmail.MaxAttachmentBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = c.Send(context.Background(), graphmail.Message{
		To: []string{"alice@corp.example"}, Subject: "Scan", Body: "hi\n",
		Attachments: []graphmail.Attachment{{Name: "huge.pdf", Path: path}},
	})
	runtime.ReadMemStats(&after)

	if !errors.Is(err, graphmail.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > graphmail.MaxAttachmentBytes {
		t.Errorf("Send allocated %d bytes for a message it refuses to send, want well under the %d byte scan",
			grew, graphmail.MaxAttachmentBytes)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Errorf("requests = %d, want 0", got)
	}
}

func TestSend_MissingAttachmentFile(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
	err := c.Send(context.Background(), graphmail.Message{
		To: []string{"alice@corp.example"}, Subject: "Scan", Body: "hi\n",
		Attachments: []graphmail.Attachment{{Name: "missing.pdf", Path: filepath.Join(t.TempDir(), "missing.pdf")}},
	})
	if err == nil {
		t.Fatal("Send: want an error, the attachment file does not exist")
	}
	if !strings.Contains(err.Error(), "missing.pdf") {
		t.Errorf("err = %v, want it to mention the attachment name", err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Errorf("requests = %d, want 0 (message must be built before any request)", got)
	}
}

func TestSend_ContextCancellation(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Retry-After", "5") // far longer than the context's deadline below
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := &graphmail.Client{HTTP: srv.Client(), BaseURL: srv.URL, Sender: testSender}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.Send(ctx, graphmail.Message{To: []string{"alice@corp.example"}, Subject: "Scan", Body: "hi\n"})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Send took %v, want well under the 5s Retry-After (cancellation must win, not be retried)", elapsed)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Errorf("requests = %d, want 1 (must not retry after cancellation)", got)
	}
}
