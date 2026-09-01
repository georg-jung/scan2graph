package smtpin_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/jobs"
	"github.com/georg-jung/scan2graph/internal/smtpin"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testConfig builds a valid *config.Config for tests: two sender profiles
// (printer@corp.example with email+web, webonly@corp.example with only
// web), one allowed recipient domain, SMTP AUTH required with fixed
// credentials. set overrides/adds env vars; unset removes them (needed for
// e.g. the anonymous-mode tests, where a plain "" value would itself be a
// config error).
// testSecret is the one fixture value these tests use wherever the
// configuration wants a credential. It is not a secret: it never leaves the
// fake getenv below.
const testSecret = "fixture-not-a-secret"

func testConfig(t *testing.T, set map[string]string, unset ...string) *config.Config {
	t.Helper()
	env := map[string]string{
		"S2G_ENTRA_TENANT_ID":           "tenant-id",
		"S2G_ENTRA_CLIENT_ID":           "client-id",
		"S2G_ENTRA_CLIENT_SECRET":       testSecret,
		"S2G_SMTP_USERNAME":             "scanner",
		"S2G_SMTP_PASSWORD":             testSecret,
		"S2G_GRAPH_SENDER":              "scans@corp.example",
		"S2G_ALLOWED_RECIPIENT_DOMAINS": "corp.example",
		"S2G_PUBLIC_BASE_URL":           "https://scan2graph.example",
		"S2G_PROFILES":                  `{"printer@corp.example":{"email":true,"web":true},"webonly@corp.example":{"web":true}}`,
		"S2G_MAX_JOBS":                  "8",
	}
	for _, k := range unset {
		delete(env, k)
	}
	for k, v := range set {
		env[k] = v
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func newStore(t *testing.T, cfg *config.Config) *jobs.Store {
	t.Helper()
	st, err := jobs.New(jobs.Options{
		Root:    t.TempDir(),
		TTL:     cfg.JobTTL,
		MaxJobs: cfg.Limits.MaxJobs,
		Logger:  testLogger(),
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// fakeHandler is a smtpin.Handler recording every enqueued job, or --  when
// err is set -- rejecting every Enqueue with that error instead.
type fakeHandler struct {
	mu  sync.Mutex
	got []jobs.Job
	err error
}

func (f *fakeHandler) Enqueue(j jobs.Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, j)
	return nil
}

func (f *fakeHandler) enqueued() []jobs.Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]jobs.Job(nil), f.got...)
}

// startServer starts a real smtpin server on a loopback port and returns its
// address. The server and its listener are torn down at test cleanup.
func startServer(t *testing.T, cfg *config.Config, store *jobs.Store, h smtpin.Handler) string {
	t.Helper()
	srv := smtpin.New(cfg, store, h, testLogger())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

// newHarness is the common case: a fresh config, store and server, wired to
// h. set/unset override testConfig's defaults.
func newHarness(t *testing.T, set map[string]string, unset []string, h smtpin.Handler) (addr string, store *jobs.Store, cfg *config.Config) {
	t.Helper()
	cfg = testConfig(t, set, unset...)
	store = newStore(t, cfg)
	addr = startServer(t, cfg, store, h)
	return addr, store, cfg
}

// smtpClient drives a real SMTP session over a real TCP connection, using
// net/textproto the way a real client would -- so what's under test is the
// wire behaviour, not the Session implementation directly.
type smtpClient struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

func dialSMTP(t *testing.T, addr string) *smtpClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	c := &smtpClient{t: t, conn: conn, tp: textproto.NewConn(conn)}
	t.Cleanup(func() { c.tp.Close() })
	c.expectCode(220) // greeting
	return c
}

func (c *smtpClient) expectCode(want int) string {
	c.t.Helper()
	code, msg := c.readCode()
	if code != want {
		c.t.Fatalf("got %d %q, want %d", code, msg, want)
	}
	return msg
}

func (c *smtpClient) readCode() (int, string) {
	c.t.Helper()
	code, msg, err := c.tp.ReadResponse(-1)
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	return code, msg
}

func (c *smtpClient) send(format string, args ...any) {
	c.t.Helper()
	if err := c.tp.PrintfLine(format, args...); err != nil {
		c.t.Fatalf("send %q: %v", format, err)
	}
}

// readCodeAfter runs send (typically a single c.send call) and returns the
// reply code and message, for commands whose expected code is not a fixed
// success code.
func (c *smtpClient) readCodeAfter(send func()) (int, string) {
	c.t.Helper()
	send()
	return c.readCode()
}

func (c *smtpClient) cmd(want int, format string, args ...any) string {
	c.t.Helper()
	c.send(format, args...)
	return c.expectCode(want)
}

func (c *smtpClient) ehlo() string {
	c.t.Helper()
	c.send("EHLO test.local")
	return c.expectCode(250)
}

func (c *smtpClient) authPlain(user, pass string) (int, string) {
	c.t.Helper()
	ir := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	c.send("AUTH PLAIN %s", ir)
	return c.readCode()
}

func (c *smtpClient) authLogin(user, pass string) (int, string) {
	c.t.Helper()
	c.send("AUTH LOGIN")
	if code, msg := c.readCode(); code != 334 {
		c.t.Fatalf("AUTH LOGIN username prompt: got %d %q, want 334", code, msg)
	}
	c.send("%s", base64.StdEncoding.EncodeToString([]byte(user)))
	if code, msg := c.readCode(); code != 334 {
		c.t.Fatalf("AUTH LOGIN password prompt: got %d %q, want 334", code, msg)
	}
	c.send("%s", base64.StdEncoding.EncodeToString([]byte(pass)))
	return c.readCode()
}

// mustAuth dials, EHLOs and authenticates with the given credentials via
// AUTH PLAIN, failing the test unless the server accepts them (235).
func mustAuth(t *testing.T, addr, user, pass string) *smtpClient {
	t.Helper()
	c := dialSMTP(t, addr)
	c.ehlo()
	if code, msg := c.authPlain(user, pass); code != 235 {
		t.Fatalf("AUTH PLAIN: got %d %q, want 235", code, msg)
	}
	return c
}

// data sends the DATA command, streams msg as the message body (dot-stuffed
// and CRLF-terminated by textproto.Writer.DotWriter) and returns the final
// reply.
func (c *smtpClient) data(msg string) (int, string) {
	c.t.Helper()
	c.send("DATA")
	if code, m := c.readCode(); code != 354 {
		c.t.Fatalf("DATA: got %d %q, want 354", code, m)
	}
	dw := c.tp.DotWriter()
	if _, err := io.WriteString(dw, msg); err != nil {
		c.t.Fatalf("write data: %v", err)
	}
	if err := dw.Close(); err != nil {
		c.t.Fatalf("close data: %v", err)
	}
	return c.readCode()
}

// bdat sends msg as a single BDAT chunk *without* LAST: go-smtp then runs
// Session.Data on its own goroutine while its command loop stays free for
// the next command, and the client has not been told 250 for the message.
func (c *smtpClient) bdat(msg string) (int, string) {
	c.t.Helper()
	c.send("BDAT %d", len(msg))
	if _, err := io.WriteString(c.tp.W, msg); err != nil {
		c.t.Fatalf("write chunk: %v", err)
	}
	if err := c.tp.W.Flush(); err != nil {
		c.t.Fatalf("flush chunk: %v", err)
	}
	return c.readCode()
}

// waitStoreEmpty waits until the store holds neither a job nor a
// reservation, for assertions that race with a session goroutine unwinding.
func waitStoreEmpty(t *testing.T, store *jobs.Store) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for store.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("store.Len() still %d after 2s, want 0", store.Len())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// pdfBody is minimal but genuine PDF content by mimescan's rules: it starts
// with the %PDF- magic and carries %%EOF near its end.
func pdfBody(fill string) string {
	return "%PDF-1.4\n" + fill + "\n%%EOF\n"
}

// scanMessage builds a minimal RFC 5322 multipart/mixed message with one
// PDF attachment per (filename, content) pair in pdfs.
func scanMessage(subject string, pdfs [][2]string) string {
	const boundary = "scan2graph-test-boundary"
	var b strings.Builder
	b.WriteString("From: scanner@lan.local\r\n")
	b.WriteString("To: someone@lan.local\r\n")
	if subject != "" {
		fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)
	for _, pdf := range pdfs {
		name, content := pdf[0], pdf[1]
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: application/pdf; name=\"%s\"\r\n", name)
		fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n", name)
		b.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		b.WriteString(content)
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

func singlePDFMessage(subject string) string {
	return scanMessage(subject, [][2]string{{"scan.pdf", pdfBody("hello world")}})
}

// textMessage is a plain message with no attachment at all.
func textMessage(subject string) string {
	return fmt.Sprintf("From: scanner@lan.local\r\nSubject: %s\r\nContent-Type: text/plain\r\n\r\nno attachment here\r\n", subject)
}

// jpegMessage is the printer that was left on JPEG: something is attached,
// but nothing that can be delivered as a scan.
func jpegMessage(subject string) string {
	const boundary = "scan2graph-test-jpeg"
	return fmt.Sprintf("From: scanner@lan.local\r\nSubject: %s\r\n"+
		"Content-Type: multipart/mixed; boundary=%q\r\n\r\n"+
		"--%s\r\nContent-Type: image/jpeg\r\n"+
		"Content-Disposition: attachment; filename=\"scan.jpg\"\r\n\r\n"+
		"\xff\xd8\xff\xe0 not a pdf\r\n--%s--\r\n",
		subject, boundary, boundary, boundary)
}

// manyPartsMessage builds a multipart message with n empty parts -- enough
// to trip mimescan's part-count limit before any content is even looked at.
func manyPartsMessage(n int) string {
	const boundary = "scan2graph-test-many-parts"
	var b strings.Builder
	b.WriteString("From: scanner@lan.local\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: text/plain\r\n\r\npart %d\r\n", i)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}
