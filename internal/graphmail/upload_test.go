package graphmail_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/georg-jung/scan2graph/internal/graphmail"
)

// fakeAccessToken is the only credential-shaped literal in these tests: an
// obviously synthetic stand-in for the Graph bearer token c.HTTP carries.
// Its whole job is to be recognisable in a request -- and, on the chunk
// PUTs, recognisably absent.
const fakeAccessToken = "fake-graph-token-for-tests-only"

// chunkBytes must match graphmail's unexported uploadChunkBytes: a round
// size comfortably under Graph's 4 MB request ceiling, which stays
// under its 4 MB request ceiling.
const chunkBytes = 3840 * 1024

// graphRequestMaxBytes is Graph's ceiling on one request body.
const graphRequestMaxBytes = 4 * 1024 * 1024

// floorBytes must match graphmail's unexported graphAttachmentFloorBytes:
// Graph's 3 MB minimum for an upload session, and the size at which an
// attachment stops being a single POST.
const floorBytes = 3 * 1024 * 1024

// draftID stands in for the message id Graph returns for a new draft:
// URL-safe base64 with padding, like the real thing.
const draftID = "AAMkAGI2fake-draft-id="

// uploadPath is where this fake's upload sessions point. A path of its own,
// because the real uploadUrl is on a host Graph picks rather than on the
// Graph endpoint itself.
const uploadPath = "/uploadsession/fake"

// gotRequest is one call the fake saw, kept whole so a test can assert on
// the sequence rather than on counters.
type gotRequest struct {
	method, path, auth, contentRange string
	body                             []byte
}

// fakeGraph answers the four calls the large-scan path makes and
// reassembles the chunks it is handed, placing each one at the offset its
// Content-Range names so a test compares bytes, not arrival order.
type fakeGraph struct {
	srv *httptest.Server
	t   *testing.T

	// Failure injection, set before the first request: failChunk is the
	// 1-based PUT to reject outright, flakyChunk the one to answer 503 once
	// so msapi retries it. Zero means neither.
	failChunk, flakyChunk int

	mu       sync.Mutex
	reqs     []gotRequest
	puts     int
	assembly []byte
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	g := &fakeGraph{t: t}
	g.srv = httptest.NewServer(http.HandlerFunc(g.handle))
	t.Cleanup(g.srv.Close)
	return g
}

// client is a Graph client pointed at the fake, whose HTTP client stamps
// the bearer token on every request the way cmd/scan2graph's oauth2 client
// does.
func (g *fakeGraph) client(largeScans bool) *graphmail.Client {
	return &graphmail.Client{
		HTTP:       &http.Client{Transport: bearer{g.srv.Client().Transport}},
		BaseURL:    g.srv.URL,
		Sender:     testSender,
		LargeScans: largeScans,
	}
}

func (g *fakeGraph) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reqs = append(g.reqs, gotRequest{
		method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"),
		contentRange: r.Header.Get("Content-Range"), body: body,
	})

	switch {
	case r.Method == http.MethodPut && r.URL.Path == uploadPath:
		g.putChunk(w, body, r.Header.Get("Content-Range"))
	case strings.HasSuffix(r.URL.Path, "/attachments/createUploadSession"):
		var s struct {
			AttachmentItem struct {
				Size int64 `json:"size"`
			} `json:"AttachmentItem"`
		}
		json.Unmarshal(body, &s)
		if s.AttachmentItem.Size < floorBytes {
			// Graph's own refusal, by name: under the floor an attachment is
			// a single POST, and a session for one is invalid.
			http.Error(w, `{"error":{"code":"ErrorAttachmentSizeShouldNotBeLessThanMinimumSize","message":"attachment size is less than the minimum size for an upload session"}}`, http.StatusBadRequest)
			return
		}
		// The session's uploadUrl is a full URL Graph chooses; this fake
		// serves it from the same host so the test needs one server.
		writeJSON(w, map[string]string{"uploadUrl": "http://" + r.Host + uploadPath})
	case strings.HasSuffix(r.URL.Path, "/attachments"):
		if a := g.directAttachment(body); len(a.Content) >= floorBytes {
			http.Error(w, `{"error":{"message":"at or over 3 MB an attachment needs an upload session"}}`, http.StatusRequestEntityTooLarge)
			return
		}
		writeJSON(w, map[string]string{"id": "fake-attachment-id"})
	case strings.HasSuffix(r.URL.Path, "/messages"):
		writeJSON(w, map[string]string{"id": draftID})
	case strings.HasSuffix(r.URL.Path, "/send"), strings.HasSuffix(r.URL.Path, "/sendMail"):
		w.WriteHeader(http.StatusAccepted)
	default:
		g.t.Errorf("fake Graph got an unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// putChunk copies one chunk into the reassembly buffer at the offset its
// Content-Range names, answering 200 for every chunk but the last, which
// gets Graph's 201.
func (g *fakeGraph) putChunk(w http.ResponseWriter, body []byte, contentRange string) {
	g.puts++
	// Graph refuses a request body at or over 4 MB, so this must too.
	if len(body) >= graphRequestMaxBytes {
		http.Error(w, `{"error":{"message":"the request is over Graph's size ceiling"}}`, http.StatusRequestEntityTooLarge)
		return
	}
	if g.puts == g.flakyChunk {
		g.flakyChunk = 0 // once only: the retry must succeed
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if g.puts == g.failChunk {
		http.Error(w, `{"error":{"message":"the upload session went away"}}`, http.StatusBadRequest)
		return
	}
	var first, last, total int64
	if _, err := fmt.Sscanf(contentRange, "bytes %d-%d/%d", &first, &last, &total); err != nil {
		g.t.Errorf("chunk %d: Content-Range %q does not parse: %v", g.puts, contentRange, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for int64(len(g.assembly)) < total {
		g.assembly = append(g.assembly, 0)
	}
	copy(g.assembly[first:], body)
	if last+1 == total {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// directAttachment is the body of the POST that carries an attachment under
// Graph's floor, checked as the fake decodes it: a request that is not a
// fileAttachment is a bug in the client, not something to report back.
type directAttachment struct {
	Type    string `json:"@odata.type"`
	Name    string `json:"name"`
	Content []byte `json:"contentBytes"` // decoded from base64 as it is read
}

func (g *fakeGraph) directAttachment(body []byte) directAttachment {
	var a directAttachment
	if err := json.Unmarshal(body, &a); err != nil {
		g.t.Errorf("direct attachment body does not decode: %v", err)
	}
	if a.Type != "#microsoft.graph.fileAttachment" {
		g.t.Errorf("direct attachment @odata.type = %q, want #microsoft.graph.fileAttachment", a.Type)
	}
	return a
}

// attached is what arrived by direct POST, by attachment name.
func (g *fakeGraph) attached() map[string][]byte {
	out := map[string][]byte{}
	for _, r := range g.seen() {
		if r.method == http.MethodPost && strings.HasSuffix(r.path, "/attachments") {
			a := g.directAttachment(r.body)
			out[a.Name] = a.Content
		}
	}
	return out
}

// uploaded is the reassembled scan, read under the fake's lock.
func (g *fakeGraph) uploaded() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.assembly
}

func (g *fakeGraph) seen() []gotRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]gotRequest(nil), g.reqs...)
}

// calls renders what the fake saw as "METHOD /path", for comparing the
// whole four-call sequence in one assertion.
func (g *fakeGraph) calls() []string {
	var out []string
	for _, r := range g.seen() {
		out = append(out, r.method+" "+r.path)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(v)
}

// bearer stamps the appliance's Graph token on every request that goes
// through the client it wraps.
type bearer struct{ rt http.RoundTripper }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+fakeAccessToken)
	return b.rt.RoundTrip(r)
}

// scanBytes builds n bytes whose value depends on their position, so a
// chunk written to the wrong offset, or written twice, cannot compare
// equal.
func scanBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

// overCeilingScan is a scan large enough to need the upload path and, at
// just over one chunk, more than one PUT.
func overCeilingScan(t *testing.T) (path string, content []byte) {
	t.Helper()
	content = scanBytes(chunkBytes + 1234)
	return writeTemp(t, "scan.pdf", content), content
}

func largeMessage(path string) graphmail.Message {
	return graphmail.Message{
		To: []string{"alice@corp.example"}, Subject: "Scan", Body: "Your scan is attached.\n",
		Attachments: []graphmail.Attachment{{Name: "scan.pdf", Path: path}},
	}
}

func TestSend_LargeScanIsUploadedInChunks(t *testing.T) {
	path, content := overCeilingScan(t)
	g := newFakeGraph(t)

	if err := g.client(true).Send(context.Background(), largeMessage(path)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	base := "/users/" + testSender + "/messages"
	wantCalls := []string{
		"POST " + base,
		"POST " + base + "/" + draftID + "/attachments/createUploadSession",
		"PUT " + uploadPath,
		"PUT " + uploadPath,
		"POST " + base + "/" + draftID + "/send",
	}
	if got := g.calls(); !slices.Equal(got, wantCalls) {
		t.Fatalf("calls =\n %q\nwant\n %q", got, wantCalls)
	}

	if got := g.uploaded(); !bytes.Equal(got, content) {
		t.Errorf("reassembled upload is %d bytes and differs from the %d byte source file", len(got), len(content))
	}

	total := len(content)
	wantRanges := []string{
		fmt.Sprintf("bytes 0-%d/%d", chunkBytes-1, total),
		fmt.Sprintf("bytes %d-%d/%d", chunkBytes, total-1, total),
	}
	var gotRanges []string
	for _, r := range g.seen() {
		if r.method != http.MethodPut {
			continue
		}
		gotRanges = append(gotRanges, r.contentRange)
		// No PUT may reach Graph's 4 MB request ceiling.
		if n := len(r.body); n >= graphRequestMaxBytes {
			t.Errorf("chunk of %d bytes is at or over Graph's %d byte ceiling", n, graphRequestMaxBytes)
		}
	}
	if !slices.Equal(gotRanges, wantRanges) {
		t.Errorf("Content-Range headers =\n %q\nwant\n %q", gotRanges, wantRanges)
	}

	var draft struct {
		Subject string `json:"subject"`
		Body    struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ToRecipients []struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"toRecipients"`
	}
	if err := json.Unmarshal(g.seen()[0].body, &draft); err != nil {
		t.Fatalf("draft request body is not JSON: %v", err)
	}
	if draft.Subject != "Scan" || draft.Body.Content != "Your scan is attached.\n" || draft.Body.ContentType != "Text" {
		t.Errorf("draft = %+v, want the message's subject and plain-text body", draft)
	}
	if len(draft.ToRecipients) != 1 || draft.ToRecipients[0].EmailAddress.Address != "alice@corp.example" {
		t.Errorf("draft recipients = %+v, want alice@corp.example", draft.ToRecipients)
	}
}

// The security property of this package: the uploadUrl points at a host
// Graph picks, so the chunk PUT must not carry the appliance's Graph token,
// which reads and writes every mailbox in the tenant.
func TestSend_LargeScanUploadPUTCarriesNoAuthorizationHeader(t *testing.T) {
	path, _ := overCeilingScan(t)
	g := newFakeGraph(t)

	if err := g.client(true).Send(context.Background(), largeMessage(path)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	puts := 0
	for _, r := range g.seen() {
		if r.method == http.MethodPut {
			puts++
			if r.auth != "" {
				t.Errorf("chunk PUT carried Authorization %q, want none: the uploadUrl is not our tenant's endpoint", r.auth)
			}
			continue
		}
		if want := "Bearer " + fakeAccessToken; r.auth != want {
			t.Errorf("%s %s carried Authorization %q, want %q", r.method, r.path, r.auth, want)
		}
	}
	if puts < 2 {
		t.Fatalf("saw %d chunk PUTs, want at least 2 (the assertion above must run on a real upload)", puts)
	}
}

// msapi.Client.Do rebuilds the request on every attempt, so a chunk that
// gets retried has to be re-read from the buffer. A reader consumed by the
// first attempt would upload an empty chunk on the second, and Graph would
// answer 200 to it.
func TestSend_LargeScanRetriedChunkUploadsTheSameBytes(t *testing.T) {
	path, content := overCeilingScan(t)
	g := newFakeGraph(t)
	g.flakyChunk = 1

	if err := g.client(true).Send(context.Background(), largeMessage(path)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := g.uploaded(); !bytes.Equal(got, content) {
		t.Errorf("after a retried chunk the reassembled upload differs from the source file (%d of %d bytes)", len(got), len(content))
	}
}

func TestSend_SmallScanStillUsesSendMail(t *testing.T) {
	small := writeTemp(t, "small.pdf", []byte("%PDF-1.4 a scan that fits\n%%EOF\n"))
	g := newFakeGraph(t)
	if err := g.client(true).Send(context.Background(), largeMessage(small)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	want := []string{"POST /users/" + testSender + "/sendMail"}
	if got := g.calls(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q (no draft for a scan that fits)", got, want)
	}
}

// A chunk that fails must fail the whole Send: better an error the caller
// turns into a notice than a draft that goes out missing its scan.
func TestSend_LargeScanUploadFailureIsNotSent(t *testing.T) {
	path, _ := overCeilingScan(t)
	g := newFakeGraph(t)
	g.failChunk = 2

	err := g.client(true).Send(context.Background(), largeMessage(path))
	if err == nil {
		t.Fatal("Send: want an error, the second chunk was rejected")
	}
	if !strings.Contains(err.Error(), "scan.pdf") {
		t.Errorf("err = %v, want it to name the attachment", err)
	}
	for _, r := range g.calls() {
		if strings.HasSuffix(r, "/send") {
			t.Errorf("the draft was sent anyway (%s), want no send after a failed upload", r)
		}
	}
}

// Graph's two ways to attach a file do not meet: sendMail stops carrying a
// scan at MaxAttachmentBytes (2.25 MB) and an upload session refuses one
// under 3 MB with ErrorAttachmentSizeShouldNotBeLessThanMinimumSize. The
// 768 KB in between can only go as a single attachments POST.
func TestSend_ScanInTheGapIsAttachedWithoutAnUploadSession(t *testing.T) {
	content := scanBytes(graphmail.MaxAttachmentBytes + 1024) // in the gap, and past sendMail
	if len(content) >= floorBytes {
		t.Fatalf("this test's scan is %d bytes, which is not under Graph's %d byte floor", len(content), floorBytes)
	}
	path := writeTemp(t, "scan.pdf", content)
	g := newFakeGraph(t)

	if err := g.client(true).Send(context.Background(), largeMessage(path)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	base := "/users/" + testSender + "/messages"
	want := []string{
		"POST " + base,
		"POST " + base + "/" + draftID + "/attachments",
		"POST " + base + "/" + draftID + "/send",
	}
	if got := g.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls =\n %q\nwant\n %q (no session under the floor)", got, want)
	}
	if got := g.attached()["scan.pdf"]; !bytes.Equal(got, content) {
		t.Errorf("attached scan.pdf is %d bytes and differs from the %d byte source file", len(got), len(content))
	}
}

// The case the appliance actually meets: mimescan lets through up to sixteen
// PDFs, and a handful of ordinary scans clears sendMail's ceiling between
// them while every one of them is far under Graph's session floor. Each has
// to go as its own attachments POST; a session for any of them is refused.
func TestSend_SeveralScansUnderTheFloorAreEachAttachedOnTheirOwn(t *testing.T) {
	const each = 700 * 1024 // four of these clear MaxAttachmentBytes together
	m := graphmail.Message{To: []string{"alice@corp.example"}, Subject: "Scan", Body: "Your scans are attached.\n"}
	want := map[string][]byte{}
	for i := range 4 {
		name := fmt.Sprintf("scan-%d.pdf", i)
		content := scanBytes(each + i) // a different length each, so a swap shows up
		want[name] = content
		m.Attachments = append(m.Attachments, graphmail.Attachment{Name: name, Path: writeTemp(t, name, content)})
	}
	g := newFakeGraph(t)

	if err := g.client(true).Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	base := "/users/" + testSender + "/messages"
	wantCalls := []string{"POST " + base}
	for range m.Attachments {
		wantCalls = append(wantCalls, "POST "+base+"/"+draftID+"/attachments")
	}
	wantCalls = append(wantCalls, "POST "+base+"/"+draftID+"/send")
	if got := g.calls(); !slices.Equal(got, wantCalls) {
		t.Fatalf("calls =\n %q\nwant\n %q", got, wantCalls)
	}
	for name, content := range want {
		if got := g.attached()[name]; !bytes.Equal(got, content) {
			t.Errorf("attached %s is %d bytes and differs from the %d byte source file", name, len(got), len(content))
		}
	}
}

// The stat Send routes on is an estimate: MaxAttachmentBytes cannot know
// what the headers cost, nor the CRLF the MIME builder adds every 76
// characters inside the inner base64. So there is a band of some 60 KB that
// passes the first check and then composes too big for sendMail after all.
// With the draft path available that band belongs to it - a notice there
// would refuse a scan the appliance was configured to send. Under the floor,
// the draft carries it as one attachments POST.
func TestSend_ScanUnderTheStatCeilingThatComposesTooBigIsStillAttached(t *testing.T) {
	// Under MaxAttachmentBytes by a hair, so the first check lets it past.
	content := scanBytes(graphmail.MaxAttachmentBytes - 1)
	path := writeTemp(t, "scan.pdf", content)
	g := newFakeGraph(t)
	if err := g.client(true).Send(context.Background(), largeMessage(path)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	base := "/users/" + testSender + "/messages"
	want := []string{
		"POST " + base,
		"POST " + base + "/" + draftID + "/attachments",
		"POST " + base + "/" + draftID + "/send",
	}
	if got := g.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls =\n %q\nwant\n %q: sendMail cannot carry this one and a session would refuse it", got, want)
	}
	if got := g.attached()["scan.pdf"]; !bytes.Equal(got, content) {
		t.Errorf("attached scan.pdf is %d bytes and differs from the %d byte source file", len(got), len(content))
	}

	// And with no upload path to fall back on it is still a notice.
	g2 := newFakeGraph(t)
	if err := g2.client(false).Send(context.Background(), largeMessage(path)); !errors.Is(err, graphmail.ErrTooLarge) {
		t.Errorf("Send without LargeScans: err = %v, want ErrTooLarge", err)
	}
}
