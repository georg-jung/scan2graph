package web

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/jobs"
)

const (
	ann     = "ann@corp.example"
	bob     = "bob@corp.example"
	jobTTL  = 90 * time.Minute
	missing = "AAAAAAAAAAAAAAAAAAAAAA" // a job id nobody ever had
)

var webCaps = jobs.Capabilities{Web: true}

// testClock is a clock the tests move by hand; it is read from request
// goroutines, hence the atomic.
type testClock struct{ ns atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.ns.Store(time.Now().UnixNano())
	return c
}

func (c *testClock) now() time.Time      { return time.Unix(0, c.ns.Load()) }
func (c *testClock) add(d time.Duration) { c.ns.Add(int64(d)) }

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// harness is the whole appliance's web side: a real job store, a real server
// over TLS (so the Secure session cookie behaves as it does behind the
// proxy), and a real OpenID Connect provider.
type harness struct {
	t      *testing.T
	idp    *fakeIDP
	store  *jobs.Store
	ts     *httptest.Server
	clock  *testClock
	prefix string // the subpath this appliance is published under, if any
}

// newHarness builds the whole web side, on a host of the appliance's own.
// uiTitle, when given, is the operator's brand for this appliance.
func newHarness(t *testing.T, uiTitle ...string) *harness {
	t.Helper()
	return newHarnessAt(t, "", uiTitle...)
}

// newHarnessAt is newHarness with the appliance published under a subpath
// prefix, the way a NAS or an existing site reaches it: the public base URL
// carries the path, and the appliance both routes and emits it.
func newHarnessAt(t *testing.T, prefix string, uiTitle ...string) *harness {
	t.Helper()
	idp := newFakeIDP(t)
	clock := newTestClock()
	store, err := jobs.New(jobs.Options{Root: t.TempDir(), TTL: jobTTL, MaxJobs: 16, Now: clock.now, Logger: quiet()})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ts := httptest.NewUnstartedServer(nil)
	cfg := &config.Config{
		PublicBaseURL: "https://" + ts.Listener.Addr().String() + prefix,
		PathPrefix:    prefix,
		ClientID:      testClientID,
		ClientSecret:  testClientSecret,
		AuthorityURL:  idp.URL,
		UITitle:       "scan2graph",
	}
	if len(uiTitle) == 1 {
		cfg.UITitle = uiTitle[0]
	}
	s, err := New(context.Background(), Options{Store: store, Config: cfg, Logger: quiet(), Now: clock.now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts.Config.Handler = s.Handler()
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return &harness{t: t, idp: idp, store: store, ts: ts, clock: clock, prefix: prefix}
}

// url is where path lives on this appliance: under its prefix, when it has
// one. Every test that asks for a page goes through it, so the prefixed run
// of TestPathsFollowThePrefix exercises the same code as all the others.
func (h *harness) url(path string) string { return h.ts.URL + h.prefix + path }

// client is one browser: its own cookie jar, and no automatic redirects so
// every hop is visible to the test.
func (h *harness) client() *http.Client {
	h.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Transport:     h.ts.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (h *harness) get(c *http.Client, rawURL string) (*http.Response, string) {
	h.t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		h.t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body of %s: %v", rawURL, err)
	}
	return resp, string(body)
}

// location resolves a redirect's Location against the URL it came from.
func (h *harness) location(resp *http.Response) string {
	h.t.Helper()
	loc, err := resp.Location()
	if err != nil {
		h.t.Fatalf("no Location header on %d response: %v", resp.StatusCode, err)
	}
	return loc.String()
}

// startSignIn does /auth/login and the provider's /authorize hop, returning
// the callback URL the provider redirected the browser to.
func (h *harness) startSignIn(c *http.Client) string {
	h.t.Helper()
	resp, _ := h.get(c, h.url("/auth/login"))
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("/auth/login: status %d, want 302", resp.StatusCode)
	}
	authorize := h.location(resp)
	if !strings.HasPrefix(authorize, h.idp.URL) {
		h.t.Fatalf("/auth/login redirected to %s, want the identity provider", authorize)
	}
	resp, _ = h.get(c, authorize)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("provider /authorize: status %d, want 302", resp.StatusCode)
	}
	return h.location(resp)
}

// signIn completes the round trip and returns the callback's own response.
func (h *harness) signIn(c *http.Client) *http.Response {
	h.t.Helper()
	resp, _ := h.get(c, h.startSignIn(c))
	return resp
}

// signedIn returns a client that has completed a sign-in.
func (h *harness) signedIn() *http.Client {
	h.t.Helper()
	c := h.client()
	if resp := h.signIn(c); resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("sign-in: status %d, want 303", resp.StatusCode)
	}
	return c
}

// addJob puts one scan into the store, with one document per content given.
func (h *harness) addJob(subject string, recipients []string, caps jobs.Capabilities, contents ...string) jobs.Job {
	h.t.Helper()
	st, err := h.store.Reserve()
	if err != nil {
		h.t.Fatalf("Reserve: %v", err)
	}
	docs := make([]jobs.NewDocument, 0, len(contents))
	for i, content := range contents {
		name := fmt.Sprintf("doc%d", i)
		f, err := st.CreateFile(name)
		if err != nil {
			h.t.Fatalf("CreateFile: %v", err)
		}
		if _, err := f.WriteString(content); err != nil {
			h.t.Fatalf("write document: %v", err)
		}
		if err := f.Close(); err != nil {
			h.t.Fatalf("close document: %v", err)
		}
		docs = append(docs, jobs.NewDocument{DisplayName: "invoice.pdf", Path: f.Name()})
	}
	j, err := st.Commit(jobs.NewJob{
		Profile:    "printer@corp.example",
		Caps:       caps,
		Subject:    subject,
		Recipients: recipients,
		Documents:  docs,
	})
	if err != nil {
		h.t.Fatalf("Commit: %v", err)
	}
	// Ready, like a job the pipeline has finished with: that is the state the
	// UI normally sees, and the one in which downloads are allowed.
	if err := h.store.SetStatus(j.ID, jobs.StatusReady, ""); err != nil {
		h.t.Fatalf("SetStatus: %v", err)
	}
	j.Status = jobs.StatusReady
	return j
}

func TestSignInRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.addJob("Rechnung Müller", []string{ann}, webCaps, "%PDF-1.7 one")

	c := h.client()
	resp := h.signIn(c)
	if resp.StatusCode != http.StatusSeeOther || h.location(resp) != h.ts.URL+"/" {
		t.Fatalf("callback: status %d location %q, want 303 to /", resp.StatusCode, resp.Header.Get("Location"))
	}

	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			cookie = ck
		}
	}
	if cookie == nil {
		t.Fatal("callback set no session cookie")
	}
	switch {
	case !cookie.HttpOnly:
		t.Error("session cookie is not HttpOnly")
	case !cookie.Secure:
		t.Error("session cookie is not Secure")
	case cookie.SameSite != http.SameSiteLaxMode:
		t.Errorf("session cookie SameSite = %v, want Lax", cookie.SameSite)
	case cookie.Path != "/":
		t.Errorf("session cookie Path = %q, want /", cookie.Path)
	case cookie.MaxAge != int(sessionTTL.Seconds()):
		t.Errorf("session cookie MaxAge = %d, want %d", cookie.MaxAge, int(sessionTTL.Seconds()))
	}

	resp, body := h.get(c, h.ts.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list page: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Rechnung Müller") {
		t.Errorf("list page does not show the user's scan:\n%s", body)
	}
	for header, want := range map[string]string{
		"Content-Type":           "text/html; charset=utf-8",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("list page %s = %q, want %q", header, got, want)
		}
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Errorf("list page CSP = %q, want %q", got, contentSecurityPolicy)
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	callback, err := url.Parse(h.startSignIn(c))
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	q := callback.Query()
	q.Set("state", "not-the-state-we-issued")
	callback.RawQuery = q.Encode()

	resp, _ := h.get(c, callback.String())
	assertSignInRejected(t, h, c, resp)
}

// TestCallbackRejectsEmptySignInCookie covers a forged cookie whose parts are
// all empty. Both the state and the nonce check compare against what the
// cookie holds, so empty values would be satisfied by a callback that carries
// no state and an ID token that carries no nonce - passing by absence rather
// than by matching.
func TestCallbackRejectsEmptySignInCookie(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	// Start a real sign-in so a code exists, then replace the cookie.
	callback, err := url.Parse(h.startSignIn(c))
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	u, err := url.Parse(h.ts.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	c.Jar.SetCookies(u, []*http.Cookie{{Name: authCookie, Value: "||", Path: authPath}})

	q := callback.Query()
	q.Del("state")
	callback.RawQuery = q.Encode()

	resp, _ := h.get(c, callback.String())
	assertSignInRejected(t, h, c, resp)

	// The cookie is what the state and nonce are checked against, so a
	// forged one must be refused before its code is worth anything: no
	// exchange with the provider at all.
	if n := h.idp.Exchanges.Load(); n != 0 {
		t.Errorf("token endpoint called %d times for a forged sign-in cookie, want 0", n)
	}
}

func TestCallbackRejectsTamperedIDToken(t *testing.T) {
	h := newHarness(t)
	// Flip one bit of the signature; header and claims stay untouched and
	// perfectly valid, so only the signature check can catch this.
	h.idp.Token = func(tok string) string {
		i := strings.LastIndex(tok, ".")
		sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		sig[0] ^= 0x01
		return tok[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
	}
	c := h.client()
	assertSignInRejected(t, h, c, h.signIn(c))
}

func TestCallbackRejectsNonceMismatch(t *testing.T) {
	h := newHarness(t)
	h.idp.Claims = func(claims map[string]any) { claims["nonce"] = "a-nonce-this-browser-never-sent" }
	c := h.client()
	assertSignInRejected(t, h, c, h.signIn(c))
}

// assertSignInRejected checks that a failed callback both refuses the request
// and leaves the browser with no session at all.
func assertSignInRejected(t *testing.T, h *harness, c *http.Client, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback: status %d, want 400", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			t.Fatal("a rejected sign-in still set a session cookie")
		}
	}
	resp, _ = h.get(c, h.ts.URL+"/")
	if resp.StatusCode != http.StatusSeeOther || h.location(resp) != h.ts.URL+"/auth/login" {
		t.Fatalf("after a rejected sign-in: status %d, want a redirect to /auth/login", resp.StatusCode)
	}
}

func TestSignOutDropsSessionServerSide(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	resp := h.signIn(c)
	var stolen string
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			stolen = ck.Value
		}
	}

	out, err := c.Post(h.ts.URL+"/auth/logout", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST /auth/logout: %v", err)
	}
	defer out.Body.Close()
	if out.StatusCode != http.StatusOK {
		t.Fatalf("logout: status %d, want 200", out.StatusCode)
	}
	cleared := false
	for _, ck := range out.Cookies() {
		if ck.Name == sessionCookie && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}

	// A browser that kept the old cookie value must not get back in.
	fresh := h.client()
	req, err := http.NewRequest(http.MethodGet, h.ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: stolen})
	replay, err := fresh.Do(req)
	if err != nil {
		t.Fatalf("replay request: %v", err)
	}
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusSeeOther {
		t.Fatalf("replayed session cookie: status %d, want a redirect to sign in", replay.StatusCode)
	}
}

func TestSessionExpires(t *testing.T) {
	h := newHarness(t)
	c := h.signedIn()
	h.clock.add(sessionTTL + time.Minute)

	resp, _ := h.get(c, h.ts.URL+"/")
	if resp.StatusCode != http.StatusSeeOther || h.location(resp) != h.ts.URL+"/auth/login" {
		t.Fatalf("expired session: status %d, want a redirect to /auth/login", resp.StatusCode)
	}
}

func TestNoSessionRedirectsToSignIn(t *testing.T) {
	h := newHarness(t)
	j := h.addJob("Invoice", []string{ann}, webCaps, "%PDF-1.7")
	c := h.client()
	for _, path := range []string{"/", "/scan/" + j.ID, "/scan/" + j.ID + "/" + j.Documents[0].ID} {
		resp, _ := h.get(c, h.ts.URL+path)
		if resp.StatusCode != http.StatusSeeOther || h.location(resp) != h.ts.URL+"/auth/login" {
			t.Errorf("GET %s without a session: status %d location %q, want 303 to /auth/login",
				path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestListShowsOnlyOwnLiveWebJobs(t *testing.T) {
	h := newHarness(t)
	expired := h.addJob("Expired scan", []string{ann}, webCaps, "%PDF-1.7")
	h.clock.add(jobTTL + time.Minute)
	h.addJob("My invoice", []string{ann}, webCaps, "%PDF-1.7")
	h.addJob("Payslip for bob", []string{bob}, webCaps, "%PDF-1.7")
	mailOnly := h.addJob("Mail only", []string{ann}, jobs.Capabilities{Email: true}, "%PDF-1.7")

	c := h.signedIn()
	_, body := h.get(c, h.ts.URL+"/")
	if !strings.Contains(body, "My invoice") {
		t.Errorf("list page is missing the user's own scan:\n%s", body)
	}
	for _, hidden := range []string{"Expired scan", "Payslip for bob", "Mail only"} {
		if strings.Contains(body, hidden) {
			t.Errorf("list page shows %q, which this user must not see:\n%s", hidden, body)
		}
	}

	// Not on the list means not reachable by URL either, own scan or not.
	for name, j := range map[string]jobs.Job{"expired": expired, "mail-only": mailOnly} {
		for _, path := range []string{"/scan/" + j.ID, "/scan/" + j.ID + "/" + j.Documents[0].ID} {
			if resp, _ := h.get(c, h.ts.URL+path); resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s (%s scan): status %d, want 404", path, name, resp.StatusCode)
			}
		}
	}
}

func TestUserWithNoMatchingIdentitySeesEmptyList(t *testing.T) {
	h := newHarness(t)
	h.addJob("Payslip for bob", []string{bob}, webCaps, "%PDF-1.7")
	h.idp.User = idpUser{Subject: "stranger", Email: "stranger@corp.example", PreferredUsername: "stranger@corp.example", Name: "Stranger"}

	resp, body := h.get(h.signedIn(), h.ts.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list page: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Nothing here right now") {
		t.Errorf("a user with no scans should see the empty state:\n%s", body)
	}
	if strings.Contains(body, "Payslip for bob") {
		t.Error("list page leaked another user's scan")
	}
}

// TestOtherUsersJobIsIndistinguishableFromMissing is the check this whole
// package exists for: somebody else's scan must answer exactly like a scan
// that never existed, on the page and on the download.
func TestOtherUsersJobIsIndistinguishableFromMissing(t *testing.T) {
	h := newHarness(t)
	theirs := h.addJob("Payslip for bob", []string{bob}, webCaps, "%PDF-1.7 secret")
	c := h.signedIn()

	for _, tc := range []struct{ name, theirs, unknown string }{
		{
			"detail page",
			"/scan/" + theirs.ID,
			"/scan/" + missing,
		},
		{
			"download",
			"/scan/" + theirs.ID + "/" + theirs.Documents[0].ID,
			"/scan/" + missing + "/" + missing,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied, deniedBody := h.get(c, h.ts.URL+tc.theirs)
			unknown, unknownBody := h.get(c, h.ts.URL+tc.unknown)
			if denied.StatusCode != http.StatusNotFound {
				t.Fatalf("another user's scan: status %d, want 404", denied.StatusCode)
			}
			if denied.StatusCode != unknown.StatusCode || deniedBody != unknownBody {
				t.Fatalf("another user's scan answers %d %q, a missing one %d %q",
					denied.StatusCode, deniedBody, unknown.StatusCode, unknownBody)
			}
			for _, hdr := range []string{"Content-Type", "Content-Length", "Content-Disposition", "Cache-Control"} {
				if denied.Header.Get(hdr) != unknown.Header.Get(hdr) {
					t.Errorf("%s differs: %q vs %q", hdr, denied.Header.Get(hdr), unknown.Header.Get(hdr))
				}
			}
			if strings.Contains(deniedBody, "secret") || strings.Contains(deniedBody, "Payslip") {
				t.Error("the 404 leaked something about the scan")
			}
		})
	}

	// A document id from somebody else's scan is no key to one's own either.
	mine := h.addJob("My invoice", []string{ann}, webCaps, "%PDF-1.7 mine")
	resp, _ := h.get(c, h.ts.URL+"/scan/"+mine.ID+"/"+theirs.Documents[0].ID)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("foreign document id on own job: status %d, want 404", resp.StatusCode)
	}
}

func TestDownload(t *testing.T) {
	h := newHarness(t)
	const content = "%PDF-1.7 the actual bytes"
	j := h.addJob("My invoice", []string{ann}, webCaps, content)
	doc := j.Documents[0]

	resp, body := h.get(h.signedIn(), h.ts.URL+"/scan/"+j.ID+"/"+doc.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download: status %d, want 200", resp.StatusCode)
	}
	if body != content {
		t.Errorf("download body = %q, want %q", body, content)
	}
	for header, want := range map[string]string{
		"Content-Type":           "application/pdf",
		"Content-Length":         "25",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("download %s = %q, want %q", header, got, want)
		}
	}

	// Asserted by parsing rather than by string: the encoding is the
	// standard library's business, the disposition and the filename are ours.
	disposition, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("Content-Disposition %q: %v", resp.Header.Get("Content-Disposition"), err)
	}
	if disposition != "attachment" || params["filename"] != "invoice.pdf" {
		t.Errorf("Content-Disposition = %q %v, want attachment with filename invoice.pdf", disposition, params)
	}
}

// TestDownloadWaitsForProcessing guards the window in which OCR replaces a
// job's files underneath the web UI: neither the page nor a direct URL may
// hand out the pre-OCR original.
func TestDownloadWaitsForProcessing(t *testing.T) {
	h := newHarness(t)
	j := h.addJob("My invoice", []string{ann}, webCaps, "%PDF-1.7 the original")
	url := h.ts.URL + "/scan/" + j.ID + "/" + j.Documents[0].ID
	c := h.signedIn()

	for _, st := range []jobs.Status{jobs.StatusPending, jobs.StatusProcessing} {
		if err := h.store.SetStatus(j.ID, st, ""); err != nil {
			t.Fatalf("SetStatus: %v", err)
		}
		resp, body := h.get(c, url)
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("download of a %s scan: status %d, want 409", st, resp.StatusCode)
		}
		if strings.Contains(body, "the original") {
			t.Errorf("download of a %s scan served the pre-OCR file", st)
		}
		if _, page := h.get(c, h.ts.URL+"/scan/"+j.ID); strings.Contains(page, url[len(h.ts.URL):]) {
			t.Errorf("detail page of a %s scan still links the download:\n%s", st, page)
		}
	}

	// A failed job keeps its downloads: the notice email links to them.
	if err := h.store.SetStatus(j.ID, jobs.StatusFailed, "Text recognition failed."); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if resp, body := h.get(c, url); resp.StatusCode != http.StatusOK || body != "%PDF-1.7 the original" {
		t.Errorf("download of a failed scan: status %d, body %q", resp.StatusCode, body)
	}
}

// TestRefreshMetaWhileProcessing checks that the self-refresh meta tag
// appears on the detail page and the list page while a job is still being
// worked on, and disappears on both once it is ready.
func TestRefreshMetaWhileProcessing(t *testing.T) {
	h := newHarness(t)
	j := h.addJob("My invoice", []string{ann}, webCaps, "%PDF-1.7")
	if err := h.store.SetStatus(j.ID, jobs.StatusProcessing, ""); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	c := h.signedIn()
	const refresh = `<meta http-equiv="refresh" content="5">`

	if _, page := h.get(c, h.ts.URL+"/scan/"+j.ID); !strings.Contains(page, refresh) {
		t.Errorf("detail page of a processing scan does not refresh:\n%s", page)
	}
	if _, page := h.get(c, h.ts.URL+"/"); !strings.Contains(page, refresh) {
		t.Errorf("list page with a processing scan does not refresh:\n%s", page)
	}

	if err := h.store.SetStatus(j.ID, jobs.StatusReady, ""); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if _, page := h.get(c, h.ts.URL+"/scan/"+j.ID); strings.Contains(page, refresh) {
		t.Errorf("detail page of a finished scan still refreshes:\n%s", page)
	}
	resp, page := h.get(c, h.ts.URL+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list page: status %d, want 200", resp.StatusCode)
	}
	if strings.Contains(page, refresh) || !strings.Contains(page, "My invoice") {
		t.Errorf("list page with nothing processing did not render as expected:\n%s", page)
	}
}

// TestListShowsScanSize covers the column that replaced the document count:
// a single-document scan just says how big it is, and only a multi-document
// one has to say how many files there are.
func TestListShowsScanSize(t *testing.T) {
	h := newHarness(t)
	h.addJob("One document", []string{ann}, webCaps, strings.Repeat("x", 3072))
	h.addJob("Two documents", []string{ann}, webCaps, strings.Repeat("x", 1024), strings.Repeat("x", 1024))

	_, body := h.get(h.signedIn(), h.ts.URL+"/")
	for _, want := range []string{">3 kB<", ">2 files \u00b7 2 kB<"} {
		if !strings.Contains(body, want) {
			t.Errorf("list page has no cell %q:\n%s", want, body)
		}
	}
}

// TestDetailPageOffersOneDocumentDirectly is the 99% case: one document, one
// download control, no list to read.
func TestDetailPageOffersOneDocumentDirectly(t *testing.T) {
	h := newHarness(t)
	one := h.addJob("One document", []string{ann}, webCaps, "%PDF-1.7 a")
	two := h.addJob("Two documents", []string{ann}, webCaps, "%PDF-1.7 a", "%PDF-1.7 bb")
	c := h.signedIn()

	_, page := h.get(c, h.ts.URL+"/scan/"+one.ID)
	if strings.Contains(page, "<ul class=\"docs\">") {
		t.Errorf("a single-document scan still renders a document list:\n%s", page)
	}
	href := "/scan/" + one.ID + "/" + one.Documents[0].ID
	if !strings.Contains(page, `<a class="download" href="`+href+`" download>Download invoice.pdf`) {
		t.Errorf("the single document is not offered as a download control:\n%s", page)
	}

	_, page = h.get(c, h.ts.URL+"/scan/"+two.ID)
	if !strings.Contains(page, "<ul class=\"docs\">") {
		t.Errorf("a two-document scan does not list its documents:\n%s", page)
	}
	for _, d := range two.Documents {
		if !strings.Contains(page, "/scan/"+two.ID+"/"+d.ID) {
			t.Errorf("the list is missing document %s:\n%s", d.DisplayName, page)
		}
	}
}

// TestUITitleIsEscaped guards the first operator-supplied string that reaches
// a page: it must arrive as text in both places that render it, never as
// markup.
func TestUITitleIsEscaped(t *testing.T) {
	const title = `Acme <script>alert(1)</script> & Co`
	h := newHarness(t, title)

	_, body := h.get(h.signedIn(), h.ts.URL+"/")
	if strings.Contains(body, "<script>") {
		t.Fatalf("the UI title reached the page as markup:\n%s", body)
	}
	// Once in the <title>, once in the header's brand link.
	escaped := "Acme &lt;script&gt;alert(1)&lt;/script&gt; &amp; Co"
	if n := strings.Count(body, escaped); n != 2 {
		t.Errorf("the escaped UI title appears %d times, want 2 (title and brand):\n%s", n, body)
	}
}

// TestConcurrentRequests exercises the session map and the handlers together
// under -race.
func TestConcurrentRequests(t *testing.T) {
	h := newHarness(t)
	j := h.addJob("My invoice", []string{ann}, webCaps, "%PDF-1.7")
	c := h.signedIn()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				for _, path := range []string{"/", "/scan/" + j.ID, "/scan/" + j.ID + "/" + j.Documents[0].ID} {
					resp, err := c.Get(h.ts.URL + path)
					if err != nil {
						t.Errorf("GET %s: %v", path, err)
						return
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Errorf("GET %s: status %d", path, resp.StatusCode)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func TestIdentities(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	for _, tc := range []struct {
		name       string
		email, upn string
		want       []string
	}{
		{"both claims, same address", ann, ann, []string{ann}},
		{"upper case is canonicalized", "Ann@Corp.Example", "", []string{ann}},
		{"two different addresses both count", ann, bob, []string{ann, bob}},
		{"nothing usable", "", "not-an-address", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.identities(tc.email, tc.upn); !slices.Equal(got, tc.want) {
				t.Fatalf("identities = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPathsFollowThePrefix drives one whole journey twice: on a host of the
// appliance's own, and under a subpath prefix on a host it shares with other
// applications. Every path the appliance emits is asserted as the prefix plus
// the path it has always had, so the first run is the proof that a deployment
// without a prefix is exactly what it was before - and the second that
// nothing is left pointing at the root, where the proxy forwards nothing.
func TestPathsFollowThePrefix(t *testing.T) {
	for _, prefix := range []string{"", "/scanner"} {
		t.Run("prefix "+prefix, func(t *testing.T) {
			h := newHarnessAt(t, prefix)
			j := h.addJob("Rechnung Müller", []string{ann}, webCaps, "%PDF-1.7 one")
			doc := j.Documents[0]
			c := h.client()

			// Signed out: the guard sends the browser to sign in where the
			// sign-in actually is.
			if resp, _ := h.get(c, h.url("/")); resp.StatusCode != http.StatusSeeOther ||
				h.location(resp) != h.url("/auth/login") {
				t.Fatalf("no session: status %d location %q, want 303 to %s",
					resp.StatusCode, resp.Header.Get("Location"), prefix+"/auth/login")
			}

			// Signing in: the short-lived cookie is scoped to the callback's
			// own path, and the identity provider is given a redirect URI
			// that comes back to this appliance rather than to the host root.
			resp, _ := h.get(c, h.url("/auth/login"))
			if got := cookie(t, resp, authCookie).Path; got != prefix+authPath {
				t.Errorf("sign-in cookie Path = %q, want %q", got, prefix+authPath)
			}
			authorize, err := url.Parse(h.location(resp))
			if err != nil {
				t.Fatalf("parse the authorize URL: %v", err)
			}
			if got, want := authorize.Query().Get("redirect_uri"), h.url("/auth/callback"); got != want {
				t.Errorf("redirect_uri = %q, want %q", got, want)
			}
			resp, _ = h.get(c, authorize.String())
			resp, _ = h.get(c, h.location(resp))
			if resp.StatusCode != http.StatusSeeOther || h.location(resp) != h.url("/") {
				t.Fatalf("callback: status %d location %q, want 303 to %s",
					resp.StatusCode, resp.Header.Get("Location"), prefix+"/")
			}
			// The whole point on a shared host: the session cookie goes to
			// this appliance and to nothing else living on that hostname.
			if got, want := cookie(t, resp, sessionCookie).Path, cmp.Or(prefix, "/"); got != want {
				t.Errorf("session cookie Path = %q, want %q", got, want)
			}

			// The list page, and every link it draws.
			resp, body := h.get(c, h.url("/"))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("list page: status %d, want 200", resp.StatusCode)
			}
			for _, want := range []string{
				`href="` + prefix + `/static/style.css"`,
				`href="` + prefix + `/"`, // the brand, home
				`action="` + prefix + `/auth/logout"`,
				`href="` + prefix + `/scan/` + j.ID + `"`,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("list page does not contain %s:\n%s", want, body)
				}
			}
			if resp, _ := h.get(c, h.url("/static/style.css")); resp.StatusCode != http.StatusOK {
				t.Errorf("stylesheet: status %d, want 200", resp.StatusCode)
			}

			// The detail page, its back link and its download.
			resp, body = h.get(c, h.url("/scan/"+j.ID))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("detail page: status %d, want 200", resp.StatusCode)
			}
			if want := `href="` + prefix + `/scan/` + j.ID + `/` + doc.ID + `"`; !strings.Contains(body, want) {
				t.Errorf("detail page does not link the document as %s:\n%s", want, body)
			}
			if resp, body := h.get(c, h.url("/scan/"+j.ID+"/"+doc.ID)); resp.StatusCode != http.StatusOK ||
				body != "%PDF-1.7 one" {
				t.Errorf("download: status %d body %q, want the document", resp.StatusCode, body)
			}

			// Signing out has to clear the cookie on the path it was set
			// with, or the browser keeps it and only the server-side drop
			// signs the user out.
			out, err := c.Post(h.url("/auth/logout"), "application/x-www-form-urlencoded", nil)
			if err != nil {
				t.Fatalf("POST %s/auth/logout: %v", prefix, err)
			}
			defer out.Body.Close()
			cleared := cookie(t, out, sessionCookie)
			if want := cmp.Or(prefix, "/"); cleared.Path != want || cleared.MaxAge >= 0 {
				t.Errorf("logout cookie Path = %q MaxAge = %d, want %q and a negative MaxAge",
					cleared.Path, cleared.MaxAge, want)
			}
			signedOut, err := io.ReadAll(out.Body)
			if err != nil {
				t.Fatalf("read the signed-out page: %v", err)
			}
			if want := `href="` + prefix + `/">Sign in again</a>`; !strings.Contains(string(signedOut), want) {
				t.Errorf("signed-out page does not offer %s:\n%s", want, signedOut)
			}

			// Nothing outside the prefix belongs to this appliance: the proxy
			// forwards the prefix and nothing else, so the root is a 404
			// rather than a second way in.
			if prefix != "" {
				if resp, _ := h.get(c, h.ts.URL+"/"); resp.StatusCode != http.StatusNotFound {
					t.Errorf("GET / under a prefix: status %d, want 404", resp.StatusCode)
				}
			}
		})
	}
}

// cookie is the named cookie a response sets, or a fatal.
func cookie(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie on the %d response", name, resp.StatusCode)
	return nil
}
