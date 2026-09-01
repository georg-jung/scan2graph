package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georg-jung/scan2graph/internal/config"
)

// The scopes a real deployment uses, which is what makes "a token minted for
// the other scope" a realistic failure rather than a contrived one.
const (
	testGraphScope = "https://graph.microsoft.com/.default"
	testDIScope    = "https://cognitiveservices.azure.com/.default"
)

// msStub stands in for Entra and Document Intelligence together: a discovery
// document go-oidc accepts, a client-credentials endpoint that checks the
// client secret and mints a token naming the scope it was asked for, and a
// document-model list that refuses a token minted for a different one.
type msStub struct {
	URL    string
	secret string // the client secret it accepts
	scope  string // the scope its document-model list requires
}

func newMSStub(t *testing.T) *msStub {
	t.Helper()
	s := &msStub{secret: testClientSecret, scope: testDIScope}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                s.URL,
			"authorization_endpoint":                s.URL + "/authorize",
			"token_endpoint":                        s.URL + "/token",
			"jwks_uri":                              s.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /documentintelligence/documentModels", s.models)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	s.URL = ts.URL
	return s
}

// token is the app-only grant, refusing a wrong secret the way Entra does:
// the message an operator has to read is the whole point of the feature.
func (s *msStub) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	switch {
	case id != testClientID:
		writeStatusJSON(w, http.StatusUnauthorized, map[string]any{
			"error":             "unauthorized_client",
			"error_description": "AADSTS700016: Application not found in the directory.\r\nTrace ID: 0\r\nCorrelation ID: 0\r\nTimestamp: now",
		})
	case secret != s.secret:
		writeStatusJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "invalid_client",
			"error_description": "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, " +
				"not the client secret ID, for a secret added to the app.\r\nTrace ID: 0\r\nCorrelation ID: 0\r\nTimestamp: now",
		})
	case r.PostFormValue("grant_type") != "client_credentials":
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
	default:
		// The token names its scope, so a resource can refuse one minted for
		// another - which is how the wrong-scope failure is reproduced here.
		writeJSON(w, map[string]any{
			"access_token": "token-for-" + r.PostFormValue("scope"),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}
}

func (s *msStub) models(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer token-for-"+s.scope {
		writeStatusJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"code": "401", "message": "Access denied due to invalid subscription key or wrong API endpoint"},
		})
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"code": "400", "message": "api-version is required"},
		})
		return
	}
	writeJSON(w, map[string]any{"value": []map[string]any{{"modelId": "prebuilt-read"}}})
}

func writeStatusJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	writeJSON(w, v)
}

// stubConfig is what the loader would produce for a deployment pointed at the
// stub, with every feature on.
func (s *msStub) config() *config.Config {
	return &config.Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		AuthorityURL: s.URL,
		TokenURL:     s.URL + "/token",
		GraphScope:   testGraphScope,
		GraphSender:  "scanner@example.com",
		DIEndpoint:   s.URL,
		DIScope:      testDIScope,
		DIAPIVersion: "2024-11-30",
		// Load derives this from which settings are present; a hand-built
		// Config has to say it, or the checks read as an appliance with
		// recognition switched off.
		DefaultProfile: config.Capabilities{Email: true, Web: true, OCR: true},
	}
}

// results indexes what runChecks returned by name, so a test can say what it
// means without counting positions.
func results(t *testing.T, got []checkResult) map[string]checkResult {
	t.Helper()
	if len(got) != 3 {
		t.Fatalf("runChecks returned %d results, want 3: %+v", len(got), got)
	}
	byName := make(map[string]checkResult, len(got))
	for _, r := range got {
		byName[r.Name] = r
	}
	return byName
}

func wantOK(t *testing.T, r checkResult) {
	t.Helper()
	if !r.OK || r.Err != "" || r.Skip != "" {
		t.Errorf("%s: %+v, want a pass", r.Name, r)
	}
}

// wantFailure asserts a failure whose text says what went wrong, and never
// carries the client secret - the one string that must not reach the page.
func wantFailure(t *testing.T, r checkResult, contains string) {
	t.Helper()
	if r.OK || r.Err == "" {
		t.Fatalf("%s: %+v, want a failure", r.Name, r)
	}
	if !strings.Contains(r.Err, contains) {
		t.Errorf("%s failed with %q, want it to mention %q", r.Name, r.Err, contains)
	}
	if strings.Contains(r.Err, testClientSecret) {
		t.Errorf("%s: the failure text carries the client secret", r.Name)
	}
	if len(r.Err) > 200+len("…") {
		t.Errorf("%s: the failure text is %d bytes, want one line", r.Name, len(r.Err))
	}
}

// TestChecksPass is the configuration that works: all three questions
// answered, nothing skipped.
func TestChecksPass(t *testing.T) {
	got := results(t, runChecks(t.Context(), newMSStub(t).config()))
	for _, r := range got {
		wantOK(t, r)
	}
}

// TestChecksSkip is the appliance with email and OCR off: the credential is
// still spent - every configuration has one, and nothing else here tests it -
// while the check that has nothing to talk to says so in the operator's terms.
func TestChecksSkip(t *testing.T) {
	cfg := newMSStub(t).config()
	cfg.GraphSender, cfg.DIEndpoint = "", ""
	cfg.DefaultProfile = config.Capabilities{Web: true}
	got := results(t, runChecks(t.Context(), cfg))
	wantOK(t, got["Entra sign-in"])
	wantOK(t, got["App-only token"])
	if r := got["Document Intelligence"]; r.Skip != "text recognition is off" || r.OK || r.Err != "" {
		t.Errorf("%+v, want it skipped with %q", r, "text recognition is off")
	}
}

// A profile can turn recognition off and leave the endpoint setting behind.
// The endpoint is then inert, so probing it would report a failure about a
// feature that is not running - the skip follows the profiles, not the
// setting.
func TestChecksSkipDIWhenNoProfileWantsIt(t *testing.T) {
	cfg := newMSStub(t).config()
	cfg.DefaultProfile = config.Capabilities{}
	cfg.Profiles = map[string]config.Capabilities{
		"scan-web@scanner.local": {Web: true, OCR: false},
	}
	got := results(t, runChecks(t.Context(), cfg))
	wantOK(t, got["App-only token"])
	if r := got["Document Intelligence"]; r.Skip != "text recognition is off" || r.Err != "" {
		t.Errorf("Document Intelligence: %+v, want it skipped even with an endpoint configured", r)
	}
}

// TestChecksRefusedToken is the failure the feature exists for: the secret is
// wrong, and Entra's own sentence about it reaches the operator while sign-in
// still passes.
func TestChecksRefusedToken(t *testing.T) {
	stub := newMSStub(t)
	cfg := stub.config()
	cfg.ClientSecret = "stale-" + testClientSecret
	got := results(t, runChecks(t.Context(), cfg))
	wantOK(t, got["Entra sign-in"])
	wantFailure(t, got["App-only token"], "AADSTS7000215")
	wantFailure(t, got["Document Intelligence"], "AADSTS7000215")
}

// TestChecksWrongScope is a token the resource will not accept: everything
// about the app registration is right, and Document Intelligence still
// refuses it - which reachability alone would never have found.
func TestChecksWrongScope(t *testing.T) {
	cfg := newMSStub(t).config()
	cfg.DIScope = "https://example.invalid/.default"
	got := results(t, runChecks(t.Context(), cfg))
	wantOK(t, got["Entra sign-in"])
	wantOK(t, got["App-only token"])
	wantFailure(t, got["Document Intelligence"], "Access denied")
}

// TestChecksWrongEndpoint is the pasted-in URL that answers, but not as a
// Document Intelligence resource.
func TestChecksWrongEndpoint(t *testing.T) {
	stub := newMSStub(t)
	cfg := stub.config()
	cfg.DIEndpoint = stub.URL + "/some-other-resource"
	got := results(t, runChecks(t.Context(), cfg))
	wantOK(t, got["App-only token"])
	wantFailure(t, got["Document Intelligence"], "404")
}

// TestChecksNotAResource is the 200 that is not an answer: a captive portal
// or a misdirected proxy, which has just been handed a real bearer token.
func TestChecksNotAResource(t *testing.T) {
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"message": "sign in to use this network"})
	}))
	t.Cleanup(portal.Close)
	cfg := newMSStub(t).config()
	cfg.DIEndpoint = portal.URL
	got := results(t, runChecks(t.Context(), cfg))
	wantOK(t, got["App-only token"])
	wantFailure(t, got["Document Intelligence"], "not with a document-model list")
}

// TestChecksRedactTheSecret is the token endpoint that echoes the request
// back: oauth2 renders error_description verbatim, and the request carries
// the client secret, so what is rendered has to be the redacted copy.
func TestChecksRedactTheSecret(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_request", "error_description": string(body),
		})
	}))
	t.Cleanup(echo.Close)

	// Entra allows both of these. The first diverges from its own encoding at
	// the "&", so only the encoded spelling ever reaches the page. The second
	// is URL-safe until the "%", so the literal is a *prefix* of the encoding
	// - take the literal out first and "%2525" becomes "***25", leaving the
	// tail of the encoding on the page and no pattern left to match it.
	for _, secret := range []string{
		testClientSecret + "&+ /",
		testClientSecret + "%25",
	} {
		t.Run(secret, func(t *testing.T) {
			cfg := newMSStub(t).config()
			cfg.TokenURL, cfg.ClientSecret = echo.URL, secret
			got := results(t, runChecks(t.Context(), cfg))["App-only token"]
			// wantFailure asserts the absence of the literal; "***" is what
			// proves the echo happened at all, rather than the request never
			// being made.
			wantFailure(t, got, "***")
			if strings.Contains(got.Err, url.QueryEscape(secret)) {
				t.Errorf("the failure text carries the secret url-encoded: %q", got.Err)
			}
			// A replacement that ate its way past the start of the other
			// spelling leaves that spelling's tail attached to the mark.
			encoded := url.QueryEscape(secret)
			for i := 1; i < len(encoded); i++ {
				if tail := encoded[i:]; strings.Contains(got.Err, "***"+tail) {
					t.Errorf("the redaction left %q of the encoding behind: %q", tail, got.Err)
					break
				}
			}
		})
	}
}

// TestChecksBounded is the identity provider that accepts the connection and
// then says nothing. Every check has to come back, so the request goroutine
// an operator is waiting on is never pinned. The deadline comes from the
// caller here rather than from checkTimeout, so the test costs milliseconds
// instead of seconds; what it proves is that the deadline is honoured at all,
// which is the same mechanism checkTimeout bounds the real thing with.
func TestChecksBounded(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); ts.Close() })

	cfg := newMSStub(t).config()
	cfg.AuthorityURL, cfg.TokenURL = ts.URL, ts.URL+"/token"
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	got := results(t, runChecks(ctx, cfg))
	// The caller's 200ms deadline is what should end this, so a correct run
	// is about that long. The bound is deliberately far below one
	// checkTimeout: at three sequential checks, a ceiling of 3*checkTimeout
	// would stay green with a check that ignored the context altogether,
	// which is the only thing this test is here to catch.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("runChecks took %s against a server that never answers", elapsed)
	}
	for _, r := range got {
		if r.OK || r.Err == "" {
			t.Errorf("%s: %+v, want a failure", r.Name, r)
		}
	}
}

// testForm is a submission the loader accepts, pointed at the stub through
// the two settings the form does not show.
func testForm(stub *msStub) (url.Values, map[string]string) {
	form := validForm()
	form.Set("action", "test")
	return form, map[string]string{
		"S2G_ENTRA_AUTHORITY_URL": stub.URL,
		"S2G_ENTRA_TOKEN_URL":     stub.URL + "/token",
	}
}

// TestSetupTestConnection presses the third button: the results are rendered
// above the form, the submission is still in the boxes, and nothing about the
// secret reaches the page.
func TestSetupTestConnection(t *testing.T) {
	stub := newMSStub(t)
	form, file := testForm(stub)
	h := newSetupHarness(t, SetupOptions{FileValues: file})
	c := h.claimed()

	resp, body := h.post(c, form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{
		"Entra sign-in", "App-only token",
		"not run — text recognition is off",
		form.Get("S2G_PUBLIC_BASE_URL"), // the submission survives alongside the results
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not mention %q", want)
		}
	}
	if strings.Contains(body, testClientSecret) {
		t.Fatal("the results page rendered the client secret")
	}
	if strings.Contains(body, "class=\"fail\"") {
		t.Errorf("a check failed against the stub: %s", body)
	}
}

// TestSetupTestConnectionFailureStillSaves is the rule the whole feature
// hangs on: a check is advice, not validation. An operator whose tenant this
// network cannot reach - here, a secret it refuses - still gets to write the
// file.
func TestSetupTestConnectionFailureStillSaves(t *testing.T) {
	stub := newMSStub(t)
	stub.secret = "some-other-" + testClientSecret
	form, file := testForm(stub)
	// Email delivery on, so the check that asks for an app-only token - the
	// one a wrong secret fails - actually runs.
	form.Set("S2G_GRAPH_SENDER", "scanner@example.com")
	form.Set("S2G_ALLOWED_RECIPIENT_DOMAINS", "example.com")
	path := filepath.Join(t.TempDir(), setupFileName)
	h := newSetupHarness(t, SetupOptions{FileValues: file, Path: path})
	c := h.claimed()

	_, body := h.post(c, form)
	if !strings.Contains(body, "AADSTS7000215") {
		t.Errorf("the page does not carry the identity provider's own message: %s", body)
	}
	if strings.Contains(body, testClientSecret) {
		t.Fatal("the results page rendered the client secret")
	}

	form.Set("action", "save")
	if _, body := h.post(c, form); !strings.Contains(body, "Saved") {
		t.Fatalf("a failed check blocked the save: %s", body)
	}
	if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != testClientSecret {
		t.Errorf("the saved secret is %q, want the submitted one", got)
	}
}

// TestSetupTestConnectionNeedsTheHolder is the same door as save and
// download, not a second one: a browser that never claimed the wizard cannot
// make it talk to anything.
func TestSetupTestConnectionNeedsTheHolder(t *testing.T) {
	stub := newMSStub(t)
	form, file := testForm(stub)
	h := newSetupHarness(t, SetupOptions{FileValues: file})
	h.claimed() // somebody else holds it

	resp, body := h.post(h.client(), form)
	if resp.StatusCode != http.StatusNotFound || strings.Contains(body, "Entra sign-in") {
		t.Errorf("an unauthorized POST got status %d and %q, want a 404 and no results", resp.StatusCode, body)
	}
}
