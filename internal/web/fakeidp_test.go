package web

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Obviously fake credentials, in one place, so a secret scanner has nothing
// to find and no test invents its own.
const (
	testClientID     = "00000000-0000-0000-0000-000000000001"
	testClientSecret = "not-a-real-client-secret"
)

// fakeIDP is a small but real OpenID Connect provider: a real discovery
// document, a real JWKS, an authorization endpoint that redirects back with a
// code, and a token endpoint that checks PKCE and the client secret before
// issuing a properly RS256-signed ID token. Nothing here skips verification;
// the point is that go-oidc does its full job against it.
//
// Work package 5 lifts this file into a standalone e2e harness, so it depends
// on nothing else in this package's tests.
type fakeIDP struct {
	URL          string // the issuer, and the base of every endpoint
	ClientID     string
	ClientSecret string
	User         idpUser

	// Claims, if set, may change the ID token's claims before it is signed
	// (a wrong nonce, a wrong audience, an expired token).
	Claims func(map[string]any)
	// Token, if set, may change the signed ID token before it is handed out
	// (tampering with the signature).
	Token func(string) string

	// Exchanges counts calls to the token endpoint, so a test can assert
	// that a rejected callback never got as far as redeeming its code.
	Exchanges atomic.Int64

	t      *testing.T
	key    *rsa.PrivateKey
	server *httptest.Server

	mu      sync.Mutex
	pending map[string]pendingAuth
}

// idpUser is who the provider authenticates the next sign-in as.
type idpUser struct {
	Subject, Email, PreferredUsername, Name string
}

type pendingAuth struct {
	nonce       string
	challenge   string
	redirectURI string
}

const testKeyID = "test-key"

// newFakeIDP starts a provider and stops it when the test ends.
func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &fakeIDP{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		User: idpUser{
			Subject:           "user-subject",
			Email:             "ann@corp.example",
			PreferredUsername: "ann@corp.example",
			Name:              "Ann Example",
		},
		t:       t,
		key:     key,
		pending: make(map[string]pendingAuth),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.server = httptest.NewServer(mux)
	f.URL = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIDP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                f.URL,
		"authorization_endpoint":                f.URL + "/authorize",
		"token_endpoint":                        f.URL + "/token",
		"jwks_uri":                              f.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeIDP) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": testKeyID,
		"n":   b64(f.key.N.Bytes()),
		"e":   "AQAB", // Go always generates E=65537
	}}})
}

// authorize is the front-channel hop. It insists on the parameters a correct
// client sends, PKCE included, so a client that stopped sending them fails
// here instead of quietly losing the protection.
func (f *fakeIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for _, p := range []string{"state", "nonce", "code_challenge", "redirect_uri"} {
		if q.Get(p) == "" {
			f.t.Errorf("fake idp: authorization request without %s", p)
			http.Error(w, "missing "+p, http.StatusBadRequest)
			return
		}
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		f.t.Errorf("fake idp: code_challenge_method = %q, want S256", got)
		http.Error(w, "bad challenge method", http.StatusBadRequest)
		return
	}

	code := rand.Text()
	f.mu.Lock()
	f.pending[code] = pendingAuth{
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
		redirectURI: q.Get("redirect_uri"),
	}
	f.mu.Unlock()

	http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
}

// token is the back channel: one-shot code, real PKCE check, real client
// authentication, and a real signature over the ID token.
func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	f.Exchanges.Add(1)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != f.ClientID || secret != f.ClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	if got := r.PostFormValue("grant_type"); got != "authorization_code" {
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	p, known := f.pending[r.PostFormValue("code")]
	delete(f.pending, r.PostFormValue("code"))
	f.mu.Unlock()
	if !known {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if b64(sum[:]) != p.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	if got := r.PostFormValue("redirect_uri"); got != p.redirectURI {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss":                f.URL,
		"aud":                f.ClientID,
		"sub":                f.User.Subject,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"nonce":              p.nonce,
		"email":              f.User.Email,
		"preferred_username": f.User.PreferredUsername,
		"name":               f.User.Name,
	}
	if f.Claims != nil {
		f.Claims(claims)
	}
	idToken := f.sign(claims)
	if f.Token != nil {
		idToken = f.Token(idToken)
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// sign builds an RS256 JWT the way a provider does, with the standard library
// only: base64url(header).base64url(claims).base64url(signature).
func (f *fakeIDP) sign(claims map[string]any) string {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": testKeyID})
	if err != nil {
		f.t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatalf("marshal claims: %v", err)
	}
	signingInput := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		f.t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + b64(sig)
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
