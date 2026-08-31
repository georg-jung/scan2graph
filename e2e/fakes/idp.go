package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// pendingAuth is one authorization request, kept between the authorize hop
// and the account the browser picks on the next one.
type pendingAuth struct {
	redirectURI, state, nonce, challenge string
}

// grant is a minted authorization code: the request it belongs to and who
// was picked. Redeemed exactly once at the token endpoint.
type grant struct {
	auth pendingAuth
	user user
}

func (f *fakes) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakes) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": keyID,
		"n":   b64(f.key.N.Bytes()),
		"e":   "AQAB", // Go always generates E=65537
	}}})
}

// authorize is the front-channel hop. It insists on everything a correct
// client sends - PKCE and an exactly matching redirect URI included - and
// then renders an account picker, so the suite signs in through a real
// browser navigation rather than a side channel.
func (f *fakes) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != clientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if q.Get("redirect_uri") != redirectURI {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	for _, p := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(p) == "" {
			http.Error(w, "missing "+p, http.StatusBadRequest)
			return
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	id := rand.Text()
	f.mu.Lock()
	f.pending[id] = pendingAuth{
		redirectURI: q.Get("redirect_uri"),
		state:       q.Get("state"),
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
	}
	f.mu.Unlock()

	// id is base32 from crypto/rand, so there is nothing to escape here.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Sign in</title>
<h1>Pick an account</h1>
<ul>
<li><a id="signin-alice" href="/idp/approve?user=alice&amp;req=%[1]s">Alice Adams</a></li>
<li><a id="signin-bob" href="/idp/approve?user=bob&amp;req=%[1]s">Bob Brown</a></li>
</ul>
`, id)
}

// approve is the account picker's target: it mints a one-time code for the
// chosen user and sends the browser back to the appliance.
func (f *fakes) approve(w http.ResponseWriter, r *http.Request) {
	u, ok := users[r.URL.Query().Get("user")]
	if !ok {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	auth, known := f.pending[r.URL.Query().Get("req")]
	code := rand.Text()
	if known {
		f.codes[code] = grant{auth: auth, user: u}
	}
	f.mu.Unlock()
	if !known {
		http.Error(w, "no such authorization request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, auth.redirectURI+"?code="+code+"&state="+url.QueryEscape(auth.state), http.StatusFound)
}

// token is the back channel. Client authentication, the one-shot code, the
// redirect URI and PKCE are all checked for real: the suite's sign-in is
// only evidence if this endpoint would refuse a broken one.
func (f *fakes) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	// oauth2 sends the client credentials as HTTP Basic or as form fields
	// depending on what it has learned about the endpoint; accept both.
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != clientID || secret != fixtureSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	switch r.PostFormValue("grant_type") {
	case "client_credentials":
		// The scope is part of the token, so a service can refuse one minted
		// for another - which is what real Entra does with a resource it was
		// not asked for.
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": appToken + "|" + r.PostFormValue("scope"),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	case "authorization_code":
		f.authorizationCode(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (f *fakes) authorizationCode(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	g, known := f.codes[r.PostFormValue("code")]
	delete(f.codes, r.PostFormValue("code")) // one code, one exchange
	f.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !known || b64(sum[:]) != g.auth.challenge || r.PostFormValue("redirect_uri") != g.auth.redirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	now := time.Now()
	idToken, err := f.sign(map[string]any{
		"iss":                f.issuer,
		"aud":                clientID,
		"sub":                g.user.subject,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"nonce":              g.auth.nonce,
		"email":              g.user.email,
		"preferred_username": g.user.email,
		"name":               g.user.name,
	})
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": userToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// sign builds an RS256 JWT the way a provider does, with the standard
// library only: base64url(header).base64url(claims).base64url(signature).
func (f *fakes) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
