package web

import (
	"context"
	"crypto/rand"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "s2g_session"
	authCookie    = "s2g_auth"
	authPath      = "/auth" // scope of the short-lived sign-in cookie
	// authCookieMaxAge is in seconds: a sign-in that takes longer has failed.
	authCookieMaxAge = 600
)

// handleLogin starts the authorization-code flow. state, nonce and the PKCE
// verifier are handed to the browser in one short-lived cookie and checked
// again on the callback; the nonce additionally has to come back inside the
// signed ID token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, nonce := rand.Text(), rand.Text()
	verifier := oauth2.GenerateVerifier()
	setCookie(w, &http.Cookie{
		Name:   authCookie,
		Value:  state + "|" + nonce + "|" + verifier,
		Path:   authPath,
		MaxAge: authCookieMaxAge,
	})
	url := s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback finishes the flow: state, then the code exchange, then a
// fully verified ID token (signature, issuer, audience, expiry via go-oidc)
// whose nonce must match the one this browser started with.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(authCookie)
	clearCookie(w, authCookie, authPath) // one cookie, one attempt
	if err != nil {
		s.signInFailed(w, "no sign-in is in progress", nil)
		return
	}
	// Every part must be present: an empty state would be "equal" to a
	// callback that carries no state at all, and an empty nonce to an ID
	// token with no nonce claim, so a forged "||" cookie would satisfy both
	// checks by being absent rather than by matching.
	parts := strings.Split(c.Value, "|")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		s.signInFailed(w, "malformed sign-in cookie", nil)
		return
	}
	state, nonce, verifier := parts[0], parts[1], parts[2]

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.signInFailed(w, "the identity provider refused the sign-in", nil)
		return
	}
	if state != q.Get("state") {
		s.signInFailed(w, "state mismatch", nil)
		return
	}

	// Both libraries take their HTTP client from the context, each under its
	// own key, so the timeout applies to the exchange and to a JWKS refresh.
	ctx := oidc.ClientContext(context.WithValue(r.Context(), oauth2.HTTPClient, s.client), s.client)
	token, err := s.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		s.signInFailed(w, "code exchange failed", err)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		s.signInFailed(w, "no id_token in the token response", nil)
		return
	}
	idToken, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		s.signInFailed(w, "id token verification failed", err)
		return
	}
	if idToken.Nonce != nonce {
		s.signInFailed(w, "nonce mismatch", nil)
		return
	}

	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		s.signInFailed(w, "id token claims are unreadable", err)
		return
	}

	identities := s.identities(claims.Email, claims.PreferredUsername)
	setCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  s.sessions.create(&session{identities: identities, name: claims.Name}),
		Path:   "/",
		MaxAge: int(sessionTTL.Seconds()),
	})
	// Counts only: the addresses themselves stay out of the log, as they do
	// on the SMTP side.
	s.log.Info("web: user signed in", "identities", len(identities))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout drops the session server-side as well as clearing the cookie,
// so a copied cookie value is worthless afterwards.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.drop(c.Value)
	}
	clearCookie(w, sessionCookie, "/")
	s.render(w, signedOutTmpl, page{Title: "Signed out"})
}

// identities are the canonical addresses the signed-in user is known by,
// taken from the verified claims and put through the same canonicalization
// (alias map included) that the SMTP side applied to the envelope recipients.
// Anything that is not a plausible address drops out, which is why a user
// whose claims match nothing simply sees an empty list.
func (s *Server) identities(claims ...string) []string {
	out := make([]string, 0, len(claims))
	for _, c := range claims {
		id := s.cfg.Canonical(c)
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// session returns the live session a request carries, if any.
func (s *Server) session(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	return s.sessions.get(c.Value)
}

// signInFailed answers every sign-in problem the same way and logs the reason.
// err is a provider or protocol error; go-oidc and oauth2 do not put tokens in
// their error text, and nothing else here is logged.
func (s *Server) signInFailed(w http.ResponseWriter, reason string, err error) {
	s.log.Warn("web: sign-in failed", "reason", reason, "err", err)
	http.Error(w, "sign-in failed", http.StatusBadRequest)
}

// setCookie applies the attributes every cookie here needs. Secure is right
// even though this server speaks plain HTTP: the reverse proxy in front of the
// appliance terminates TLS.
func setCookie(w http.ResponseWriter, c *http.Cookie) {
	c.HttpOnly = true
	c.Secure = true
	c.SameSite = http.SameSiteLaxMode
	http.SetCookie(w, c)
}

func clearCookie(w http.ResponseWriter, name, path string) {
	setCookie(w, &http.Cookie{Name: name, Value: "", Path: path, MaxAge: -1})
}
