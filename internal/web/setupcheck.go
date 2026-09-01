package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/msapi"
)

// The wizard's third button. config.Load proves a configuration is
// well-formed; it cannot tell an operator that their client secret expired
// last week - the wizard can ask, because it has the credentials in its
// hands at the moment the operator is looking at them.
//
// None of these checks sends mail, uploads a document or writes anything: a
// failure is advice rather than validation, so the file stays saveable even
// against a tenant this network cannot reach yet.

const (
	// checkTimeout bounds one check, so a hung identity provider cannot pin
	// the request goroutine. Seconds rather than the appliance's minutes: an
	// operator is watching this one.
	checkTimeout = 5 * time.Second
	// checkBodyLimit bounds one response body. No real answer comes close:
	// a discovery document, a token response and a document-model list are
	// single-digit kilobytes each, so this is a hostile server's ceiling and
	// not anybody's budget. go-oidc and oauth2 each read their body whole
	// with no limit of their own, and one press against an endless one takes
	// the wizard from 11 MB to 2.0 GB - a kill under a container's memory
	// limit.
	checkBodyLimit = 1 << 20 // 1 MiB
)

// checkResult is one line of the results block.
type checkResult struct {
	Name string
	OK   bool
	Skip string // why it was not run ("text recognition is off"), else ""
	Err  string // one line, on failure
}

// runChecks is the whole of it. cfg comes from the same config.Load the form
// already ran, so the checks and the appliance agree about what they are
// testing.
func runChecks(ctx context.Context, cfg *config.Config) []checkResult {
	// One client for all three: it never follows a redirect, since two of
	// them carry a credential a 3xx could walk to another origin, and it
	// caps every body it reads.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     capped{http.DefaultTransport},
	}
	// Not "is an endpoint configured": profiles can turn recognition off and
	// leave the setting behind, and probing an endpoint nothing uses would
	// report a failure about a feature that is not running.
	di := ""
	if !cfg.AnyOCR() {
		di = "text recognition is off"
	}
	secret := cfg.ClientSecret
	return []checkResult{
		// Discovery and the issuer match: what the web UI's login needs, so
		// a wrong authority or tenant is found here rather than at the first
		// sign-in. Close to what web.New does at startup, but not identical
		// - this client refuses redirects, because the two checks below it
		// carry a credential, and waits 5s where a start waits 15s.
		check(ctx, "Entra sign-in", "", secret, func(ctx context.Context) error {
			_, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.AuthorityURL)
			return err
		}),
		// The client id, the secret and the tenant, which Graph and Document
		// Intelligence both need. It always runs: every configuration has a
		// credential, and this is the only thing that spends it. Entra mints
		// .default for any app in the tenant, so a pass says nothing about
		// whether anybody granted Mail.Send - the wording under the results
		// says so, and asking Graph itself would need User.Read.All, which a
		// correctly scoped registration does not have and would go red on a
		// working appliance.
		check(ctx, "App-only token", "", secret, func(ctx context.Context) error {
			_, err := appToken(ctx, client, cfg, cfg.GraphScope)
			return err
		}),
		check(ctx, "Document Intelligence", di, secret, func(ctx context.Context) error {
			return checkDocIntel(ctx, client, cfg)
		}),
	}
}

// check runs one question under its own deadline, or says why it did not.
func check(ctx context.Context, name, skip, secret string, ask func(context.Context) error) checkResult {
	if skip != "" {
		return checkResult{Name: name, Skip: skip}
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	if err := ask(ctx); err != nil {
		return checkResult{Name: name, Err: oneLine(err, secret)}
	}
	return checkResult{Name: name, OK: true}
}

// appToken asks for one app-only token, the same client-credentials grant the
// appliance uses for Graph and for Document Intelligence.
func appToken(ctx context.Context, client *http.Client, cfg *config.Config, scope string) (*oauth2.Token, error) {
	cc := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
		Scopes:       []string{scope},
	}
	return cc.Token(context.WithValue(ctx, oauth2.HTTPClient, client))
}

// checkDocIntel lists the resource's models with an app-only token: one call
// proves the endpoint, its TLS chain, the token and the scope together.
func checkDocIntel(ctx context.Context, client *http.Client, cfg *config.Config) error {
	tok, err := appToken(ctx, client, cfg, cfg.DIScope)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		cfg.DIEndpoint+"/documentintelligence/documentModels?api-version="+url.QueryEscape(cfg.DIAPIVersion), nil)
	if err != nil {
		return err
	}
	tok.SetAuthHeader(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		// Accepted cost of reusing msapi's envelope reader: the status
		// prefix is lost when the service does send a message - the message
		// is the informative half.
		return errors.New(msapi.ErrorMessage(resp))
	}
	defer resp.Body.Close()
	// A 200 is not an answer. A captive portal or a misdirected proxy sends
	// one too, and has just been handed a real bearer token; only a list of
	// document models has the array the service documents.
	var body struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Value == nil {
		return errors.New("the endpoint answered, but not with a document-model list")
	}
	return nil
}

// oneLine flattens a failure into one rendered line: html/template escapes
// it, and only the browser holding the wizard sees it. What it carries is
// whatever the far end chose to say, which is the whole value of the feature
// - and secret is stripped out of it first, because oauth2.RetrieveError
// renders the token endpoint's error_description verbatim, so an endpoint
// that echoes the request back would otherwise put the client secret on the
// page. config.Load requires that secret, so it is never an empty needle.
func oneLine(err error, secret string) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	// Both spellings: the token request is form-encoded, so an endpoint that
	// echoes its body back returns a secret containing "&" or "+" as
	// client_secret=a%26b, which the literal never matches. Encoded first,
	// because encoding only ever lengthens: a secret ending in "%25" encodes
	// to "%2525", and taking the literal out first would eat the prefix and
	// leave the rest of the encoding sitting on the page.
	for _, form := range []string{url.QueryEscape(secret), secret} {
		s = strings.ReplaceAll(s, form, "***")
	}
	// Entra glues a trace id, a correlation id and a timestamp onto every
	// message, so the useful part is the front; 200 bytes keeps it one
	// readable line. After the redaction, or the cut could leave half a
	// secret behind.
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "") + "…"
	}
	return s
}

// capped is checkBodyLimit as a RoundTripper, so all three checks get it
// rather than only the one that does its own HTTP: the other two hand their
// response to a library that reads it whole.
type capped struct{ http.RoundTripper }

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.RoundTripper.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, checkBodyLimit), resp.Body}
	return resp, nil
}
