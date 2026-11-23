// Package config loads scan2graph's typed, environment-first configuration
// and owns address normalization (see NormalizeAddress). Load reads
// well-known S2G_* environment variables, validates them, and returns either
// a fully valid *Config or a single error listing every problem found.
package config

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/georg-jung/scan2graph/internal/jobs"
)

// SMTPUsername is the SMTP AUTH username the printer signs in with. A
// constant: the password is the secret, and one printer needs one account.
const SMTPUsername = "scanner"

// Limits bounds resource usage for incoming SMTP messages. A decoded
// attachment is always smaller than the message that carried it, so
// MaxMessageBytes also bounds PDF sizes.
type Limits struct {
	MaxMessageBytes int64 // SMTP DATA cap
	MaxStoredBytes  int64 // disk budget for queued, in-flight and web-visible scans
}

// Config is scan2graph's fully validated, effective configuration. Build one
// with Load; the zero value is not meaningful.
type Config struct {
	HTTPAddr, SMTPAddr string
	PublicBaseURL      string // normalized: no trailing slash; "" if unset
	// PathPrefix is PublicBaseURL's path, e.g. "/scanner" when the appliance
	// shares a host with other applications, and "" when it has a host of its
	// own. The appliance both routes and emits it, so the reverse proxy must
	// forward the path unchanged rather than stripping the prefix.
	PathPrefix string
	LogLevel   slog.Level

	// SMTPPassword is never logged. When neither a password nor
	// SMTPAllowAnonymous was configured, Load generates one and sets
	// SMTPPasswordGenerated so main can print it once at startup.
	SMTPPassword          string
	SMTPAllowAnonymous    bool
	SMTPPasswordGenerated bool

	// Available is every feature this configuration can serve: email with a
	// Graph sender and a recipient allowlist, web with a public base URL, OCR
	// with a Document Intelligence endpoint. Features picks among them.
	Available jobs.Capabilities
	// AllowedRecipientDomains is the recipient-domain allowlist: lowercase,
	// without a leading "@". Empty means "every domain is allowed", which is
	// only a legal configuration when email is not available.
	AllowedRecipientDomains []string

	TenantID, ClientID string
	ClientSecret       string // never logged, never in String()/error text
	AuthorityURL       string // OIDC issuer used for discovery
	TokenURL           string // client-credentials token endpoint, derived from AuthorityURL

	GraphBaseURL, GraphSender string
	DIEndpoint                string

	JobTTL time.Duration
	Limits Limits
}

// Load builds a Config from environment variables, reading each one through
// getenv (pass os.Getenv in production; tests supply a fake). On failure the
// returned error is an errors.Join of one error per problem, each naming the
// offending variable, so a misconfigured deployment learns about every
// problem at once.
func Load(getenv func(string) string) (*Config, error) {
	l := &loader{getenv: getenv}
	c := &Config{}

	c.HTTPAddr = cmp.Or(getenv("S2G_HTTP_ADDR"), ":8080")
	c.SMTPAddr = cmp.Or(getenv("S2G_SMTP_ADDR"), ":2525")
	c.LogLevel = l.logLevel()
	c.SMTPPassword, c.SMTPAllowAnonymous, c.SMTPPasswordGenerated = l.smtpAuth()

	c.DIEndpoint = l.baseURL("S2G_DI_ENDPOINT", "https")
	c.AllowedRecipientDomains = l.domains()
	c.PublicBaseURL = l.publicBaseURL("S2G_PUBLIC_BASE_URL")
	c.PathPrefix = BasePath(c.PublicBaseURL)
	c.GraphSender = l.graphSender()

	// A configured Graph sender is an unambiguous statement of intent, so a
	// missing allowlist is an error rather than "email quietly off".
	if c.GraphSender != "" && len(c.AllowedRecipientDomains) == 0 {
		l.errorf("S2G_ALLOWED_RECIPIENT_DOMAINS is required because S2G_GRAPH_SENDER is configured: without a recipient domain allowlist scan2graph would be an open mail relay")
	}
	c.Available = jobs.Capabilities{
		Email: c.GraphSender != "" && len(c.AllowedRecipientDomains) > 0,
		Web:   c.PublicBaseURL != "",
		OCR:   c.DIEndpoint != "",
	}
	if !c.Available.Email && !c.Available.Web {
		l.errorf("scan2graph has no way to deliver a scan: configure S2G_PUBLIC_BASE_URL for the web UI, and/or S2G_GRAPH_SENDER with S2G_ALLOWED_RECIPIENT_DOMAINS for email delivery")
	}

	const identityReason = "scan2graph always needs an Entra app registration (for the web UI's OIDC login and for app-only Graph/Document Intelligence tokens)"
	c.TenantID = l.required("S2G_ENTRA_TENANT_ID", identityReason)
	c.ClientID = l.required("S2G_ENTRA_CLIENT_ID", identityReason)
	c.ClientSecret = l.required("S2G_ENTRA_CLIENT_SECRET", identityReason)

	// The authority is overridable so a test harness can point it at a fake
	// IdP; the token endpoint follows it, so that is one setting, not two.
	c.AuthorityURL = cmp.Or(l.baseURL("S2G_ENTRA_AUTHORITY_URL", "http", "https"),
		"https://login.microsoftonline.com/"+c.TenantID+"/v2.0")
	c.TokenURL = strings.TrimSuffix(c.AuthorityURL, "/v2.0") + "/oauth2/v2.0/token"

	c.GraphBaseURL = cmp.Or(l.baseURL("S2G_GRAPH_BASE_URL", "http", "https"), "https://graph.microsoft.com/v1.0")

	c.JobTTL = l.durationAtLeast("S2G_JOB_TTL", 8*time.Hour, time.Minute)

	c.Limits = l.limits()

	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	return c, nil
}

// domains resolves and validates S2G_ALLOWED_RECIPIENT_DOMAINS: an optional
// comma-separated list of domains, lowercased and deduplicated.
func (l *loader) domains() []string {
	parts := strings.Split(l.getenv("S2G_ALLOWED_RECIPIENT_DOMAINS"), ",")
	var out []string
	for _, p := range parts {
		d := strings.ToLower(strings.TrimSpace(p))
		if d == "" {
			continue
		}
		if !validDomain(d) {
			l.errorf("S2G_ALLOWED_RECIPIENT_DOMAINS: %q is not a valid domain", d)
			continue
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	if !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") ||
		strings.Contains(d, "..") {
		return false
	}
	// Deliberately strict: an entry like "*.corp.example" or "https://corp"
	// would otherwise be accepted and then never match anything, rejecting
	// every recipient with a 550 that looks like a printer problem.
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

// graphSender resolves and validates S2G_GRAPH_SENDER: a mailbox address,
// normalized like any other address.
func (l *loader) graphSender() string {
	raw := l.getenv("S2G_GRAPH_SENDER")
	if raw == "" {
		return ""
	}
	n := NormalizeAddress(raw)
	if n == "" {
		l.errorf("S2G_GRAPH_SENDER: %q is not a valid address", raw)
	}
	return n
}

// smtpAuth resolves the SMTP AUTH configuration. Anonymous mode with a
// password is contradictory; with neither, an ephemeral password is generated
// so the listener is never silently unauthenticated, and main prints it.
func (l *loader) smtpAuth() (password string, allowAnonymous, generated bool) {
	password = l.getenv("S2G_SMTP_PASSWORD")
	anon := l.boolValue("S2G_SMTP_ALLOW_ANONYMOUS")
	switch {
	case anon && password != "":
		l.errorf("S2G_SMTP_ALLOW_ANONYMOUS=true is contradictory with S2G_SMTP_PASSWORD being set; unset one of them")
		return "", true, false
	case anon:
		return "", true, false
	case password != "":
		return password, false, false
	}
	return rand.Text(), false, true
}

func (l *loader) limits() Limits {
	lim := Limits{
		MaxMessageBytes: l.int64Positive("S2G_MAX_MESSAGE_BYTES", 33554432),
		MaxStoredBytes:  l.int64Positive("S2G_MAX_STORED_BYTES", 536870912),
	}
	// Two messages must fit: an unread message is charged at the DATA cap, and
	// OCR briefly holds a scan twice. Halve the budget rather than double the
	// cap so it cannot overflow.
	if lim.MaxStoredBytes > 0 && lim.MaxMessageBytes > lim.MaxStoredBytes/2 {
		l.errorf("S2G_MAX_STORED_BYTES: must be at least twice S2G_MAX_MESSAGE_BYTES (%d), got %d",
			lim.MaxMessageBytes, lim.MaxStoredBytes)
	}
	return lim
}

func (l *loader) logLevel() slog.Level {
	raw := l.getenv("S2G_LOG_LEVEL")
	level := slog.LevelInfo
	if raw == "" {
		return level
	}
	if err := level.UnmarshalText([]byte(raw)); err != nil {
		l.errorf("S2G_LOG_LEVEL: must be one of debug, info, warn, error, got %q", raw)
		return slog.LevelInfo
	}
	return level
}

// Sender refusals. Static text, so an SMTP reply carrying one never echoes
// the client's input back onto the wire.
var (
	errBadSender   = errors.New("sender not recognized")
	errNoDelivery  = errors.New("sender names no delivery: add email or web")
	errUnavailable = errors.New("sender names a feature this appliance has not configured")
)

// Features returns the features a scan from envelopeSender gets. The words
// "email", "web" and "ocr" in its local part, split on anything but ASCII
// letters and digits, name exactly the features wanted; an address naming
// none of them gets everything Available. The error says why a sender is
// refused, in words fit for an SMTP reply.
func (c *Config) Features(envelopeSender string) (jobs.Capabilities, error) {
	if NormalizeAddress(envelopeSender) == "" {
		return jobs.Capabilities{}, errBadSender
	}
	// Split before lowercasing: Unicode case mapping turns a few non-ASCII
	// runes (U+0130, U+212A) into ASCII letters that would otherwise join a
	// word. Brackets and whitespace NormalizeAddress strips are separators.
	local, _, _ := strings.Cut(envelopeSender, "@")
	var named jobs.Capabilities
	for _, w := range strings.FieldsFunc(local, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		switch strings.ToLower(w) {
		case "email":
			named.Email = true
		case "web":
			named.Web = true
		case "ocr":
			named.OCR = true
		}
	}
	switch {
	case named == jobs.Capabilities{}:
		return c.Available, nil
	case !named.Email && !named.Web:
		return jobs.Capabilities{}, errNoDelivery
	case named.Email && !c.Available.Email, named.Web && !c.Available.Web, named.OCR && !c.Available.OCR:
		return jobs.Capabilities{}, errUnavailable
	}
	return named, nil
}

// NormalizeAddress lowercases s, trims surrounding whitespace and a matched
// pair of angle brackets, and returns "" unless the result is a plausible
// "local@domain" address: exactly one "@", a non-empty local part, a domain
// containing a ".", no whitespace or control characters, and length <= 254.
func NormalizeAddress(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if s == "" || len(s) > 254 {
		return ""
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return ""
		}
	}
	if strings.Count(s, "@") != 1 {
		return ""
	}
	at := strings.IndexByte(s, '@')
	local, domain := s[:at], s[at+1:]
	if local == "" || domain == "" || !strings.Contains(domain, ".") {
		return ""
	}
	return strings.ToLower(s)
}

// RecipientAllowed reports whether a canonical address may receive scans:
// true for every address when no domain allowlist is configured (only a
// legal configuration when email is not available), otherwise true iff the
// address's domain matches an entry in AllowedRecipientDomains exactly (no
// subdomain wildcards).
func (c *Config) RecipientAllowed(canonical string) bool {
	if len(c.AllowedRecipientDomains) == 0 {
		return true
	}
	at := strings.LastIndexByte(canonical, '@')
	if at < 0 {
		return false
	}
	return slices.Contains(c.AllowedRecipientDomains, strings.ToLower(canonical[at+1:]))
}

// LogValue returns a redacted summary of c suitable for slog: addresses,
// base URLs, available features, limits and TTLs, and whether the client
// secret is set - but never the secret itself.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http_addr", c.HTTPAddr),
		slog.String("smtp_addr", c.SMTPAddr),
		slog.String("smtp_auth", c.smtpAuthMode()),
		slog.String("public_base_url", c.PublicBaseURL),
		slog.String("log_level", c.LogLevel.String()),
		slog.Any("available", c.Available),
		slog.Any("allowed_recipient_domains", c.AllowedRecipientDomains),
		slog.String("tenant_id", c.TenantID),
		slog.String("client_id", c.ClientID),
		slog.Bool("client_secret_set", c.ClientSecret != ""),
		slog.String("authority_url", c.AuthorityURL),
		slog.String("token_url", c.TokenURL),
		slog.String("graph_base_url", c.GraphBaseURL),
		slog.String("graph_sender", c.GraphSender),
		slog.String("di_endpoint", c.DIEndpoint),
		slog.String("job_ttl", c.JobTTL.String()),
		slog.Any("limits", c.Limits),
	)
}

// String returns the same redacted summary as LogValue, formatted for
// fmt/%v/%s. Config intentionally has no method that could print
// ClientSecret or SMTPPassword.
func (c *Config) String() string {
	return fmt.Sprintf("Config%s", c.LogValue().String())
}

// smtpAuthMode summarizes SMTP AUTH for logging without ever exposing
// SMTPPassword: "disabled" when anonymous SMTP is allowed, "ephemeral" when
// Load generated the password itself, "configured" when an operator
// supplied one.
func (c *Config) smtpAuthMode() string {
	switch {
	case c.SMTPAllowAnonymous:
		return "disabled"
	case c.SMTPPasswordGenerated:
		return "ephemeral"
	default:
		return "configured"
	}
}
