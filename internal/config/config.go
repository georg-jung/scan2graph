// Package config loads scan2graph's typed, environment-first configuration
// and owns address canonicalization (see NormalizeAddress and
// (*Config).Canonical). There is no configuration framework here: Load reads
// well-known S2G_* environment variables (or the file an S2G_*_FILE points
// at), validates them, and returns either a fully valid *Config or a single
// error listing every problem found.
package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Capabilities is the set of independent features a sender profile enables.
type Capabilities struct {
	Email bool `json:"email"`
	Web   bool `json:"web"`
	OCR   bool `json:"ocr"`
}

// Limits bounds resource usage for incoming SMTP messages and the pipeline.
//
// A decoded attachment is always smaller than the message that carried it,
// so MaxMessageBytes already bounds PDF sizes without a separate cap. MIME
// part/depth/count caps are constants in the MIME package instead (work
// package 2), and OCR concurrency follows the worker count.
type Limits struct {
	MaxMessageBytes   int64 // SMTP DATA cap
	MaxJobs           int   // queued + in-flight + web-visible jobs
	MaxConcurrentJobs int   // pipeline workers
}

// Config is scan2graph's fully validated, effective configuration. Build one
// with Load; the zero value is not meaningful.
type Config struct {
	HTTPAddr, SMTPAddr string
	PublicBaseURL      string // normalized: no trailing slash; "" if unset
	TempDir            string
	LogLevel           slog.Level
	LogFormat          string

	// SMTPUsername/SMTPPassword are the SMTP AUTH PLAIN/LOGIN credentials
	// the scanner must present. SMTPPassword is never logged. When
	// SMTPAllowAnonymous is true both stay empty and AUTH is not required.
	// When neither a password nor SMTPAllowAnonymous was configured, Load
	// generates an ephemeral SMTPPassword and sets SMTPPasswordGenerated so
	// main can print it once at startup.
	SMTPUsername          string
	SMTPPassword          string
	SMTPAllowAnonymous    bool
	SMTPPasswordGenerated bool

	// Profiles maps a canonical envelope-sender address to the capabilities
	// it enables. Keys are normalized with NormalizeAddress. It may be
	// empty, in which case DefaultProfile applies to every sender.
	Profiles map[string]Capabilities
	// DefaultProfile is what every sender gets when no profiles are
	// configured: each capability is enabled exactly when the configuration
	// it needs is present (a Graph sender plus a recipient allowlist for
	// email, a public base URL for web, a Document Intelligence endpoint for
	// OCR). It is the zero value when Profiles is not empty.
	DefaultProfile Capabilities
	// RecipientAliases maps a canonical alias address to the canonical
	// identity address it stands for. Applied exactly once by Canonical.
	RecipientAliases map[string]string
	// AllowedRecipientDomains is the recipient-domain allowlist: lowercase,
	// without a leading "@". Empty means "every domain is allowed", which is
	// only a legal configuration when no profile enables email.
	AllowedRecipientDomains []string

	TenantID, ClientID string
	ClientSecret       string // never logged, never in String()/error text
	AuthorityURL       string // OIDC issuer used for discovery
	TokenURL           string // client-credentials token endpoint

	GraphBaseURL, GraphScope, GraphSender string
	DIEndpoint, DIAPIVersion, DIScope     string

	JobTTL time.Duration
	Limits Limits
}

// Load builds a Config from environment variables, reading each one through
// getenv (pass os.Getenv in production; tests supply a fake). Every S2G_*
// variable listed in the project spec may instead be supplied as
// S2G_*_FILE, pointing at a file whose content (trailing whitespace/newlines
// trimmed) is used as the value; setting both is an error.
//
// Load validates as much as it can before returning, so a misconfigured
// deployment learns about every problem at once: on failure the returned
// error is an errors.Join of one distinct error per problem, each naming the
// offending environment variable.
func Load(getenv func(string) string) (*Config, error) {
	l := newLoader(getenv)
	c := &Config{}

	c.HTTPAddr = l.stringDefault("S2G_HTTP_ADDR", ":8080")
	c.SMTPAddr = l.stringDefault("S2G_SMTP_ADDR", ":2525")
	c.TempDir = l.stringDefault("S2G_TEMP_DIR", os.TempDir())
	c.LogFormat = l.logFormat()
	c.LogLevel = l.logLevel()

	c.SMTPUsername, c.SMTPPassword, c.SMTPAllowAnonymous, c.SMTPPasswordGenerated = l.smtpAuth()

	c.Profiles = l.profiles()
	c.RecipientAliases = l.aliases(c.Profiles)

	var anyEmail, anyWeb, anyOCR bool
	for _, cp := range c.Profiles {
		anyEmail = anyEmail || cp.Email
		anyWeb = anyWeb || cp.Web
		anyOCR = anyOCR || cp.OCR
	}

	// Each of these is required only when an explicit profile asks for the
	// capability it serves. Without profiles they are all optional, and
	// whichever ones are configured decide what the default profile does.
	c.DIEndpoint = l.baseURL("S2G_DI_ENDPOINT", anyOCR,
		`at least one sender profile has "ocr" enabled`, "https")
	c.DIAPIVersion = l.stringDefault("S2G_DI_API_VERSION", "2024-11-30")
	c.DIScope = l.stringDefault("S2G_DI_SCOPE", "https://cognitiveservices.azure.com/.default")

	c.AllowedRecipientDomains = l.domains(anyEmail, `at least one sender profile has "email" enabled`)
	c.PublicBaseURL = l.rootBaseURL("S2G_PUBLIC_BASE_URL", anyWeb,
		`at least one sender profile has "web" enabled`, "http", "https")
	c.GraphSender = l.graphSender(anyEmail, `at least one sender profile has "email" enabled`)

	if len(c.Profiles) == 0 {
		// A configured Graph sender is an unambiguous statement of intent,
		// so a missing allowlist is an error rather than "email quietly off".
		if c.GraphSender != "" && len(c.AllowedRecipientDomains) == 0 {
			l.errorf("S2G_ALLOWED_RECIPIENT_DOMAINS is required because S2G_GRAPH_SENDER is configured: without a recipient domain allowlist scan2graph would be an open mail relay")
		}
		c.DefaultProfile = Capabilities{
			Email: c.GraphSender != "" && len(c.AllowedRecipientDomains) > 0,
			Web:   c.PublicBaseURL != "",
			OCR:   c.DIEndpoint != "",
		}
		if !c.DefaultProfile.Email && !c.DefaultProfile.Web {
			l.errorf("scan2graph has no way to deliver a scan: configure S2G_PUBLIC_BASE_URL for the web UI, and/or S2G_GRAPH_SENDER with S2G_ALLOWED_RECIPIENT_DOMAINS for email delivery (or define S2G_PROFILES explicitly)")
		}
	}

	const identityReason = "scan2graph always needs an Entra app registration (for the web UI's OIDC login and for app-only Graph/Document Intelligence tokens)"
	c.TenantID = l.requiredIf("S2G_ENTRA_TENANT_ID", true, identityReason)
	c.ClientID = l.requiredIf("S2G_ENTRA_CLIENT_ID", true, identityReason)
	c.ClientSecret = l.requiredIf("S2G_ENTRA_CLIENT_SECRET", true, identityReason)

	c.AuthorityURL = l.tenantURL("S2G_ENTRA_AUTHORITY_URL", c.TenantID, "/v2.0")
	c.TokenURL = l.tenantURL("S2G_ENTRA_TOKEN_URL", c.TenantID, "/oauth2/v2.0/token")

	c.GraphBaseURL = l.baseURLDefault("S2G_GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0", "http", "https")
	c.GraphScope = l.stringDefault("S2G_GRAPH_SCOPE", "https://graph.microsoft.com/.default")

	c.JobTTL = l.durationAtLeast("S2G_JOB_TTL", 90*time.Minute, time.Minute)

	c.Limits = l.limits()

	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	return c, nil
}

// profiles resolves and validates S2G_PROFILES: an optional JSON object
// mapping envelope-sender address to Capabilities. Keys are normalized with
// NormalizeAddress; unknown JSON fields, invalid keys, all-false capability
// sets and keys that collide after normalization are all errors. An empty
// result means "no profiles configured", which makes Config.DefaultProfile
// apply to every sender.
func (l *loader) profiles() map[string]Capabilities {
	raw, ok := decodeStringMap[Capabilities](l, "S2G_PROFILES")
	if !ok {
		return nil
	}

	out := make(map[string]Capabilities, len(raw))
	for k, cp := range raw {
		canon := NormalizeAddress(k)
		if canon == "" {
			l.errorf("S2G_PROFILES: key %q is not a valid address", k)
			continue
		}
		if !cp.Email && !cp.Web && !cp.OCR {
			l.errorf("S2G_PROFILES: profile %q has no capability enabled (email, web and ocr are all false)", k)
			continue
		}
		if _, dup := out[canon]; dup {
			l.errorf("S2G_PROFILES: key %q normalizes to %q, which is already used by another profile key", k, canon)
			continue
		}
		out[canon] = cp
	}
	return out
}

// aliases resolves and validates S2G_RECIPIENT_ALIASES: an optional JSON
// object mapping a shorthand alias address to the canonical identity address
// it stands for. Both sides are normalized with NormalizeAddress; an alias
// key that collides with a profile key, or with another alias key after
// normalization, is an error. An alias whose key equals its value is legal
// (pointless, but harmless).
func (l *loader) aliases(profiles map[string]Capabilities) map[string]string {
	raw, ok := decodeStringMap[string](l, "S2G_RECIPIENT_ALIASES")
	if !ok {
		return nil
	}

	out := make(map[string]string, len(raw))
	for k, v := range raw {
		ck := NormalizeAddress(k)
		if ck == "" {
			l.errorf("S2G_RECIPIENT_ALIASES: key %q is not a valid address", k)
			continue
		}
		cv := NormalizeAddress(v)
		if cv == "" {
			l.errorf("S2G_RECIPIENT_ALIASES: value %q for key %q is not a valid address", v, k)
			continue
		}
		if _, isProfile := profiles[ck]; isProfile {
			l.errorf("S2G_RECIPIENT_ALIASES: key %q is also a S2G_PROFILES key, which is confusing configuration", ck)
			continue
		}
		if _, dup := out[ck]; dup {
			l.errorf("S2G_RECIPIENT_ALIASES: key %q normalizes to %q, which is already used by another alias key", k, ck)
			continue
		}
		out[ck] = cv
	}
	return out
}

// domains resolves and validates S2G_ALLOWED_RECIPIENT_DOMAINS: an optional
// comma-separated list of domains, lowercased and deduplicated. It is
// required (and an error if it ends up empty) whenever required is true.
func (l *loader) domains(required bool, reason string) []string {
	raw, ok := l.resolve("S2G_ALLOWED_RECIPIENT_DOMAINS")
	var out []string
	if ok {
		out = l.parseDomains(raw)
	}
	if required && len(out) == 0 {
		l.errorf("S2G_ALLOWED_RECIPIENT_DOMAINS is required because %s: without a recipient domain allowlist scan2graph would be an open mail relay", reason)
	}
	return out
}

func (l *loader) parseDomains(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		d := strings.ToLower(strings.TrimSpace(p))
		if d == "" {
			continue
		}
		if !validDomain(d) {
			l.errorf("S2G_ALLOWED_RECIPIENT_DOMAINS: %q is not a valid domain", d)
			continue
		}
		if !seen[d] {
			seen[d] = true
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

// graphSender resolves and validates S2G_GRAPH_SENDER, required whenever
// required is true: a mailbox address, normalized like any other address.
func (l *loader) graphSender(required bool, reason string) string {
	raw := l.requiredIf("S2G_GRAPH_SENDER", required, reason)
	if raw == "" {
		return ""
	}
	n := NormalizeAddress(raw)
	if n == "" {
		l.errorf("S2G_GRAPH_SENDER: %q is not a valid address", raw)
		return ""
	}
	return n
}

// smtpAuth resolves and validates the SMTP AUTH configuration:
//
//   - a configured password requires AUTH; the username defaults to
//     "scanner" if not set explicitly.
//   - a configured username without a password is an error.
//   - S2G_SMTP_ALLOW_ANONYMOUS=true together with a configured username or
//     password is an error (contradictory); when true (and uncontested),
//     username and password stay empty and AUTH is not required.
//   - if neither a password nor anonymous mode was configured, an ephemeral
//     password is generated so the listener is never silently
//     unauthenticated; the caller (main) is expected to print it once at
//     startup, since this package itself never logs it.
func (l *loader) smtpAuth() (username, password string, allowAnonymous, generated bool) {
	userRaw, userSet := l.resolve("S2G_SMTP_USERNAME")
	passRaw, passSet := l.resolve("S2G_SMTP_PASSWORD")
	anon, _ := l.boolValue("S2G_SMTP_ALLOW_ANONYMOUS", false)

	if anon && (userSet || passSet) {
		l.errorf("S2G_SMTP_ALLOW_ANONYMOUS=true is contradictory with S2G_SMTP_USERNAME or S2G_SMTP_PASSWORD being set; unset them, or leave S2G_SMTP_ALLOW_ANONYMOUS unset/false to use SMTP AUTH")
	}
	if anon {
		return "", "", true, false
	}

	if userSet && !passSet {
		l.errorf("S2G_SMTP_USERNAME is set but S2G_SMTP_PASSWORD is not; SMTP AUTH requires both, or set S2G_SMTP_ALLOW_ANONYMOUS=true to run without AUTH")
	}
	// An empty value (typically an unpopulated Docker secret file) must never
	// turn into "AUTH enabled, empty password accepted".
	if passSet && passRaw == "" {
		l.errorf("S2G_SMTP_PASSWORD is set but empty; set a real password, or set S2G_SMTP_ALLOW_ANONYMOUS=true to run without AUTH")
	}
	if userSet && userRaw == "" {
		l.errorf("S2G_SMTP_USERNAME is set but empty; unset it to use the default %q", "scanner")
	}

	if passSet {
		username = "scanner"
		if userSet {
			username = userRaw
		}
		return username, passRaw, false, false
	}

	// Neither a password nor anonymous mode was configured.
	return "scanner", rand.Text(), false, true
}

// tenantURL resolves an Entra endpoint URL that defaults to a well-known
// path under the tenant's login.microsoftonline.com authority, but may be
// overridden (e.g. by an e2e test harness pointing it at a local fake, which
// is why http is accepted alongside https).
func (l *loader) tenantURL(name, tenantID, defaultPathSuffix string) string {
	raw, ok := l.resolve(name)
	if ok {
		v, err := parseBaseURL(name, raw, "http", "https")
		if err != nil {
			l.addErr(err)
			return ""
		}
		return v
	}
	if tenantID == "" {
		// No explicit value and no tenant to derive a default from; the
		// missing tenant id is already reported as its own error.
		return ""
	}
	return "https://login.microsoftonline.com/" + tenantID + defaultPathSuffix
}

func (l *loader) limits() Limits {
	return Limits{
		MaxMessageBytes:   l.int64Positive("S2G_MAX_MESSAGE_BYTES", 33554432),
		MaxJobs:           l.intPositive("S2G_MAX_JOBS", 32),
		MaxConcurrentJobs: l.intPositive("S2G_MAX_CONCURRENT_JOBS", 2),
	}
}

func (l *loader) logLevel() slog.Level {
	raw, ok := l.resolve("S2G_LOG_LEVEL")
	if !ok {
		return slog.LevelInfo
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		l.errorf("S2G_LOG_LEVEL: must be one of debug, info, warn, error, got %q", raw)
		return slog.LevelInfo
	}
}

func (l *loader) logFormat() string {
	raw, ok := l.resolve("S2G_LOG_FORMAT")
	if !ok {
		return "json"
	}
	v := strings.ToLower(strings.TrimSpace(raw))
	if v != "json" && v != "text" {
		l.errorf("S2G_LOG_FORMAT: must be \"json\" or \"text\", got %q", raw)
		return "json"
	}
	return v
}

// Profile looks up the sender profile for an SMTP envelope sender address.
// It normalizes envelopeSender first; ok is false for an implausible address
// or an address with no configured profile (the caller should reject the
// SMTP transaction in both cases). When no profiles are configured at all,
// DefaultProfile applies to every plausible sender.
func (c *Config) Profile(envelopeSender string) (Capabilities, bool) {
	n := NormalizeAddress(envelopeSender)
	if n == "" {
		return Capabilities{}, false
	}
	if len(c.Profiles) == 0 {
		return c.DefaultProfile, true
	}
	cp, ok := c.Profiles[n]
	return cp, ok
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

// Canonical normalizes addr and then applies the recipient alias map exactly
// once (alias -> canonical identity; alias chains are not followed). It
// returns "" for an implausible address.
func (c *Config) Canonical(addr string) string {
	n := NormalizeAddress(addr)
	if n == "" {
		return ""
	}
	if canon, ok := c.RecipientAliases[n]; ok {
		return canon
	}
	return n
}

// RecipientAllowed reports whether a canonical address may receive scans:
// true for every address when no domain allowlist is configured (only a
// legal configuration when no profile enables email), otherwise true iff the
// address's domain case-insensitively matches an entry in
// AllowedRecipientDomains exactly (no subdomain wildcards).
func (c *Config) RecipientAllowed(canonical string) bool {
	if len(c.AllowedRecipientDomains) == 0 {
		return true
	}
	at := strings.LastIndexByte(canonical, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(canonical[at+1:])
	for _, d := range c.AllowedRecipientDomains {
		if domain == d {
			return true
		}
	}
	return false
}

// LogValue returns a redacted summary of c suitable for slog: addresses,
// base URLs, profile names and their capability flags, limits and TTLs, and
// whether the client secret is set - but never the secret itself.
func (c *Config) LogValue() slog.Value {
	names := make([]string, 0, len(c.Profiles))
	for addr := range c.Profiles {
		names = append(names, addr)
	}
	sort.Strings(names)
	profiles := make([]string, 0, len(names))
	for _, addr := range names {
		cp := c.Profiles[addr]
		profiles = append(profiles, fmt.Sprintf("%s(email=%t,web=%t,ocr=%t)", addr, cp.Email, cp.Web, cp.OCR))
	}
	if len(profiles) == 0 {
		cp := c.DefaultProfile
		profiles = append(profiles, fmt.Sprintf("<any sender>(email=%t,web=%t,ocr=%t)", cp.Email, cp.Web, cp.OCR))
	}

	return slog.GroupValue(
		slog.String("http_addr", c.HTTPAddr),
		slog.String("smtp_addr", c.SMTPAddr),
		slog.String("smtp_auth", c.smtpAuthMode()),
		slog.String("public_base_url", c.PublicBaseURL),
		slog.String("temp_dir", c.TempDir),
		slog.String("log_level", c.LogLevel.String()),
		slog.String("log_format", c.LogFormat),
		slog.Any("profiles", profiles),
		slog.Int("recipient_aliases", len(c.RecipientAliases)),
		slog.Any("allowed_recipient_domains", c.AllowedRecipientDomains),
		slog.String("tenant_id", c.TenantID),
		slog.String("client_id", c.ClientID),
		slog.Bool("client_secret_set", c.ClientSecret != ""),
		slog.String("authority_url", c.AuthorityURL),
		slog.String("token_url", c.TokenURL),
		slog.String("graph_base_url", c.GraphBaseURL),
		slog.String("graph_scope", c.GraphScope),
		slog.String("graph_sender", c.GraphSender),
		slog.String("di_endpoint", c.DIEndpoint),
		slog.String("di_api_version", c.DIAPIVersion),
		slog.String("di_scope", c.DIScope),
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
