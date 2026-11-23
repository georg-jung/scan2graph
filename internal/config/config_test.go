package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/georg-jung/scan2graph/internal/jobs"
)

// testSMTPPassword is a fixture value, not a credential: it only ever
// travels through a fake getenv inside these tests.
const testSMTPPassword = "smtp-fixture-value"

// baseEnv returns an environment that Load accepts with all three features
// available. Individual tests mutate/delete keys.
func baseEnv() map[string]string {
	return map[string]string{
		"S2G_PUBLIC_BASE_URL":           "https://scan2graph.example.com",
		"S2G_GRAPH_SENDER":              "scanner@example.com",
		"S2G_ALLOWED_RECIPIENT_DOMAINS": "example.com",
		"S2G_DI_ENDPOINT":               "https://myres.cognitiveservices.azure.com",
		"S2G_ENTRA_TENANT_ID":           "00000000-0000-0000-0000-000000000000",
		"S2G_ENTRA_CLIENT_ID":           "11111111-1111-1111-1111-111111111111",
		"S2G_ENTRA_CLIENT_SECRET":       "TOTALLY-SECRET-VALUE",
	}
}

func fakeGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func mustLoad(t *testing.T, env map[string]string) *Config {
	t.Helper()
	c, err := Load(fakeGetenv(env))
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	return c
}

func wantLoadErr(t *testing.T, env map[string]string, substrs ...string) {
	t.Helper()
	_, err := Load(fakeGetenv(env))
	if err == nil {
		t.Fatalf("Load() succeeded, want error containing %q", substrs)
	}
	msg := err.Error()
	for _, s := range substrs {
		if !strings.Contains(msg, s) {
			t.Errorf("Load() error = %q, want it to contain %q", msg, s)
		}
	}
}

func TestLoadMinimalValidConfigAndDefaults(t *testing.T) {
	env := baseEnv()
	c := mustLoad(t, env)

	if c.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", c.HTTPAddr)
	}
	if c.SMTPAddr != ":2525" {
		t.Errorf("SMTPAddr = %q, want :2525", c.SMTPAddr)
	}
	if c.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", c.LogLevel)
	}
	if c.PublicBaseURL != "https://scan2graph.example.com" {
		t.Errorf("PublicBaseURL = %q", c.PublicBaseURL)
	}
	if got, want := c.AllowedRecipientDomains, []string{"example.com"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("AllowedRecipientDomains = %v, want %v", got, want)
	}
	if c.GraphSender != "scanner@example.com" {
		t.Errorf("GraphSender = %q", c.GraphSender)
	}
	if c.DIEndpoint != "https://myres.cognitiveservices.azure.com" {
		t.Errorf("DIEndpoint = %q", c.DIEndpoint)
	}
	wantAuthority := "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
	if c.AuthorityURL != wantAuthority {
		t.Errorf("AuthorityURL = %q, want %q", c.AuthorityURL, wantAuthority)
	}
	wantToken := "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"
	if c.TokenURL != wantToken {
		t.Errorf("TokenURL = %q, want %q", c.TokenURL, wantToken)
	}
	if c.GraphBaseURL != "https://graph.microsoft.com/v1.0" {
		t.Errorf("GraphBaseURL = %q", c.GraphBaseURL)
	}
	if c.JobTTL != 8*time.Hour {
		t.Errorf("JobTTL = %v, want 8h", c.JobTTL)
	}
	wantLimits := Limits{MaxMessageBytes: 33554432, MaxStoredBytes: 536870912}
	if c.Limits != wantLimits {
		t.Errorf("Limits = %+v, want %+v", c.Limits, wantLimits)
	}
}

func TestLoadPublicBaseURLValidation(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		env := baseEnv()
		env["S2G_PUBLIC_BASE_URL"] = "/just/a/path"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "absolute")
	})
	t.Run("bad scheme", func(t *testing.T) {
		env := baseEnv()
		env["S2G_PUBLIC_BASE_URL"] = "ftp://scan2graph.example.com"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "scheme")
	})
	t.Run("query string", func(t *testing.T) {
		env := baseEnv()
		env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/?x=1"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "query")
	})
	t.Run("fragment", func(t *testing.T) {
		env := baseEnv()
		env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/#frag"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "fragment")
	})
	// A path is the subpath prefix the appliance serves itself under, and
	// PathPrefix is where the rest of the appliance reads it rather than
	// parsing the URL again. Trailing slashes all go: one left behind would
	// make every link on the page start "//", which a browser reads as a host.
	t.Run("path becomes the prefix", func(t *testing.T) {
		for raw, want := range map[string]string{
			"https://scan2graph.example.com":          "",
			"https://scan2graph.example.com/":         "",
			"https://scan2graph.example.com//":        "",
			"https://nas.acme.office/scanner":         "/scanner",
			"https://nas.acme.office/scanner/":        "/scanner",
			"https://nas.acme.office/apps/scanner///": "/apps/scanner",
		} {
			env := baseEnv()
			env["S2G_PUBLIC_BASE_URL"] = raw
			c := mustLoad(t, env)
			if c.PathPrefix != want {
				t.Errorf("PathPrefix for %q = %q, want %q", raw, c.PathPrefix, want)
			}
			if c.PublicBaseURL != strings.TrimRight(raw, "/") {
				t.Errorf("PublicBaseURL for %q = %q, want the trailing slashes gone", raw, c.PublicBaseURL)
			}
		}
	})
	// A path that is not a plain subpath is refused rather than served. Each
	// of these once reached a route pattern or a cookie Path, where the
	// failure is a panic at the next start or a sign-in that can never
	// complete - and the wizard that repairs it would have panicked too.
	t.Run("only a plain subpath", func(t *testing.T) {
		for _, raw := range []string{
			"https://nas.acme.office//scanner",        // unclean: ServeMux panics on the pattern
			"https://nas.acme.office/apps/../scanner", // likewise
			"https://nas.acme.office/scanner/..",      // likewise
			"https://nas.acme.office/sca{nner",        // a pattern ServeMux reads as a bad wildcard
			"https://nas.acme.office/{x}",             // one it reads as a wildcard that matches anything
			"https://nas.acme.office/\\evil.example",  // "//evil.example" to a browser's URL parser
			"https://nas.acme.office/sc\u00e4nner",    // SetCookie drops the non-ASCII byte from a Path
			"https://nas.acme.office/sca%2Fnner",      // the route would be /sca/nner, which %2F never matches
		} {
			env := baseEnv()
			env["S2G_PUBLIC_BASE_URL"] = raw
			wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "plain subpath")
			// And the resolver the wizard mounts itself from says nothing
			// rather than something unusable: it serves the root and stays
			// available to fix the value that got here.
			if got := ResolveBaseURL(fakeGetenv(env)); got != "" {
				t.Errorf("ResolveBaseURL for %q = %q, want it refused", raw, got)
			}
		}
	})
}

func TestLoadEmailValidation(t *testing.T) {
	t.Run("invalid graph sender", func(t *testing.T) {
		env := baseEnv()
		env["S2G_GRAPH_SENDER"] = "not-an-address"
		wantLoadErr(t, env, "S2G_GRAPH_SENDER", "not a valid address")
	})
	t.Run("missing domain allowlist", func(t *testing.T) {
		env := baseEnv()
		delete(env, "S2G_ALLOWED_RECIPIENT_DOMAINS")
		wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "open mail relay")
	})
	t.Run("domain allowlist all invalid entries", func(t *testing.T) {
		env := baseEnv()
		env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = "not a domain,also@bad"
		wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "open mail relay")
	})
}

func TestLoadOCRValidation(t *testing.T) {
	t.Run("http not allowed", func(t *testing.T) {
		env := baseEnv()
		env["S2G_DI_ENDPOINT"] = "http://myres.cognitiveservices.azure.com"
		wantLoadErr(t, env, "S2G_DI_ENDPOINT", "scheme")
	})
	t.Run("trailing slash stripped", func(t *testing.T) {
		env := baseEnv()
		env["S2G_DI_ENDPOINT"] = "https://myres.cognitiveservices.azure.com/"
		c := mustLoad(t, env)
		if c.DIEndpoint != "https://myres.cognitiveservices.azure.com" {
			t.Errorf("DIEndpoint = %q, want no trailing slash", c.DIEndpoint)
		}
	})
}

func TestLoadIdentityValidation(t *testing.T) {
	for _, name := range []string{"S2G_ENTRA_TENANT_ID", "S2G_ENTRA_CLIENT_ID", "S2G_ENTRA_CLIENT_SECRET"} {
		t.Run("missing "+name, func(t *testing.T) {
			env := baseEnv()
			delete(env, name)
			wantLoadErr(t, env, name, "required")
		})
	}
	t.Run("all three missing lists all three", func(t *testing.T) {
		env := baseEnv()
		delete(env, "S2G_ENTRA_TENANT_ID")
		delete(env, "S2G_ENTRA_CLIENT_ID")
		delete(env, "S2G_ENTRA_CLIENT_SECRET")
		wantLoadErr(t, env, "S2G_ENTRA_TENANT_ID", "S2G_ENTRA_CLIENT_ID", "S2G_ENTRA_CLIENT_SECRET")
	})
	t.Run("explicit authority URL must be absolute http/https", func(t *testing.T) {
		env := baseEnv()
		env["S2G_ENTRA_AUTHORITY_URL"] = "not a url \x7f"
		wantLoadErr(t, env, "S2G_ENTRA_AUTHORITY_URL")
	})
	t.Run("explicit authority URL http allowed for e2e fakes", func(t *testing.T) {
		env := baseEnv()
		env["S2G_ENTRA_AUTHORITY_URL"] = "http://127.0.0.1:9999/fake-authority/"
		c := mustLoad(t, env)
		if c.AuthorityURL != "http://127.0.0.1:9999/fake-authority" {
			t.Errorf("AuthorityURL = %q", c.AuthorityURL)
		}
	})
	// The token endpoint follows the authority, so pointing at a test IdP
	// is one setting.
	t.Run("token URL is derived from the authority", func(t *testing.T) {
		env := baseEnv()
		env["S2G_ENTRA_AUTHORITY_URL"] = "http://127.0.0.1:9999/tenant/v2.0"
		if got := mustLoad(t, env).TokenURL; got != "http://127.0.0.1:9999/tenant/oauth2/v2.0/token" {
			t.Errorf("TokenURL = %q", got)
		}
	})
}

func TestLoadDurationValidation(t *testing.T) {
	t.Run("job ttl below one minute", func(t *testing.T) {
		env := baseEnv()
		env["S2G_JOB_TTL"] = "30s"
		wantLoadErr(t, env, "S2G_JOB_TTL", "at least")
	})
	t.Run("job ttl zero", func(t *testing.T) {
		env := baseEnv()
		env["S2G_JOB_TTL"] = "0s"
		wantLoadErr(t, env, "S2G_JOB_TTL")
	})
	t.Run("job ttl negative", func(t *testing.T) {
		env := baseEnv()
		env["S2G_JOB_TTL"] = "-5m"
		wantLoadErr(t, env, "S2G_JOB_TTL")
	})
	t.Run("job ttl unparsable", func(t *testing.T) {
		env := baseEnv()
		env["S2G_JOB_TTL"] = "not-a-duration"
		wantLoadErr(t, env, "S2G_JOB_TTL", "invalid duration")
	})
	t.Run("valid duration round trips", func(t *testing.T) {
		env := baseEnv()
		env["S2G_JOB_TTL"] = "2h"
		c := mustLoad(t, env)
		if c.JobTTL != 2*time.Hour {
			t.Errorf("JobTTL = %v", c.JobTTL)
		}
	})
}

func TestLoadLimitValidation(t *testing.T) {
	limitVars := []string{"S2G_MAX_MESSAGE_BYTES", "S2G_MAX_STORED_BYTES"}
	for _, name := range limitVars {
		t.Run(name+"=0", func(t *testing.T) {
			env := baseEnv()
			env[name] = "0"
			wantLoadErr(t, env, name, "> 0")
		})
		t.Run(name+"=negative", func(t *testing.T) {
			env := baseEnv()
			env[name] = "-3"
			wantLoadErr(t, env, name)
		})
		t.Run(name+"=not-a-number", func(t *testing.T) {
			env := baseEnv()
			env[name] = "abc"
			wantLoadErr(t, env, name, "invalid integer")
		})
	}
}

// A message the store could never make room for would be rejected on
// arrival, every time, so the pair is validated together rather than each
// value on its own.
func TestLoadRejectsBudgetSmallerThanTwoMessages(t *testing.T) {
	env := baseEnv()
	env["S2G_MAX_MESSAGE_BYTES"] = "2000"
	env["S2G_MAX_STORED_BYTES"] = "3999"
	wantLoadErr(t, env, "S2G_MAX_STORED_BYTES", "at least")
}

func TestNormalizeAddress(t *testing.T) {
	longLocal := strings.Repeat("a", 250)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lowercases", "Foo@BAR.com", "foo@bar.com"},
		{"angle brackets", "<a@b.example>", "a@b.example"},
		{"angle brackets with inner spaces", "< a@b.example >", "a@b.example"},
		{"surrounding spaces", "  a@b.example  ", "a@b.example"},
		{"missing at sign", "noatsign.example.com", ""},
		{"two at signs", "a@b@c.example", ""},
		{"empty local part", "@b.example", ""},
		{"empty domain", "a@", ""},
		{"domain without dot", "a@localhost", ""},
		{"internal space", "a b@example.com", ""},
		{"tab character", "a\tb@example.com", ""},
		{"control character", "a\x00b@example.com", ""},
		{"newline", "a\nb@example.com", ""},
		{"unicode lowercased", "ÜSER@ËXAMPLE.com", "üser@ëxample.com"},
		{"unicode already lower", "üser@ëxample.com", "üser@ëxample.com"},
		{"empty string", "", ""},
		{"only whitespace", "   ", ""},
		{"just an at sign", "@", ""},
		{"over length", longLocal + "@" + longLocal + longLocal + ".example.com", ""},
		{"exactly at boundary local domain", "a@b.example", "a@b.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeAddress(tc.in); got != tc.want {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRecipientAllowed(t *testing.T) {
	t.Run("empty allowlist allows everything", func(t *testing.T) {
		c := &Config{}
		if !c.RecipientAllowed("anyone@anywhere.example") {
			t.Errorf("RecipientAllowed with empty allowlist = false, want true")
		}
	})
	t.Run("exact domain match", func(t *testing.T) {
		c := &Config{AllowedRecipientDomains: []string{"example.com", "corp.example"}}
		if !c.RecipientAllowed("user@example.com") {
			t.Errorf("RecipientAllowed(user@example.com) = false, want true")
		}
	})
	t.Run("case insensitive", func(t *testing.T) {
		c := &Config{AllowedRecipientDomains: []string{"example.com"}}
		if !c.RecipientAllowed("user@EXAMPLE.com") {
			t.Errorf("RecipientAllowed(user@EXAMPLE.com) = false, want true")
		}
	})
	t.Run("domain not in list", func(t *testing.T) {
		c := &Config{AllowedRecipientDomains: []string{"example.com"}}
		if c.RecipientAllowed("user@other.example") {
			t.Errorf("RecipientAllowed(user@other.example) = true, want false")
		}
	})
	t.Run("no subdomain wildcard", func(t *testing.T) {
		c := &Config{AllowedRecipientDomains: []string{"example.com"}}
		if c.RecipientAllowed("user@sub.example.com") {
			t.Errorf("RecipientAllowed(user@sub.example.com) = true, want false (no subdomain wildcard)")
		}
	})
	t.Run("no at sign", func(t *testing.T) {
		c := &Config{AllowedRecipientDomains: []string{"example.com"}}
		if c.RecipientAllowed("garbage") {
			t.Errorf("RecipientAllowed(garbage) = true, want false")
		}
	})
}

func TestLoadAllowedRecipientDomainsParsing(t *testing.T) {
	env := baseEnv()
	env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = " Example.com , Corp.Example ,example.com"
	c := mustLoad(t, env)
	want := []string{"example.com", "corp.example"}
	if len(c.AllowedRecipientDomains) != len(want) {
		t.Fatalf("AllowedRecipientDomains = %v, want %v", c.AllowedRecipientDomains, want)
	}
	for i, d := range want {
		if c.AllowedRecipientDomains[i] != d {
			t.Errorf("AllowedRecipientDomains[%d] = %q, want %q", i, c.AllowedRecipientDomains[i], d)
		}
	}
}

func TestLogValueAndStringNeverLeakSecret(t *testing.T) {
	const secret = "TOTALLY-SECRET-VALUE"
	env := baseEnv()
	env["S2G_ENTRA_CLIENT_SECRET"] = secret
	c := mustLoad(t, env)

	if strings.Contains(c.String(), secret) {
		t.Errorf("String() leaks the client secret: %s", c.String())
	}
	if strings.Contains(fmt.Sprintf("%v", c), secret) {
		t.Errorf("%%v leaks the client secret")
	}
	if strings.Contains(fmt.Sprintf("%+v", c), secret) {
		t.Errorf("%%+v leaks the client secret")
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("effective config", "config", c)
	if strings.Contains(buf.String(), secret) {
		t.Errorf("slog output leaks the client secret: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "client_secret_set") {
		t.Errorf("slog output missing client_secret_set marker: %s", buf.String())
	}
	if c.ClientSecret != secret {
		t.Fatalf("sanity check failed: ClientSecret = %q, want %q", c.ClientSecret, secret)
	}
}

func TestLoadLogLevel(t *testing.T) {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"Error": slog.LevelError,
	}
	for raw, want := range levels {
		t.Run("level "+raw, func(t *testing.T) {
			env := baseEnv()
			env["S2G_LOG_LEVEL"] = raw
			c := mustLoad(t, env)
			if c.LogLevel != want {
				t.Errorf("LogLevel = %v, want %v", c.LogLevel, want)
			}
		})
	}
	t.Run("invalid level", func(t *testing.T) {
		env := baseEnv()
		env["S2G_LOG_LEVEL"] = "verbose"
		wantLoadErr(t, env, "S2G_LOG_LEVEL")
	})
}

func TestLoadGraphBaseURLOverride(t *testing.T) {
	env := baseEnv()
	env["S2G_GRAPH_BASE_URL"] = "http://127.0.0.1:9999/fake-graph/"
	c := mustLoad(t, env)
	if c.GraphBaseURL != "http://127.0.0.1:9999/fake-graph" {
		t.Errorf("GraphBaseURL = %q", c.GraphBaseURL)
	}
}

func TestLoadBaseURLMissingHostOrUnparsable(t *testing.T) {
	t.Run("missing host", func(t *testing.T) {
		env := baseEnv()
		env["S2G_PUBLIC_BASE_URL"] = "https:///no-host-here"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "host")
	})
	t.Run("unparsable", func(t *testing.T) {
		env := baseEnv()
		env["S2G_PUBLIC_BASE_URL"] = "http://[::1"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "invalid URL")
	})
}

func TestValidDomainLength(t *testing.T) {
	env := baseEnv()
	env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = strings.Repeat("a", 250) + ".com"
	wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "not a valid domain")
}

func TestLoadSMTPAuthDefaultsToEphemeralPassword(t *testing.T) {
	env := baseEnv()
	c := mustLoad(t, env)

	if !c.SMTPPasswordGenerated {
		t.Errorf("SMTPPasswordGenerated = false, want true")
	}
	if c.SMTPAllowAnonymous {
		t.Errorf("SMTPAllowAnonymous = true, want false")
	}
	if c.SMTPPassword == "" {
		t.Fatal("SMTPPassword is empty, want a generated password")
	}
	if len(c.SMTPPassword) < 20 {
		t.Errorf("generated SMTPPassword = %q, want at least 20 chars (128 bits of base32)", c.SMTPPassword)
	}
	for _, r := range c.SMTPPassword {
		if !((r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7')) {
			t.Errorf("generated SMTPPassword %q contains %q, want RFC 4648 base32 alphabet only", c.SMTPPassword, r)
			break
		}
	}

	// Two independent Loads must not reuse the same "random" password.
	c2 := mustLoad(t, baseEnv())
	if c.SMTPPassword == c2.SMTPPassword {
		t.Errorf("two Load() calls generated the same password: %q", c.SMTPPassword)
	}
}

func TestLoadSMTPAuthConfigured(t *testing.T) {
	env := baseEnv()
	env["S2G_SMTP_PASSWORD"] = testSMTPPassword
	c := mustLoad(t, env)
	if c.SMTPPassword != testSMTPPassword {
		t.Errorf("SMTPPassword = %q", c.SMTPPassword)
	}
	if c.SMTPPasswordGenerated {
		t.Errorf("SMTPPasswordGenerated = true, want false")
	}
	if c.SMTPAllowAnonymous {
		t.Errorf("SMTPAllowAnonymous = true, want false")
	}
}

func TestLoadSMTPAuthAnonymous(t *testing.T) {
	t.Run("allow anonymous alone", func(t *testing.T) {
		env := baseEnv()
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "true"
		c := mustLoad(t, env)
		if !c.SMTPAllowAnonymous {
			t.Errorf("SMTPAllowAnonymous = false, want true")
		}
		if c.SMTPPassword != "" {
			t.Errorf("SMTPPassword = %q, want empty when anonymous", c.SMTPPassword)
		}
		if c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = true, want false when anonymous")
		}
	})
	t.Run("explicit false behaves like unset", func(t *testing.T) {
		env := baseEnv()
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "false"
		c := mustLoad(t, env)
		if !c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = false, want true (ephemeral path)")
		}
	})
	t.Run("contradictory with password", func(t *testing.T) {
		env := baseEnv()
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "true"
		env["S2G_SMTP_PASSWORD"] = testSMTPPassword
		wantLoadErr(t, env, "S2G_SMTP_ALLOW_ANONYMOUS", "S2G_SMTP_PASSWORD")
	})
	t.Run("invalid boolean", func(t *testing.T) {
		env := baseEnv()
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "maybe"
		wantLoadErr(t, env, "S2G_SMTP_ALLOW_ANONYMOUS", "invalid boolean")
	})
}

func TestLogValueSMTPAuthModes(t *testing.T) {
	for _, tc := range []struct{ mode, key, val string }{
		{"ephemeral", "", ""},
		{"configured", "S2G_SMTP_PASSWORD", testSMTPPassword},
		{"disabled", "S2G_SMTP_ALLOW_ANONYMOUS", "true"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			env := baseEnv()
			if tc.key != "" {
				env[tc.key] = tc.val
			}
			c := mustLoad(t, env)
			if got := c.smtpAuthMode(); got != tc.mode {
				t.Errorf("smtpAuthMode() = %q, want %q", got, tc.mode)
			}
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("effective config", "config", c)
			for _, out := range []string{c.String(), fmt.Sprintf("%v", c), buf.String()} {
				if c.SMTPPassword != "" && strings.Contains(out, c.SMTPPassword) {
					t.Errorf("output leaks the SMTP password: %s", out)
				}
			}
			if !strings.Contains(buf.String(), `"smtp_auth":"`+tc.mode+`"`) {
				t.Errorf("slog output missing smtp_auth=%s: %s", tc.mode, buf.String())
			}
		})
	}
}

func TestLoadGraphSenderNormalizesAddress(t *testing.T) {
	env := baseEnv()
	env["S2G_GRAPH_SENDER"] = "Scanner@Example.com"
	c := mustLoad(t, env)
	if c.GraphSender != "scanner@example.com" {
		t.Errorf("GraphSender = %q, want normalized address", c.GraphSender)
	}
}

func TestLoadRejectsMalformedRecipientDomains(t *testing.T) {
	for _, domain := range []string{"*.example.com", "https://example.com", "example.com/x", ".example.com", "example..com"} {
		t.Run(domain, func(t *testing.T) {
			env := baseEnv()
			env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = domain
			wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS")
		})
	}
}

func TestLoadAvailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		without []string
		want    jobs.Capabilities
	}{
		{"everything configured", nil, jobs.Capabilities{Email: true, Web: true, OCR: true}},
		{"no graph sender", []string{"S2G_GRAPH_SENDER"}, jobs.Capabilities{Web: true, OCR: true}},
		{"no base URL", []string{"S2G_PUBLIC_BASE_URL"}, jobs.Capabilities{Email: true, OCR: true}},
		{"no document intelligence", []string{"S2G_DI_ENDPOINT"}, jobs.Capabilities{Email: true, Web: true}},
		{"web only", []string{"S2G_GRAPH_SENDER", "S2G_DI_ENDPOINT"}, jobs.Capabilities{Web: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := baseEnv()
			for _, name := range tc.without {
				delete(env, name)
			}
			if got := mustLoad(t, env).Available; got != tc.want {
				t.Errorf("Available = %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("no delivery path at all is an error", func(t *testing.T) {
		env := baseEnv()
		delete(env, "S2G_GRAPH_SENDER")
		delete(env, "S2G_PUBLIC_BASE_URL")
		wantLoadErr(t, env, "no way to deliver a scan")
	})
}

func TestFeatures(t *testing.T) {
	all := jobs.Capabilities{Email: true, Web: true, OCR: true}
	webOCR := &Config{Available: jobs.Capabilities{Web: true, OCR: true}}
	full := &Config{Available: all}
	for _, tc := range []struct {
		c      *Config
		sender string
		want   jobs.Capabilities
		err    error
	}{
		{full, "scan@x.local", all, nil},
		{full, "Copier@Printer.Example", all, nil},
		{full, "<scan@x.local>", all, nil},
		{full, "web@x.local", jobs.Capabilities{Web: true}, nil},
		{full, "WEB@x.local", jobs.Capabilities{Web: true}, nil},
		{full, "web-ocr@x.local", jobs.Capabilities{Web: true, OCR: true}, nil},
		{full, "scan.email+ocr@x.local", jobs.Capabilities{Email: true, OCR: true}, nil},
		{full, "email_web_ocr@x.local", all, nil},
		{full, "ocr-web-ocr@x.local", jobs.Capabilities{Web: true, OCR: true}, nil},
		{full, " < web@x.local > ", jobs.Capabilities{Web: true}, nil},
		// Only whole words count, so these name nothing and get everything.
		{full, "webcam@x.local", all, nil},
		{full, "emails@x.local", all, nil},
		{full, "web2@x.local", all, nil},
		// The domain is not the local part.
		{full, "scan@web.ocr.local", all, nil},
		// Non-ASCII separates, and never lowercases into a feature word:
		// U+0130 lowercases to "i".
		{full, "emaİl@x.local", all, nil},
		{full, "webéocr@x.local", jobs.Capabilities{Web: true, OCR: true}, nil},
		{full, "ocr@x.local", jobs.Capabilities{}, errNoDelivery},
		{full, "ocr-scan@x.local", jobs.Capabilities{}, errNoDelivery},
		{webOCR, "email@x.local", jobs.Capabilities{}, errUnavailable},
		{webOCR, "web-email@x.local", jobs.Capabilities{}, errUnavailable},
		{webOCR, "web@x.local", jobs.Capabilities{Web: true}, nil},
		{webOCR, "scan@x.local", webOCR.Available, nil},
		{&Config{Available: jobs.Capabilities{Web: true}}, "web-ocr@x.local", jobs.Capabilities{}, errUnavailable},
		{full, "", jobs.Capabilities{}, errBadSender},
		{full, "not-an-address", jobs.Capabilities{}, errBadSender},
		{full, "web@a@x.local", jobs.Capabilities{}, errBadSender},
	} {
		got, err := tc.c.Features(tc.sender)
		if got != tc.want || err != tc.err {
			t.Errorf("Features(%q) with %+v = %+v, %v; want %+v, %v", tc.sender, tc.c.Available, got, err, tc.want, tc.err)
		}
	}
}

// FuzzFeatures pins what the rule promises for any envelope sender: it never
// grants a feature that is not available, an accepted scan always has a
// delivery, and a refusal is one of the three static replies.
func FuzzFeatures(f *testing.F) {
	for _, s := range []string{"scan@x.local", "web-ocr@x.local", "ocr@x.local", "EMAIL@X.LOCAL", "<web@x.local>", "emaİl@x.local", "@", ""} {
		f.Add(s, true, true, true)
	}
	f.Fuzz(func(t *testing.T, sender string, email, web, ocr bool) {
		c := &Config{Available: jobs.Capabilities{Email: email, Web: web, OCR: ocr}}
		got, err := c.Features(sender)
		if err != nil {
			if err != errBadSender && err != errNoDelivery && err != errUnavailable {
				t.Fatalf("Features(%q) = unexpected error %v", sender, err)
			}
			if got != (jobs.Capabilities{}) {
				t.Fatalf("Features(%q) refused but granted %+v", sender, got)
			}
			return
		}
		if NormalizeAddress(sender) == "" {
			t.Fatalf("Features(%q) accepted an address NormalizeAddress rejects", sender)
		}
		if got.Email && !email || got.Web && !web || got.OCR && !ocr {
			t.Fatalf("Features(%q) = %+v, beyond available %+v", sender, got, c.Available)
		}
		if (email || web) && !got.Email && !got.Web {
			t.Fatalf("Features(%q) = %+v accepted without a delivery", sender, got)
		}
	})
}
