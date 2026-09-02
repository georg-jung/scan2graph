package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testSMTPPassword is a fixture value, not a credential: it only ever
// travels through a fake getenv inside these tests.
const testSMTPPassword = "smtp-fixture-value"

// baseEnv returns a minimal environment that Load accepts: one profile with
// all three capabilities enabled, plus every variable that combination
// requires. Individual tests clone it and mutate/delete keys.
func baseEnv() map[string]string {
	return map[string]string{
		"S2G_PROFILES":                  `{"scan@scanner.local":{"email":true,"web":true,"ocr":true}}`,
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

func clone(m map[string]string) map[string]string { return maps.Clone(m) }

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
	if c.TempDir != os.TempDir() {
		t.Errorf("TempDir = %q, want %q", c.TempDir, os.TempDir())
	}
	if c.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", c.LogLevel)
	}
	if c.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want json", c.LogFormat)
	}
	if c.UITitle != "scan2graph" {
		t.Errorf("UITitle = %q, want scan2graph", c.UITitle)
	}
	// A blank title would leave the header with nothing to click.
	for _, blank := range []string{"", "   "} {
		env := clone(baseEnv())
		env["S2G_UI_TITLE"] = blank
		if got := mustLoad(t, env).UITitle; got != "scan2graph" {
			t.Errorf("UITitle for %q = %q, want the default", blank, got)
		}
	}
	if c.PublicBaseURL != "https://scan2graph.example.com" {
		t.Errorf("PublicBaseURL = %q", c.PublicBaseURL)
	}
	if len(c.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1", len(c.Profiles))
	}
	if cp, ok := c.Profiles["scan@scanner.local"]; !ok || !cp.Email || !cp.Web || !cp.OCR {
		t.Errorf("Profiles[scan@scanner.local] = %+v, ok=%v, want all true", cp, ok)
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
	if c.DIAPIVersion != "2024-11-30" {
		t.Errorf("DIAPIVersion = %q", c.DIAPIVersion)
	}
	if c.DIScope != "https://cognitiveservices.azure.com/.default" {
		t.Errorf("DIScope = %q", c.DIScope)
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
	if c.GraphScope != "https://graph.microsoft.com/.default" {
		t.Errorf("GraphScope = %q", c.GraphScope)
	}
	if c.JobTTL != 8*time.Hour {
		t.Errorf("JobTTL = %v, want 8h", c.JobTTL)
	}
	wantLimits := Limits{
		MaxMessageBytes:   33554432,
		MaxJobs:           32,
		MaxConcurrentJobs: 2,
	}
	if c.Limits != wantLimits {
		t.Errorf("Limits = %+v, want %+v", c.Limits, wantLimits)
	}
	if cp, ok := c.Profile("Scan@Scanner.Local"); !ok || !cp.Web {
		t.Errorf("Profile(mixed-case sender) = %+v, ok=%v, want a match", cp, ok)
	}
	if _, ok := c.Profile("unknown@scanner.local"); ok {
		t.Errorf("Profile(unknown sender) matched, want no match")
	}
}

func TestLoadPublicBaseURLValidation(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_PUBLIC_BASE_URL")
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "required")
	})
	t.Run("relative", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "/just/a/path"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "absolute")
	})
	t.Run("bad scheme", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "ftp://scan2graph.example.com"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "scheme")
	})
	t.Run("query string", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/?x=1"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "query")
	})
	t.Run("fragment", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/#frag"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "fragment")
	})
	t.Run("path", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/scans"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "root of a host")
	})
	t.Run("trailing slash stripped", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/"
		c := mustLoad(t, env)
		if c.PublicBaseURL != "https://scan2graph.example.com" {
			t.Errorf("PublicBaseURL = %q, want no trailing slash", c.PublicBaseURL)
		}
	})
	t.Run("not required without web profile", func(t *testing.T) {
		env := map[string]string{
			"S2G_PROFILES":                  `{"scan-email@scanner.local":{"email":true}}`,
			"S2G_GRAPH_SENDER":              "scanner@example.com",
			"S2G_ALLOWED_RECIPIENT_DOMAINS": "example.com",
			"S2G_ENTRA_TENANT_ID":           "tenant",
			"S2G_ENTRA_CLIENT_ID":           "client",
			"S2G_ENTRA_CLIENT_SECRET":       "secret",
		}
		c := mustLoad(t, env)
		if c.PublicBaseURL != "" {
			t.Errorf("PublicBaseURL = %q, want empty", c.PublicBaseURL)
		}
	})
}

func TestLoadEmailValidation(t *testing.T) {
	t.Run("missing graph sender", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_GRAPH_SENDER")
		wantLoadErr(t, env, "S2G_GRAPH_SENDER", "required")
	})
	t.Run("invalid graph sender", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_GRAPH_SENDER"] = "not-an-address"
		wantLoadErr(t, env, "S2G_GRAPH_SENDER", "not a valid address")
	})
	t.Run("missing domain allowlist", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_ALLOWED_RECIPIENT_DOMAINS")
		wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "open mail relay")
	})
	t.Run("domain allowlist all invalid entries", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = "not a domain,also@bad"
		wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "open mail relay")
	})
	t.Run("not required without email profile", func(t *testing.T) {
		env := map[string]string{
			"S2G_PROFILES":            `{"scan-web@scanner.local":{"web":true}}`,
			"S2G_PUBLIC_BASE_URL":     "https://scan2graph.example.com",
			"S2G_ENTRA_TENANT_ID":     "tenant",
			"S2G_ENTRA_CLIENT_ID":     "client",
			"S2G_ENTRA_CLIENT_SECRET": "secret",
		}
		c := mustLoad(t, env)
		if c.GraphSender != "" {
			t.Errorf("GraphSender = %q, want empty", c.GraphSender)
		}
		if len(c.AllowedRecipientDomains) != 0 {
			t.Errorf("AllowedRecipientDomains = %v, want empty", c.AllowedRecipientDomains)
		}
	})
}

func TestLoadOCRValidation(t *testing.T) {
	t.Run("missing DI endpoint", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_DI_ENDPOINT")
		wantLoadErr(t, env, "S2G_DI_ENDPOINT", "required")
	})
	t.Run("http not allowed", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_DI_ENDPOINT"] = "http://myres.cognitiveservices.azure.com"
		wantLoadErr(t, env, "S2G_DI_ENDPOINT", "scheme")
	})
	t.Run("trailing slash stripped", func(t *testing.T) {
		env := clone(baseEnv())
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
			env := clone(baseEnv())
			delete(env, name)
			wantLoadErr(t, env, name, "required")
		})
	}
	t.Run("all three missing lists all three", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_ENTRA_TENANT_ID")
		delete(env, "S2G_ENTRA_CLIENT_ID")
		delete(env, "S2G_ENTRA_CLIENT_SECRET")
		wantLoadErr(t, env, "S2G_ENTRA_TENANT_ID", "S2G_ENTRA_CLIENT_ID", "S2G_ENTRA_CLIENT_SECRET")
	})
	t.Run("explicit authority URL must be absolute http/https", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_ENTRA_AUTHORITY_URL"] = "not a url \x7f"
		wantLoadErr(t, env, "S2G_ENTRA_AUTHORITY_URL")
	})
	t.Run("explicit authority URL http allowed for e2e fakes", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_ENTRA_AUTHORITY_URL"] = "http://127.0.0.1:9999/fake-authority/"
		c := mustLoad(t, env)
		if c.AuthorityURL != "http://127.0.0.1:9999/fake-authority" {
			t.Errorf("AuthorityURL = %q", c.AuthorityURL)
		}
	})
	t.Run("explicit token URL bad scheme", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_ENTRA_TOKEN_URL"] = "ftp://login.microsoftonline.com/tenant/token"
		wantLoadErr(t, env, "S2G_ENTRA_TOKEN_URL", "scheme")
	})
}

func TestLoadDurationValidation(t *testing.T) {
	t.Run("job ttl below one minute", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_JOB_TTL"] = "30s"
		wantLoadErr(t, env, "S2G_JOB_TTL", "at least")
	})
	t.Run("job ttl zero", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_JOB_TTL"] = "0s"
		wantLoadErr(t, env, "S2G_JOB_TTL")
	})
	t.Run("job ttl negative", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_JOB_TTL"] = "-5m"
		wantLoadErr(t, env, "S2G_JOB_TTL")
	})
	t.Run("job ttl unparsable", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_JOB_TTL"] = "not-a-duration"
		wantLoadErr(t, env, "S2G_JOB_TTL", "invalid duration")
	})
	t.Run("valid duration round trips", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_JOB_TTL"] = "2h"
		c := mustLoad(t, env)
		if c.JobTTL != 2*time.Hour {
			t.Errorf("JobTTL = %v", c.JobTTL)
		}
	})
}

func TestLoadLimitValidation(t *testing.T) {
	limitVars := []string{"S2G_MAX_MESSAGE_BYTES", "S2G_MAX_JOBS", "S2G_MAX_CONCURRENT_JOBS"}
	for _, name := range limitVars {
		t.Run(name+"=0", func(t *testing.T) {
			env := clone(baseEnv())
			env[name] = "0"
			wantLoadErr(t, env, name, "> 0")
		})
		t.Run(name+"=negative", func(t *testing.T) {
			env := clone(baseEnv())
			env[name] = "-3"
			wantLoadErr(t, env, name)
		})
		t.Run(name+"=not-a-number", func(t *testing.T) {
			env := clone(baseEnv())
			env[name] = "abc"
			wantLoadErr(t, env, name, "invalid integer")
		})
	}
}

func TestLoadProfilesValidation(t *testing.T) {
	t.Run("malformed json", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{not valid json`
		wantLoadErr(t, env, "S2G_PROFILES", "invalid JSON")
	})
	t.Run("unknown field rejected", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{"scan@scanner.local":{"email":true,"ocr2":true}}`
		wantLoadErr(t, env, "S2G_PROFILES", "unknown field")
	})
	t.Run("invalid key", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{"not-an-address":{"email":true}}`
		wantLoadErr(t, env, "S2G_PROFILES", "not a valid address")
	})
	t.Run("all capabilities false", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{"scan@scanner.local":{"email":false,"web":false,"ocr":false}}`
		wantLoadErr(t, env, "S2G_PROFILES", "no capability enabled")
	})
	t.Run("duplicate keys after normalization", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{"Scan@Scanner.Local":{"email":true},"scan@scanner.local":{"web":true}}`
		wantLoadErr(t, env, "S2G_PROFILES", "already used by another profile key")
	})
	t.Run("multiple distinct profiles", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{
			"scan-web@scanner.local": {"web": true},
			"scan-email-ocr@scanner.local": {"email": true, "ocr": true}
		}`
		c := mustLoad(t, env)
		if len(c.Profiles) != 2 {
			t.Fatalf("len(Profiles) = %d, want 2", len(c.Profiles))
		}
	})
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
	env := clone(baseEnv())
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

func TestLoadFileIndirection(t *testing.T) {
	t.Run("client secret from file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "secret")
		if err := os.WriteFile(p, []byte("file-secret-value\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := clone(baseEnv())
		delete(env, "S2G_ENTRA_CLIENT_SECRET")
		env["S2G_ENTRA_CLIENT_SECRET_FILE"] = p
		c := mustLoad(t, env)
		if c.ClientSecret != "file-secret-value" {
			t.Errorf("ClientSecret = %q, want %q", c.ClientSecret, "file-secret-value")
		}
	})

	t.Run("both var and file set is an error and does not leak either value", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "secret")
		if err := os.WriteFile(p, []byte("file-secret-value"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := clone(baseEnv())
		env["S2G_ENTRA_CLIENT_SECRET"] = "env-secret-value"
		env["S2G_ENTRA_CLIENT_SECRET_FILE"] = p
		_, err := Load(fakeGetenv(env))
		if err == nil {
			t.Fatal("Load() succeeded, want error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "S2G_ENTRA_CLIENT_SECRET") {
			t.Errorf("error %q does not name the variable", msg)
		}
		if strings.Contains(msg, "env-secret-value") || strings.Contains(msg, "file-secret-value") {
			t.Errorf("error %q leaks a secret value", msg)
		}
	})

	t.Run("file not found reports path and OS error, no panic", func(t *testing.T) {
		env := clone(baseEnv())
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		delete(env, "S2G_ENTRA_CLIENT_SECRET")
		env["S2G_ENTRA_CLIENT_SECRET_FILE"] = missing
		_, err := Load(fakeGetenv(env))
		if err == nil {
			t.Fatal("Load() succeeded, want error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "S2G_ENTRA_CLIENT_SECRET_FILE") {
			t.Errorf("error %q does not name the _FILE variable", msg)
		}
		if !strings.Contains(msg, missing) {
			t.Errorf("error %q does not mention the path", msg)
		}
	})

	t.Run("profiles from file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "profiles.json")
		content := `{"scan@scanner.local":{"email":true,"web":true,"ocr":true}}` + "\n  \n"
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		env := clone(baseEnv())
		delete(env, "S2G_PROFILES")
		env["S2G_PROFILES_FILE"] = p
		c := mustLoad(t, env)
		if len(c.Profiles) != 1 {
			t.Fatalf("len(Profiles) = %d, want 1", len(c.Profiles))
		}
	})

	// A mount that failed to populate is the failure this refuses, and
	// profiles are the setting where fail-open is worst: reading nothing as
	// "no profiles" would accept every sender and turn each capability on
	// from whatever the rest of the configuration happens to enable, so a
	// profile that could not mail suddenly can.
	t.Run("an empty profiles file is refused, not read as no profiles", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "profiles.json")
		if err := os.WriteFile(p, []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := clone(baseEnv())
		delete(env, "S2G_PROFILES")
		env["S2G_PROFILES_FILE"] = p
		wantLoadErr(t, env, "S2G_PROFILES", "invalid JSON")
	})

	t.Run("both var and file set for a plain string variable", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "addr")
		if err := os.WriteFile(p, []byte(":9090"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := clone(baseEnv())
		env["S2G_HTTP_ADDR"] = ":8080"
		env["S2G_HTTP_ADDR_FILE"] = p
		wantLoadErr(t, env, "S2G_HTTP_ADDR", "S2G_HTTP_ADDR_FILE")
	})

	// Resolve is that same lookup for a single setting, exported for the
	// setup wizard: it reads where to listen and which URL to print before
	// there is a *Config to read either from. What is new next to the rest of
	// this test is the wrapper itself: on anything Load would refuse, it
	// swallows the error and returns "" rather than surfacing it - there is
	// no *Config to attach one to yet.
	t.Run("Resolve swallows what Load would refuse", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "addr")
		if err := os.WriteFile(p, []byte(":9090"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := map[string]string{"S2G_HTTP_ADDR": ":8080", "S2G_HTTP_ADDR_FILE": p} // both spellings: Load refuses
		if got := Resolve(fakeGetenv(env), "S2G_HTTP_ADDR"); got != "" {
			t.Errorf("Resolve with both spellings set = %q, want \"\" so the caller's default wins", got)
		}
	})

	// ResolveRootBaseURL is the same lookup plus the rules Load applies to a
	// public base URL, for the one caller that turns the value into a link
	// the operator is told to open. The URL rules themselves are
	// TestLoadPublicBaseURLValidation's and TestSetupURL's job; what is new
	// here is that the file indirection still applies to a URL-shaped value.
	t.Run("ResolveRootBaseURL follows the file indirection", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "base-url")
		if err := os.WriteFile(p, []byte("https://scan2graph.example.com/\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := map[string]string{"S2G_PUBLIC_BASE_URL_FILE": p}
		if got := ResolveRootBaseURL(fakeGetenv(env), "S2G_PUBLIC_BASE_URL"); got != "https://scan2graph.example.com" {
			t.Errorf("ResolveRootBaseURL = %q, want the file's URL without its trailing slash", got)
		}
	})
}

func TestLogValueAndStringNeverLeakSecret(t *testing.T) {
	const secret = "TOTALLY-SECRET-VALUE"
	env := clone(baseEnv())
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

func TestLoadLogLevelAndFormat(t *testing.T) {
	levels := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"INFO":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"Error":   slog.LevelError,
	}
	for raw, want := range levels {
		t.Run("level "+raw, func(t *testing.T) {
			env := clone(baseEnv())
			env["S2G_LOG_LEVEL"] = raw
			c := mustLoad(t, env)
			if c.LogLevel != want {
				t.Errorf("LogLevel = %v, want %v", c.LogLevel, want)
			}
		})
	}
	t.Run("invalid level", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_LOG_LEVEL"] = "verbose"
		wantLoadErr(t, env, "S2G_LOG_LEVEL")
	})

	t.Run("format text", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_LOG_FORMAT"] = "TEXT"
		c := mustLoad(t, env)
		if c.LogFormat != "text" {
			t.Errorf("LogFormat = %q, want text", c.LogFormat)
		}
	})
	t.Run("invalid format", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_LOG_FORMAT"] = "xml"
		wantLoadErr(t, env, "S2G_LOG_FORMAT")
	})
}

func TestLoadGraphBaseURLOverride(t *testing.T) {
	env := clone(baseEnv())
	env["S2G_GRAPH_BASE_URL"] = "http://127.0.0.1:9999/fake-graph/"
	c := mustLoad(t, env)
	if c.GraphBaseURL != "http://127.0.0.1:9999/fake-graph" {
		t.Errorf("GraphBaseURL = %q", c.GraphBaseURL)
	}
}

func TestLoadBaseURLMissingHostOrUnparsable(t *testing.T) {
	t.Run("missing host", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "https:///no-host-here"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "host")
	})
	t.Run("unparsable", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PUBLIC_BASE_URL"] = "http://[::1"
		wantLoadErr(t, env, "S2G_PUBLIC_BASE_URL", "invalid URL")
	})
}

func TestProfileRejectsImplausibleSender(t *testing.T) {
	c := mustLoad(t, baseEnv())
	if _, ok := c.Profile("not-an-address"); ok {
		t.Errorf("Profile(not-an-address) matched, want no match")
	}
}

func TestValidDomainLength(t *testing.T) {
	env := clone(baseEnv())
	env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = strings.Repeat("a", 250) + ".com"
	wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "not a valid domain")
}

func TestLoadSMTPAuthDefaultsToEphemeralPassword(t *testing.T) {
	env := clone(baseEnv())
	c := mustLoad(t, env)

	if !c.SMTPPasswordGenerated {
		t.Errorf("SMTPPasswordGenerated = false, want true")
	}
	if c.SMTPAllowAnonymous {
		t.Errorf("SMTPAllowAnonymous = true, want false")
	}
	if c.SMTPUsername != "scanner" {
		t.Errorf("SMTPUsername = %q, want scanner", c.SMTPUsername)
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
	c2 := mustLoad(t, clone(baseEnv()))
	if c.SMTPPassword == c2.SMTPPassword {
		t.Errorf("two Load() calls generated the same password: %q", c.SMTPPassword)
	}
}

func TestLoadSMTPAuthConfigured(t *testing.T) {
	t.Run("password only, username defaults to scanner", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_PASSWORD"] = testSMTPPassword
		c := mustLoad(t, env)
		if c.SMTPUsername != "scanner" {
			t.Errorf("SMTPUsername = %q, want scanner", c.SMTPUsername)
		}
		if c.SMTPPassword != testSMTPPassword {
			t.Errorf("SMTPPassword = %q", c.SMTPPassword)
		}
		if c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = true, want false")
		}
		if c.SMTPAllowAnonymous {
			t.Errorf("SMTPAllowAnonymous = true, want false")
		}
	})

	t.Run("username and password both set", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_USERNAME"] = "front-desk-scanner"
		env["S2G_SMTP_PASSWORD"] = testSMTPPassword
		c := mustLoad(t, env)
		if c.SMTPUsername != "front-desk-scanner" {
			t.Errorf("SMTPUsername = %q", c.SMTPUsername)
		}
		if c.SMTPPassword != testSMTPPassword {
			t.Errorf("SMTPPassword = %q", c.SMTPPassword)
		}
		if c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = true, want false")
		}
	})

	t.Run("username without password is an error", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_USERNAME"] = "front-desk-scanner"
		wantLoadErr(t, env, "S2G_SMTP_USERNAME", "S2G_SMTP_PASSWORD", "S2G_SMTP_ALLOW_ANONYMOUS")
	})

	t.Run("password via file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "smtp-password")
		if err := os.WriteFile(p, []byte("file-smtp-pass\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := clone(baseEnv())
		env["S2G_SMTP_PASSWORD_FILE"] = p
		c := mustLoad(t, env)
		if c.SMTPPassword != "file-smtp-pass" {
			t.Errorf("SMTPPassword = %q, want file-smtp-pass", c.SMTPPassword)
		}
		if c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = true, want false")
		}
	})
}

func TestLoadSMTPAuthAnonymous(t *testing.T) {
	t.Run("allow anonymous alone", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "true"
		c := mustLoad(t, env)
		if !c.SMTPAllowAnonymous {
			t.Errorf("SMTPAllowAnonymous = false, want true")
		}
		if c.SMTPUsername != "" {
			t.Errorf("SMTPUsername = %q, want empty when anonymous", c.SMTPUsername)
		}
		if c.SMTPPassword != "" {
			t.Errorf("SMTPPassword = %q, want empty when anonymous", c.SMTPPassword)
		}
		if c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = true, want false when anonymous")
		}
	})
	t.Run("explicit false behaves like unset", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "false"
		c := mustLoad(t, env)
		if !c.SMTPPasswordGenerated {
			t.Errorf("SMTPPasswordGenerated = false, want true (ephemeral path)")
		}
	})
	t.Run("contradictory with username", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "true"
		env["S2G_SMTP_USERNAME"] = "front-desk-scanner"
		wantLoadErr(t, env, "S2G_SMTP_ALLOW_ANONYMOUS", "S2G_SMTP_USERNAME")
	})
	t.Run("contradictory with password", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "true"
		env["S2G_SMTP_PASSWORD"] = testSMTPPassword
		wantLoadErr(t, env, "S2G_SMTP_ALLOW_ANONYMOUS", "S2G_SMTP_PASSWORD")
	})
	t.Run("invalid boolean", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_SMTP_ALLOW_ANONYMOUS"] = "maybe"
		wantLoadErr(t, env, "S2G_SMTP_ALLOW_ANONYMOUS", "invalid boolean")
	})
}

func TestLogValueSMTPAuthModes(t *testing.T) {
	const pw = testSMTPPassword

	cases := []struct {
		name     string
		mutate   func(env map[string]string)
		wantMode string
	}{
		{
			name:     "ephemeral",
			mutate:   func(env map[string]string) {},
			wantMode: "ephemeral",
		},
		{
			name: "configured",
			mutate: func(env map[string]string) {
				env["S2G_SMTP_PASSWORD"] = pw
			},
			wantMode: "configured",
		},
		{
			name: "disabled",
			mutate: func(env map[string]string) {
				env["S2G_SMTP_ALLOW_ANONYMOUS"] = "true"
			},
			wantMode: "disabled",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := clone(baseEnv())
			tc.mutate(env)
			c := mustLoad(t, env)
			if got := c.smtpAuthMode(); got != tc.wantMode {
				t.Errorf("smtpAuthMode() = %q, want %q", got, tc.wantMode)
			}

			if strings.Contains(c.String(), pw) {
				t.Errorf("String() leaks the SMTP password: %s", c.String())
			}
			if strings.Contains(fmt.Sprintf("%v", c), pw) {
				t.Errorf("%%v leaks the SMTP password")
			}
			if c.SMTPPassword != "" && strings.Contains(c.LogValue().String(), c.SMTPPassword) {
				t.Errorf("LogValue() leaks the SMTP password: %s", c.LogValue().String())
			}

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			logger.Info("effective config", "config", c)
			if c.SMTPPassword != "" && strings.Contains(buf.String(), c.SMTPPassword) {
				t.Errorf("slog output leaks the SMTP password: %s", buf.String())
			}
			if !strings.Contains(buf.String(), `"smtp_auth":"`+tc.wantMode+`"`) {
				t.Errorf("slog output missing smtp_auth=%s: %s", tc.wantMode, buf.String())
			}
		})
	}
}

func TestLoadGraphSenderNormalizesAddress(t *testing.T) {
	env := clone(baseEnv())
	env["S2G_GRAPH_SENDER"] = "Scanner@Example.com"
	c := mustLoad(t, env)
	if c.GraphSender != "scanner@example.com" {
		t.Errorf("GraphSender = %q, want normalized address", c.GraphSender)
	}
}

func TestLoadRejectsEmptyConfiguredSMTPPassword(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "smtp-password")
	if err := os.WriteFile(empty, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}

	env := clone(baseEnv())
	env["S2G_SMTP_PASSWORD_FILE"] = empty
	wantLoadErr(t, env, "S2G_SMTP_PASSWORD")
}

// TestLoadRejectsAnEmptyRequiredValue is the same rule one setting wider: a
// _FILE spelling pointing at a file with nothing in it resolves cleanly, so
// without the check the appliance starts with no client secret at all and the
// SMTP port open, accepting scans it can never deliver.
func TestLoadRejectsAnEmptyRequiredValue(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "unpopulated-secret")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"S2G_ENTRA_TENANT_ID", "S2G_ENTRA_CLIENT_ID",
		"S2G_ENTRA_CLIENT_SECRET", "S2G_GRAPH_SENDER",
	} {
		t.Run(name, func(t *testing.T) {
			env := clone(baseEnv())
			delete(env, name)
			env[name+"_FILE"] = empty
			wantLoadErr(t, env, name, "required")
		})
	}
}

func TestLoadRejectsDuplicateJSONKeys(t *testing.T) {
	t.Run("profiles", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{"scan@example.com":{"email":true},"scan@example.com":{"web":true}}`
		wantLoadErr(t, env, "S2G_PROFILES")
	})
	t.Run("inside a capability object", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `{"scan@example.com":{"email":true,"email":false,"web":true}}`
		wantLoadErr(t, env, "S2G_PROFILES", `duplicate key "email"`)
	})
	// A second value after the object is a truncated edit or a shell that
	// concatenated two settings, and either way half of what is there is
	// being ignored. json.Decoder.More reads the next non-space byte at the
	// top level, so it does see one - worth pinning, because "the object
	// decoded, so we are done" is the reading a reader expects.
	t.Run("trailing data", func(t *testing.T) {
		for _, tail := range []string{`{"other@example.com":{"web":true}}`, ` garbage`, `null`} {
			env := clone(baseEnv())
			env["S2G_PROFILES"] = `{"scan@example.com":{"web":true}}` + tail
			wantLoadErr(t, env, "S2G_PROFILES", "trailing data after the JSON object")
		}
	})
	t.Run("not an object", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_PROFILES"] = `["scan@example.com"]`
		wantLoadErr(t, env, "S2G_PROFILES")
	})
}

func TestLoadRejectsTrailingJSON(t *testing.T) {
	env := clone(baseEnv())
	env["S2G_PROFILES"] = `{"a@example.com":{"web":true}}{"b@example.com":{"web":true}}`
	wantLoadErr(t, env, "S2G_PROFILES")
}

func TestLoadRejectsMalformedRecipientDomains(t *testing.T) {
	for _, domain := range []string{"*.example.com", "https://example.com", "example.com/x", ".example.com", "example..com"} {
		t.Run(domain, func(t *testing.T) {
			env := clone(baseEnv())
			env["S2G_ALLOWED_RECIPIENT_DOMAINS"] = domain
			wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS")
		})
	}
}

func TestLoadDefaultProfile(t *testing.T) {
	t.Run("every sender gets the default profile", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_PROFILES")
		delete(env, "S2G_DI_ENDPOINT")

		c, err := Load(fakeGetenv(env))
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		want := Capabilities{Email: true, Web: true, OCR: false}
		if c.DefaultProfile != want {
			t.Errorf("DefaultProfile = %+v, want %+v", c.DefaultProfile, want)
		}
		for _, sender := range []string{"anything@scanner.local", "Copier@Printer.Example"} {
			cp, ok := c.Profile(sender)
			if !ok || cp != want {
				t.Errorf("Profile(%q) = %+v, %t; want %+v, true", sender, cp, ok, want)
			}
		}
		if _, ok := c.Profile("not-an-address"); ok {
			t.Error("Profile(\"not-an-address\") = ok, want rejected")
		}
	})

	t.Run("ocr follows the Document Intelligence endpoint", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_PROFILES")

		c, err := Load(fakeGetenv(env))
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if !c.DefaultProfile.OCR {
			t.Error("DefaultProfile.OCR = false, want true when S2G_DI_ENDPOINT is set")
		}
	})

	t.Run("capabilities follow the configuration", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			without []string
			want    Capabilities
		}{
			{"everything configured", nil, Capabilities{Email: true, Web: true, OCR: true}},
			{"no graph sender", []string{"S2G_GRAPH_SENDER"}, Capabilities{Web: true, OCR: true}},
			{"no base URL", []string{"S2G_PUBLIC_BASE_URL"}, Capabilities{Email: true, OCR: true}},
			{"no document intelligence", []string{"S2G_DI_ENDPOINT"}, Capabilities{Email: true, Web: true}},
			{"web only", []string{"S2G_GRAPH_SENDER", "S2G_DI_ENDPOINT"}, Capabilities{Web: true}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := clone(baseEnv())
				delete(env, "S2G_PROFILES")
				for _, name := range tc.without {
					delete(env, name)
				}
				c, err := Load(fakeGetenv(env))
				if err != nil {
					t.Fatalf("Load() = %v", err)
				}
				if c.DefaultProfile != tc.want {
					t.Errorf("DefaultProfile = %+v, want %+v", c.DefaultProfile, tc.want)
				}
			})
		}
	})

	t.Run("a graph sender without an allowlist is an error", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_PROFILES")
		delete(env, "S2G_ALLOWED_RECIPIENT_DOMAINS")
		wantLoadErr(t, env, "S2G_ALLOWED_RECIPIENT_DOMAINS", "open mail relay")
	})

	t.Run("no delivery path at all is an error", func(t *testing.T) {
		env := clone(baseEnv())
		delete(env, "S2G_PROFILES")
		delete(env, "S2G_GRAPH_SENDER")
		delete(env, "S2G_PUBLIC_BASE_URL")
		wantLoadErr(t, env, "no way to deliver a scan")
	})

	t.Run("configured profiles still reject unknown senders", func(t *testing.T) {
		c, err := Load(fakeGetenv(baseEnv()))
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if _, ok := c.Profile("someone-else@scanner.local"); ok {
			t.Error("Profile(unknown sender) = ok, want rejected when profiles are configured")
		}
	})
}
