package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// noEnv is a process environment with nothing in it, so a test's only source
// of settings is the configuration file.
func noEnv(string) string { return "" }

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeEnvFile renders env as a configuration file, so the tests below load
// the same settings the rest of this package's tests use, only through the
// file instead of through the environment.
func writeEnvFile(t *testing.T, env map[string]string) string {
	t.Helper()
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# scan2graph test configuration\n\n")
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%s\n", name, env[name])
	}
	return writeFile(t, "scan2graph.env", b.String())
}

func mustFileEnv(t *testing.T, path string, environ func(string) string) (func(string) string, []string) {
	t.Helper()
	getenv, overridden, err := FileEnv(path, environ)
	if err != nil {
		t.Fatalf("FileEnv(%q) unexpected error: %v", path, err)
	}
	return getenv, overridden
}

func TestFileEnvPrecedence(t *testing.T) {
	t.Run("no file at all leaves the environment alone", func(t *testing.T) {
		env := baseEnv()
		getenv, overridden := mustFileEnv(t, "", fakeGetenv(env))
		if len(overridden) != 0 {
			t.Errorf("overridden = %v, want none", overridden)
		}
		if got := getenv("S2G_GRAPH_SENDER"); got != env["S2G_GRAPH_SENDER"] {
			t.Errorf("getenv(S2G_GRAPH_SENDER) = %q, want %q", got, env["S2G_GRAPH_SENDER"])
		}
	})

	t.Run("the file alone configures the appliance", func(t *testing.T) {
		getenv, overridden := mustFileEnv(t, writeEnvFile(t, baseEnv()), noEnv)
		if len(overridden) != 0 {
			t.Errorf("overridden = %v, want none", overridden)
		}
		c, err := Load(getenv)
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if c.GraphSender != "scanner@example.com" {
			t.Errorf("GraphSender = %q, want scanner@example.com", c.GraphSender)
		}
		// An unquoted JSON value straight out of the file.
		if len(c.Profiles) != 1 {
			t.Errorf("len(Profiles) = %d, want 1", len(c.Profiles))
		}
		// Not in the file, so the built-in default still applies.
		if c.HTTPAddr != ":8080" {
			t.Errorf("HTTPAddr = %q, want :8080", c.HTTPAddr)
		}
	})

	t.Run("the environment wins over the file and is counted", func(t *testing.T) {
		path := writeEnvFile(t, baseEnv())
		environ := fakeGetenv(map[string]string{
			"S2G_PUBLIC_BASE_URL": "https://from-environment.example",
			"S2G_UI_TITLE":        "From the environment",
		})
		getenv, overridden := mustFileEnv(t, path, environ)
		// Named, not counted: S2G_UI_TITLE is in the environment only, so
		// it is not something the file is losing.
		if want := []string{"S2G_PUBLIC_BASE_URL"}; !slices.Equal(overridden, want) {
			t.Errorf("overridden = %v, want %v", overridden, want)
		}
		c, err := Load(getenv)
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if c.PublicBaseURL != "https://from-environment.example" {
			t.Errorf("PublicBaseURL = %q, want the environment's value", c.PublicBaseURL)
		}
		if c.UITitle != "From the environment" {
			t.Errorf("UITitle = %q, want the environment's value", c.UITitle)
		}
		// Untouched by the environment, so still the file's.
		if c.DIEndpoint != baseEnv()["S2G_DI_ENDPOINT"] {
			t.Errorf("DIEndpoint = %q, want the file's value", c.DIEndpoint)
		}
	})
}

func TestFileEnvFileIndirection(t *testing.T) {
	const secret = "file-fixture-value"

	t.Run("_FILE inside the configuration file", func(t *testing.T) {
		secretPath := writeFile(t, "client-secret", secret+"\n")
		env := clone(baseEnv())
		delete(env, "S2G_ENTRA_CLIENT_SECRET")
		env["S2G_ENTRA_CLIENT_SECRET_FILE"] = secretPath
		getenv, _ := mustFileEnv(t, writeEnvFile(t, env), noEnv)
		c, err := Load(getenv)
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if c.ClientSecret != secret {
			t.Errorf("ClientSecret = %q, want %q", c.ClientSecret, secret)
		}
	})

	t.Run("the environment's spelling hides the file's other spelling", func(t *testing.T) {
		// The file names a secret file; the environment supplies the secret
		// directly. That is an override, not the "set only one" conflict.
		env := clone(baseEnv())
		delete(env, "S2G_ENTRA_CLIENT_SECRET")
		env["S2G_ENTRA_CLIENT_SECRET_FILE"] = writeFile(t, "client-secret", "the file's secret")
		environ := fakeGetenv(map[string]string{"S2G_ENTRA_CLIENT_SECRET": secret})
		getenv, overridden := mustFileEnv(t, writeEnvFile(t, env), environ)
		// The file's spelling is what got overridden, and that is the name
		// reported - the operator needs to see which line lost.
		if want := []string{"S2G_ENTRA_CLIENT_SECRET_FILE"}; !slices.Equal(overridden, want) {
			t.Errorf("overridden = %v, want %v", overridden, want)
		}
		c, err := Load(getenv)
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if c.ClientSecret != secret {
			t.Errorf("ClientSecret = %q, want the environment's %q", c.ClientSecret, secret)
		}
	})

	t.Run("the environment's _FILE hides the file's direct value", func(t *testing.T) {
		environ := fakeGetenv(map[string]string{
			"S2G_ENTRA_CLIENT_SECRET_FILE": writeFile(t, "client-secret", secret),
		})
		getenv, _ := mustFileEnv(t, writeEnvFile(t, baseEnv()), environ)
		c, err := Load(getenv)
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if c.ClientSecret != secret {
			t.Errorf("ClientSecret = %q, want the environment's %q", c.ClientSecret, secret)
		}
	})

	t.Run("both spellings inside the file is still an error", func(t *testing.T) {
		env := clone(baseEnv())
		env["S2G_ENTRA_CLIENT_SECRET_FILE"] = writeFile(t, "client-secret", secret)
		getenv, _ := mustFileEnv(t, writeEnvFile(t, env), noEnv)
		_, err := Load(getenv)
		if err == nil {
			t.Fatal("Load() succeeded, want the \"set only one\" error")
		}
		if !strings.Contains(err.Error(), "S2G_ENTRA_CLIENT_SECRET_FILE") {
			t.Errorf("error %q does not name the _FILE variable", err)
		}
	})
}

func TestParseEnvFileFormat(t *testing.T) {
	const profiles = `{"scan@scanner.local":{"email":true,"web":true,"ocr":true}}`
	path := writeFile(t, "scan2graph.env", strings.Join([]string{
		"# a comment",
		"   # an indented comment",
		"",
		"   ",
		"S2G_HTTP_ADDR=:8080",
		"  S2G_SMTP_ADDR = :2525  ",
		"export S2G_UI_TITLE=ACME Document Scanning",
		`S2G_ENTRA_CLIENT_SECRET="quoted secret"`,
		"S2G_LOG_LEVEL='info'",
		"S2G_PROFILES=" + profiles,
		`S2G_GRAPH_SCOPE="` + profiles + `"`,
		"S2G_DI_SCOPE=https://example.test/.default?a=b#c",
		"S2G_JOB_TTL=",
	}, "\r\n"))

	got, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() unexpected error: %v", err)
	}
	want := map[string]string{
		"S2G_HTTP_ADDR":           ":8080",
		"S2G_SMTP_ADDR":           ":2525",
		"S2G_UI_TITLE":            "ACME Document Scanning",
		"S2G_ENTRA_CLIENT_SECRET": "quoted secret",
		"S2G_LOG_LEVEL":           "info",
		// JSON survives both unquoted and double-quoted, inner quotes and
		// all; S2G_LOG_LEVEL above is the single-quoted case.
		"S2G_PROFILES":    profiles,
		"S2G_GRAPH_SCOPE": profiles,
		// Nothing in a value is interpreted: no trailing-comment stripping.
		"S2G_DI_SCOPE": "https://example.test/.default?a=b#c",
		"S2G_JOB_TTL":  "",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %q, want %q", name, got[name], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("parsed %d keys, want %d: %v", len(got), len(want), got)
	}
}

func TestParseEnvFileErrors(t *testing.T) {
	const secret = "a-secret-on-a-broken-line"

	t.Run("duplicate key", func(t *testing.T) {
		path := writeFile(t, "scan2graph.env", "S2G_HTTP_ADDR=:8080\n#\nS2G_HTTP_ADDR=:9090\n")
		_, err := ParseFile(path)
		if err == nil {
			t.Fatal("ParseFile() succeeded, want an error")
		}
		for _, want := range []string{path, "line 3", "duplicate", "S2G_HTTP_ADDR"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
	})

	t.Run("malformed line names the line but never its content", func(t *testing.T) {
		path := writeFile(t, "scan2graph.env", "S2G_HTTP_ADDR=:8080\n"+secret+"\n")
		_, err := ParseFile(path)
		if err == nil {
			t.Fatal("ParseFile() succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "line 2") {
			t.Errorf("error %q does not name the line number", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q leaks the line's content", err)
		}
	})

	t.Run("a key that is not a variable name", func(t *testing.T) {
		path := writeFile(t, "scan2graph.env", "not a key="+secret+"\n")
		_, err := ParseFile(path)
		if err == nil {
			t.Fatal("ParseFile() succeeded, want an error")
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q leaks the line's content", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		// A directory: unreadable as a file whatever the test runs as.
		_, _, err := FileEnv(t.TempDir(), noEnv)
		if err == nil {
			t.Fatal("FileEnv() succeeded, want an error")
		}
	})

	t.Run("a file that was asked for but does not exist", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.env")
		_, _, err := FileEnv(missing, noEnv)
		if err == nil {
			t.Fatal("FileEnv() succeeded, want an error")
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error %q does not name the path", err)
		}
	})
}

// TestFileEnvLoadsShippedExample keeps .env.example loadable as it ships:
// it is what operators copy, and the wizard writes the same format.
func TestFileEnvLoadsShippedExample(t *testing.T) {
	getenv, overridden := mustFileEnv(t, filepath.Join("..", "..", ".env.example"), noEnv)
	if len(overridden) != 0 {
		t.Errorf("overridden = %v, want none", overridden)
	}
	if _, err := Load(getenv); err != nil {
		t.Fatalf(".env.example does not load: %v", err)
	}
}
