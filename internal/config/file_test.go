package config

import (
	"fmt"
	"log/slog"
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
		// Not in the file, so the built-in default still applies.
		if c.HTTPAddr != ":8080" {
			t.Errorf("HTTPAddr = %q, want :8080", c.HTTPAddr)
		}
	})

	t.Run("the environment wins over the file and is counted", func(t *testing.T) {
		path := writeEnvFile(t, baseEnv())
		environ := fakeGetenv(map[string]string{
			"S2G_PUBLIC_BASE_URL": "https://from-environment.example",
			"S2G_LOG_LEVEL":       "debug",
		})
		getenv, overridden := mustFileEnv(t, path, environ)
		// Named, not counted: S2G_LOG_LEVEL is in the environment only, so
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
		if c.LogLevel != slog.LevelDebug {
			t.Errorf("LogLevel = %v, want the environment's value", c.LogLevel)
		}
		// Untouched by the environment, so still the file's.
		if c.DIEndpoint != baseEnv()["S2G_DI_ENDPOINT"] {
			t.Errorf("DIEndpoint = %q, want the file's value", c.DIEndpoint)
		}
	})
}

func TestParseEnvFileFormat(t *testing.T) {
	const json = `{"a":{"b":true}}`
	path := writeFile(t, "scan2graph.env", strings.Join([]string{
		"# a comment",
		"   # an indented comment",
		"",
		"   ",
		"S2G_HTTP_ADDR=:8080",
		"  S2G_SMTP_ADDR = :2525  ",
		"export S2G_GRAPH_SENDER=scanner@example.com",
		`S2G_ENTRA_CLIENT_SECRET="quoted secret"`,
		"S2G_LOG_LEVEL='info'",
		"JSON_A=" + json,
		`JSON_B="` + json + `"`,
		"S2G_DI_ENDPOINT=https://example.test/x?a=b#c",
		"S2G_JOB_TTL=",
	}, "\r\n"))

	got, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() unexpected error: %v", err)
	}
	want := map[string]string{
		"S2G_HTTP_ADDR":           ":8080",
		"S2G_SMTP_ADDR":           ":2525",
		"S2G_GRAPH_SENDER":        "scanner@example.com",
		"S2G_ENTRA_CLIENT_SECRET": "quoted secret",
		"S2G_LOG_LEVEL":           "info",
		// Inner quotes survive both unquoted and double-quoted; S2G_LOG_LEVEL
		// above is the single-quoted case.
		"JSON_A": json,
		"JSON_B": json,
		// Nothing in a value is interpreted: no trailing-comment stripping.
		"S2G_DI_ENDPOINT": "https://example.test/x?a=b#c",
		"S2G_JOB_TTL":     "",
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
