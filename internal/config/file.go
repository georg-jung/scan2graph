package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// FileEnv returns the getenv function Load should read through when a
// configuration file may supply settings the process environment does not:
// precedence is process environment > configuration file > built-in default.
// path may be empty, meaning "no configuration file", in which case environ
// is returned unchanged; a path that was asked for but cannot be read or
// parsed is an error rather than a silent fall back to the environment
// alone. overridden names the file's settings that the environment supplied
// as well, sorted, for the startup banner: names rather than a count,
// because "two of your settings are being ignored" is the half of the
// sentence that does not help.
func FileEnv(path string, environ func(string) string) (getenv func(string) string, overridden []string, err error) {
	if path == "" {
		return environ, nil, nil
	}
	file, err := ParseFile(path)
	if err != nil {
		return nil, nil, err
	}
	for name := range file {
		if environ(name) != "" || environ(pairedName(name)) != "" {
			overridden = append(overridden, name)
		}
	}
	slices.Sort(overridden)
	return Layer(file, environ), overridden, nil
}

// Layer is FileEnv's precedence rule over an already-parsed file, so the
// setup wizard can validate an edit the way the next start will read it.
func Layer(file map[string]string, environ func(string) string) func(string) string {
	return func(name string) string {
		if v := environ(name); v != "" {
			return v
		}
		// The environment overrides a setting, not one spelling of it. With
		// S2G_X in the environment and S2G_X_FILE in the file, resolve would
		// otherwise see both and refuse to start over a conflict the
		// operator never created - which is exactly what happens when a
		// copy of .env.example gets its secret replaced by a mounted one.
		// So whichever spelling the environment uses hides both of the
		// file's, and "both set" stays an error within a single layer.
		if environ(pairedName(name)) != "" {
			return ""
		}
		return file[name]
	}
}

// pairedName is the other spelling of the setting name refers to:
// S2G_X_FILE for S2G_X, and S2G_X for S2G_X_FILE.
func pairedName(name string) string {
	if base, ok := strings.CutSuffix(name, "_FILE"); ok {
		return base
	}
	return name + "_FILE"
}

// ParseFile reads a configuration file in the format of .env.example:
// KEY=value, one per line, with "#" comment lines, blank lines and an
// optional "export " prefix. The value is taken verbatim to the end of the
// line (nothing is interpreted, so no shell expansion and no trailing
// comments) with one matched pair of surrounding single or double quotes
// stripped, which is what makes the JSON-valued settings read the same
// whether or not the writer quoted them. A duplicate key is an error rather
// than last-one-wins, as it already is inside those JSON values.
//
// Errors name the file and the line number but never the line itself: a
// malformed line in a configuration file may well hold a client secret.
func ParseFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("configuration file: %w", err)
	}
	out := make(map[string]string)
	// Windows editors write UTF-8 with a byte order mark, and this file gets
	// copied from .env.example on whatever machine the operator has.
	for i, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		// A name with a space in it is prose that happened to contain an
		// equals sign, not a setting. Nothing stricter: a file may carry
		// keys this appliance never reads, and those are simply inert.
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, fmt.Errorf("%s: line %d: expected KEY=value", path, i+1)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s: line %d: duplicate key %s", path, i+1, name)
		}
		out[name] = unquote(strings.TrimSpace(value))
	}
	return out, nil
}

// unquote strips one matched pair of surrounding single or double quotes.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
