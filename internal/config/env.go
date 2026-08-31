package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// loader reads and validates environment variables, collecting every problem
// it finds instead of stopping at the first one. Callers ask for a typed
// value; if the raw value is missing or malformed the loader records an
// error and returns the type's zero value or a supplied default so that
// loading can continue and later steps do not panic on empty data.
type loader struct {
	getenv func(string) string
	errs   []error

	// conflicted remembers which variable names failed resolution because
	// both X and X_FILE were set, so a later "X is required" check does not
	// pile a second, less useful error message on top of that one.
	conflicted map[string]bool
}

func newLoader(getenv func(string) string) *loader {
	return &loader{getenv: getenv}
}

func (l *loader) addErr(err error) {
	if err != nil {
		l.errs = append(l.errs, err)
	}
}

func (l *loader) errorf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

// resolve returns the value of the environment variable name, honoring the
// "X_FILE" file-indirection convention: if name+"_FILE" is set, its content
// is read from disk (trailing whitespace/newlines trimmed) and used as the
// value. Setting both name and name+"_FILE" is a startup error. ok is false
// when neither is set, or when reading/validating failed; in the failure
// case an error has already been recorded.
// maxFileValueBytes bounds a *_FILE indirection: secrets and JSON maps are
// small, and a misconfigured path (a log file, /dev/zero) must not be read
// into memory in full.
const maxFileValueBytes = 1 << 20

// readFileLimited reads at most limit bytes from path and fails if the file
// is larger, so an operator learns about the mistake instead of the process
// growing until it is killed.
func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	return data, nil
}

func (l *loader) resolve(name string) (value string, ok bool) {
	direct := l.getenv(name)
	fileVar := name + "_FILE"
	filePath := l.getenv(fileVar)

	if direct != "" && filePath != "" {
		if l.conflicted == nil {
			l.conflicted = make(map[string]bool)
		}
		l.conflicted[name] = true
		l.errorf("%s and %s are both set; set only one", name, fileVar)
		return "", false
	}

	if filePath != "" {
		data, err := readFileLimited(filePath, maxFileValueBytes)
		if err != nil {
			// Report the path and the OS error only - never the file's
			// content, since this indirection exists for secrets.
			l.errorf("%s: reading file: %w", fileVar, err)
			return "", false
		}
		return strings.TrimRight(string(data), " \t\r\n"), true
	}

	if direct != "" {
		return direct, true
	}
	return "", false
}

// resolveRequired is like resolve, but records a well-worded "is required"
// error (naming why) when the variable is unset - unless resolve already
// reported a more specific problem (the X/X_FILE conflict) for it.
func (l *loader) resolveRequired(name, reason string) (value string, ok bool) {
	v, ok := l.resolve(name)
	if ok || l.conflicted[name] {
		return v, ok
	}
	if reason == "" {
		l.errorf("%s is required", name)
	} else {
		l.errorf("%s is required because %s", name, reason)
	}
	return "", false
}

// requiredIf resolves name, requiring it (with reason explaining why) only
// when required is true. It returns "" when the variable is absent, whether
// or not that absence was an error.
func (l *loader) requiredIf(name string, required bool, reason string) string {
	if required {
		v, _ := l.resolveRequired(name, reason)
		return v
	}
	v, _ := l.resolve(name)
	return v
}

func (l *loader) stringDefault(name, def string) string {
	v, ok := l.resolve(name)
	if !ok {
		return def
	}
	return v
}

func (l *loader) durationValue(name string, def time.Duration) (d time.Duration, resolved bool) {
	raw, ok := l.resolve(name)
	if !ok {
		return def, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.errorf("%s: invalid duration %q: %v", name, raw, err)
		return def, false
	}
	return d, true
}

// durationPositive resolves a duration that must be greater than zero.
func (l *loader) durationPositive(name string, def time.Duration) time.Duration {
	d, resolved := l.durationValue(name, def)
	if resolved && d <= 0 {
		l.errorf("%s: must be > 0, got %s", name, d)
	}
	return d
}

// durationAtLeast resolves a duration that must be at least min.
func (l *loader) durationAtLeast(name string, def, min time.Duration) time.Duration {
	d, resolved := l.durationValue(name, def)
	if resolved && d < min {
		l.errorf("%s: must be at least %s, got %s", name, min, d)
	}
	return d
}

// boolValue resolves name as a boolean, accepting whatever strconv.ParseBool
// accepts ("1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE",
// "false", "False", ...). resolved reports whether the variable was
// actually set, as opposed to def having been used because it was absent.
func (l *loader) boolValue(name string, def bool) (value bool, resolved bool) {
	raw, ok := l.resolve(name)
	if !ok {
		return def, false
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		l.errorf("%s: invalid boolean %q: %v", name, raw, err)
		return def, false
	}
	return b, true
}

func (l *loader) intPositive(name string, def int) int {
	raw, ok := l.resolve(name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		l.errorf("%s: invalid integer %q: %v", name, raw, err)
		return def
	}
	if n <= 0 {
		l.errorf("%s: must be > 0, got %d", name, n)
	}
	return n
}

func (l *loader) int64Positive(name string, def int64) int64 {
	raw, ok := l.resolve(name)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		l.errorf("%s: invalid integer %q: %v", name, raw, err)
		return def
	}
	if n <= 0 {
		l.errorf("%s: must be > 0, got %d", name, n)
	}
	return n
}

// parseBaseURL parses value as an absolute URL whose scheme is one of
// schemes, requires a host, forbids a query string or fragment, and strips a
// trailing slash from the path so callers can safely concatenate further
// path segments.
func parseBaseURL(name, value string, schemes ...string) (string, error) {
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("%s: invalid URL: %w", name, err)
	}
	if !u.IsAbs() {
		return "", fmt.Errorf("%s: must be an absolute URL, got %q", name, value)
	}
	schemeOK := false
	for _, sc := range schemes {
		if u.Scheme == sc {
			schemeOK = true
			break
		}
	}
	if !schemeOK {
		return "", fmt.Errorf("%s: scheme must be %s, got %q", name, strings.Join(schemes, " or "), u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s: must include a host, got %q", name, value)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s: must not include a query string or fragment, got %q", name, value)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}

// baseURL resolves name (required if required is true, for the given
// reason), parses it as a base URL restricted to schemes, and strips a
// trailing slash. It returns "" if the variable is absent (whether or not
// that is itself an error) or malformed.
func (l *loader) baseURL(name string, required bool, reason string, schemes ...string) string {
	raw := l.requiredIf(name, required, reason)
	if raw == "" {
		return ""
	}
	v, err := parseBaseURL(name, raw, schemes...)
	if err != nil {
		l.addErr(err)
		return ""
	}
	return v
}

// baseURLDefault is like baseURL but always has a default value, so the
// variable is validated whether the operator set it explicitly or not.
func (l *loader) baseURLDefault(name, def string, schemes ...string) string {
	raw, ok := l.resolve(name)
	if !ok {
		raw = def
	}
	v, err := parseBaseURL(name, raw, schemes...)
	if err != nil {
		l.addErr(err)
		return ""
	}
	return v
}

// decodeStringMap resolves name (defaulting to an empty object when unset)
// and decodes it as a JSON object with string keys. Unlike a plain
// json.Unmarshal into a map it rejects duplicate keys, unknown fields in the
// values and trailing data, so a mangled or typo'd configuration value fails
// at startup instead of silently taking the last of two entries.
func decodeStringMap[V any](l *loader, name string) (map[string]V, bool) {
	raw, set := l.resolve(name)
	if !set {
		raw = "{}"
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()

	if tok, err := dec.Token(); err != nil {
		l.errorf("%s: invalid JSON: %v", name, err)
		return nil, false
	} else if d, ok := tok.(json.Delim); !ok || d != '{' {
		l.errorf("%s: must be a JSON object", name)
		return nil, false
	}

	out := make(map[string]V)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			l.errorf("%s: invalid JSON: %v", name, err)
			return nil, false
		}
		key, ok := tok.(string)
		if !ok {
			l.errorf("%s: must be a JSON object", name)
			return nil, false
		}
		var v V
		if err := dec.Decode(&v); err != nil {
			l.errorf("%s: key %q: invalid value: %v", name, key, err)
			return nil, false
		}
		if _, dup := out[key]; dup {
			l.errorf("%s: duplicate key %q", name, key)
			return nil, false
		}
		out[key] = v
	}

	if _, err := dec.Token(); err != nil {
		l.errorf("%s: invalid JSON: %v", name, err)
		return nil, false
	}
	if dec.More() {
		l.errorf("%s: trailing data after the JSON object", name)
		return nil, false
	}
	return out, true
}
