package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
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
func (l *loader) resolve(name string) (value string, ok bool) {
	direct := l.getenv(name)
	fileVar := name + "_FILE"
	filePath := l.getenv(fileVar)

	if direct != "" && filePath != "" {
		l.errorf("%s and %s are both set; set only one", name, fileVar)
		return "", false
	}

	if filePath != "" {
		data, err := os.ReadFile(filePath)
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

// Resolve reads one setting the way Load does, following the documented
// S2G_X_FILE indirection. It returns "" for anything Load would refuse
// (both spellings set, or an unreadable file): a caller outside Load
// cannot report that, and the built-in default is the safe answer.
func Resolve(getenv func(string) string, name string) string {
	v, _ := newLoader(getenv).resolve(name)
	return v
}

// ResolveBaseURL is Resolve for a setting that must be an absolute http(s)
// URL. It returns "" for anything Load would refuse, so a caller printing a
// link for the operator to open falls back to one that works rather than one
// that parses.
func ResolveBaseURL(getenv func(string) string, name string) string {
	return newLoader(getenv).publicBaseURL(name, false, "")
}

// BasePath is the subpath prefix a public base URL asks the appliance to
// serve itself under: "/scanner" for https://nas.example/scanner/, and "" for
// a host of its own. Load puts it on Config.PathPrefix; main and the wizard
// ask the same question of a value they resolved rather than loaded. Every
// caller's value has been through parseBaseURL, which strips the trailing
// slashes; stripping them again is what keeps the answer this comment
// promises from depending on that.
func BasePath(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}

// resolveRequired is like resolve, but records a well-worded "is required"
// error (naming why) when the variable is unset - or set to nothing, which
// an unpopulated Docker secret is: without that, S2G_ENTRA_CLIENT_SECRET_FILE
// pointing at an empty file starts the appliance with no client secret and
// the SMTP port open, accepting scans it cannot deliver. smtpAuth guards
// exactly this for S2G_SMTP_PASSWORD.
func (l *loader) resolveRequired(name, reason string) (value string, ok bool) {
	v, ok := l.resolve(name)
	if ok && v != "" {
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
// schemes, requires a host, forbids a query string or fragment, and strips
// trailing slashes from the path so callers can safely concatenate further
// path segments. All of them go: a path left as "/" would make the
// appliance's own links start "//", which a browser reads as another host.
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
	u.Path = strings.TrimRight(u.Path, "/")
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

// plainSubpath is what the appliance's own base URL may carry as a path:
// nothing, or unreserved ASCII segments - "/scanner", "/apps/scan2graph".
// Empty, "." and ".." segments are out because the first character of one
// cannot be "." or "/".
var plainSubpath = regexp.MustCompile(`^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*$`)

// publicBaseURL is baseURL with the one restriction the appliance's own
// address has and a vendor's endpoint does not: its path is where the
// appliance serves itself, so it becomes route patterns and cookie scopes,
// and neither is forgiving. ServeMux panics at registration on a pattern
// whose path is unclean or holds a "{", so "//scanner" or "/a/../b" would
// take down every start after the one that saved it - the wizard that repairs
// it included. http.SetCookie silently drops the bytes outside 0x20..0x7e
// from a Path, so "/scänner" would route perfectly and make signing in
// impossible, the session cookie being scoped to a path nothing serves. And
// a path beginning "\" becomes "//evil.example" in a browser's URL parser,
// which is another host. Refusing all of it here costs the operator a
// hostname with a "+" in it, and Load says why.
func (l *loader) publicBaseURL(name string, required bool, reason string) string {
	v := l.baseURL(name, required, reason, "http", "https")
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || !plainSubpath.MatchString(u.EscapedPath()) {
		l.errorf("%s: the path must be a plain subpath such as /scanner, got %q", name, u.EscapedPath())
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

// ParseProfiles decodes an S2G_PROFILES value: a JSON object of address to
// Capabilities. Nothing at all is spelled "{}" and not "", so that a caller
// has to say which it means: an S2G_PROFILES_FILE pointing at a file with
// nothing in it resolves to the empty string, and reading that as "no
// profiles" would be a mount that failed quietly turning "these addresses
// may do exactly this" into "every sender may do whatever else is
// configured". It rejects
// duplicate keys at any depth, unknown fields in the values and trailing
// data, so a mangled or typo'd value fails instead of quietly taking the
// last of two entries or ignoring a misspelled capability.
//
// Exported because the setup wizard has to ask exactly this question before
// it offers to edit such a value: a form built on a laxer reading would show
// only the surviving entry and write the other one away on the next save.
// Sharing the function rather than the answer is what keeps the two from
// drifting apart.
func ParseProfiles(raw string) (map[string]Capabilities, error) {
	out := map[string]Capabilities{}
	switch dup, err := duplicateJSONKey(strings.NewReader(raw)); {
	case err != nil:
		return nil, fmt.Errorf("invalid JSON: %v", err)
	case dup != "":
		return nil, fmt.Errorf("duplicate key %q", dup)
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON object")
	}
	if out == nil {
		out = map[string]Capabilities{} // the literal "null"
	}
	return out, nil
}

// duplicateJSONKey returns the first object key that occurs twice in the
// same object anywhere in the JSON value read from r, or "" if there is
// none. encoding/json itself silently keeps the last of two entries, which
// would turn a configuration typo into a profile that quietly does
// something else.
func duplicateJSONKey(r io.Reader) (string, error) {
	dec := json.NewDecoder(r)

	var value func() (string, error)
	value = func() (string, error) {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return "", nil // a scalar has no keys
		}

		if delim == '{' {
			seen := make(map[string]bool)
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return "", err
				}
				key, _ := keyTok.(string)
				if seen[key] {
					return key, nil
				}
				seen[key] = true
				if dup, err := value(); dup != "" || err != nil {
					return dup, err
				}
			}
		} else {
			for dec.More() {
				if dup, err := value(); dup != "" || err != nil {
					return dup, err
				}
			}
		}
		_, err = dec.Token() // the closing } or ]
		return "", err
	}

	return value()
}
