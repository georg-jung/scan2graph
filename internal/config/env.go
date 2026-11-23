package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// loader reads and validates environment variables, collecting every problem
// it finds instead of stopping at the first one, so that loading can continue
// and later steps do not panic on empty data.
type loader struct {
	getenv func(string) string
	errs   []error
}

func (l *loader) errorf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

// ResolveBaseURL reads a setting that must be an absolute http(s) URL the
// way Load does. It returns "" for anything Load would refuse, so a caller
// printing a link for the operator to open falls back to one that works
// rather than one that parses.
func ResolveBaseURL(getenv func(string) string) string {
	return (&loader{getenv: getenv}).publicBaseURL("S2G_PUBLIC_BASE_URL")
}

// BasePath is the subpath prefix a public base URL asks the appliance to
// serve itself under: "/scanner" for https://nas.example/scanner/, else "".
func BasePath(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}

// required records an "is required" error naming why when name is unset.
func (l *loader) required(name, reason string) string {
	v := l.getenv(name)
	if v == "" {
		l.errorf("%s is required because %s", name, reason)
	}
	return v
}

// durationAtLeast resolves a duration that must be at least min.
func (l *loader) durationAtLeast(name string, def, min time.Duration) time.Duration {
	raw := l.getenv(name)
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.errorf("%s: invalid duration %q: %v", name, raw, err)
		return def
	}
	if d < min {
		l.errorf("%s: must be at least %s, got %s", name, min, d)
	}
	return d
}

// boolValue resolves name as a boolean, accepting whatever strconv.ParseBool
// accepts; unset is false.
func (l *loader) boolValue(name string) bool {
	raw := l.getenv(name)
	if raw == "" {
		return false
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		l.errorf("%s: invalid boolean %q: %v", name, raw, err)
	}
	return b
}

func (l *loader) int64Positive(name string, def int64) int64 {
	raw := l.getenv(name)
	if raw == "" {
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

// baseURL parses name, if set, as a base URL restricted to schemes. It
// returns "" if the variable is unset or malformed.
func (l *loader) baseURL(name string, schemes ...string) string {
	raw := l.getenv(name)
	if raw == "" {
		return ""
	}
	v, err := parseBaseURL(name, raw, schemes...)
	if err != nil {
		l.errs = append(l.errs, err)
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
func (l *loader) publicBaseURL(name string) string {
	v := l.baseURL(name, "http", "https")
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
