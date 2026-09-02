package web

import (
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/georg-jung/scan2graph/internal/config"
)

// setupToken is the one-shot token these tests present; it is as fake as it
// looks, and the only credential this file invents.
const setupToken = "not-a-real-setup-token"

func noEnv(string) string { return "" }

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// validForm is the smallest configuration the loader accepts: an Entra app
// registration, plus the public URL that turns the web UI on.
func validForm() url.Values {
	return url.Values{
		"S2G_ENTRA_TENANT_ID":     {"00000000-0000-0000-0000-000000000000"},
		"S2G_ENTRA_CLIENT_ID":     {testClientID},
		"S2G_ENTRA_CLIENT_SECRET": {testClientSecret},
		"S2G_PUBLIC_BASE_URL":     {"https://scan2graph.example.com"},
	}
}

// setupHarness is the wizard as a browser meets it: a real server over plain
// http, which is how it is reached on the LAN.
type setupHarness struct {
	t    *testing.T
	ts   *httptest.Server
	path string
}

func newSetupHarness(t *testing.T, opts SetupOptions) *setupHarness {
	t.Helper()
	if opts.Getenv == nil {
		opts.Getenv = noEnv
	}
	ts := httptest.NewServer(NewSetup(opts))
	t.Cleanup(ts.Close)
	return &setupHarness{t: t, ts: ts, path: opts.Path}
}

// client is one browser: its own cookie jar, and no automatic redirects.
func (h *setupHarness) client() *http.Client {
	h.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		h.t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (h *setupHarness) do(resp *http.Response, err error, what string) (*http.Response, string) {
	h.t.Helper()
	if err != nil {
		h.t.Fatalf("%s: %v", what, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body of %s: %v", what, err)
	}
	return resp, string(body)
}

func (h *setupHarness) get(c *http.Client, path string) (*http.Response, string) {
	h.t.Helper()
	resp, err := c.Get(h.ts.URL + path)
	return h.do(resp, err, "GET "+path)
}

func (h *setupHarness) post(c *http.Client, form url.Values) (*http.Response, string) {
	h.t.Helper()
	resp, err := c.PostForm(h.ts.URL+"/setup", form)
	return h.do(resp, err, "POST /setup")
}

// start presses "Start configuration", which is how any browser gets past the
// claim page to the form - and closes the wizard behind it.
func (h *setupHarness) start(c *http.Client) *http.Response {
	h.t.Helper()
	resp, err := c.PostForm(h.ts.URL+"/setup/start", nil)
	got, _ := h.do(resp, err, "POST /setup/start")
	return got
}

// claim is start for the browser that is meant to win: the 303 and the cookie
// its jar keeps from here on.
func (h *setupHarness) claim(c *http.Client) {
	h.t.Helper()
	if resp := h.start(c); resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("claiming the wizard: status %d, want 303", resp.StatusCode)
	}
}

// claimed is the browser every test that reaches the form needs: an unclaimed
// wizard shows the claim page and refuses everything else, so pressing Start
// is the first thing any of them does.
func (h *setupHarness) claimed() *http.Client {
	h.t.Helper()
	c := h.client()
	h.claim(c)
	return c
}

// formID is the hidden field a rendered form carries, which a browser hands
// straight back on the next press: the wizard's name for the page in front of
// the operator, and how it knows what an empty password box on that page
// means.
func (h *setupHarness) formID(body string) string {
	h.t.Helper()
	m := regexp.MustCompile(`name="form" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("the rendered page carries no form id:\n%s", body)
	}
	return m[1]
}

// loads asserts the file the wizard wrote is one the appliance would actually
// start from, read back through the real parser and the real loader.
func loads(t *testing.T, path string) map[string]string {
	t.Helper()
	values, err := config.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile(%q): %v", path, err)
	}
	if _, err := config.Load(config.Layer(values, noEnv)); err != nil {
		t.Fatalf("the written file does not load: %v", err)
	}
	return values
}

// TestSetupFieldsCoverConfig is the whole defence against the field table and
// the loader drifting apart: every S2G_* name internal/config reads is in
// exactly one of setupFields (a box on the form) or handEdited (the e2e
// fakes' settings, deliberately given no box), and neither list names a
// setting the loader ignores. Only quoted names count, so prose in a comment
// does not join either list.
func TestSetupFieldsCoverConfig(t *testing.T) {
	sources, err := filepath.Glob(filepath.Join("..", "config", "*.go"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("globbing internal/config: %v (%d files)", err, len(sources))
	}
	re := regexp.MustCompile(`"(S2G_[A-Z0-9_]+)"`)
	want := make(map[string]bool)
	for _, source := range sources {
		src, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			// S2G_CONFIG_FILE points at the file itself; it is main's, and
			// no setting the file can contain.
			if m[1] == "S2G_CONFIG_FILE" {
				continue
			}
			want[strings.TrimSuffix(m[1], "_FILE")] = true
		}
	}
	if len(want) < 20 {
		t.Fatalf("only %d settings found in internal/config; the pattern stopped matching", len(want))
	}

	got := make(map[string]bool, len(setupFields))
	for _, f := range setupFields {
		if got[f.Name] {
			t.Errorf("%s appears twice in setupFields", f.Name)
		}
		got[f.Name] = true
		if f.Label == "" || f.Help == "" || f.Group == "" {
			t.Errorf("%s: label, help and group are all required", f.Name)
		}
	}
	hand := make(map[string]bool, len(handEdited))
	for _, name := range handEdited {
		if hand[name] {
			t.Errorf("%s appears twice in handEdited", name)
		}
		hand[name] = true
	}

	for name := range want {
		switch {
		case got[name] && hand[name]:
			t.Errorf("%s is in both setupFields and handEdited", name)
		case !got[name] && !hand[name]:
			t.Errorf("%s is read by internal/config but is in neither setupFields nor handEdited", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("%s is a field in setupFields but internal/config never reads it", name)
		}
	}
	for name := range hand {
		if !want[name] {
			t.Errorf("%s is in handEdited but internal/config never reads it", name)
		}
	}
}

// TestAnyConfigured pins the narrowed rule: the question is "is there a
// secret here to steal", not "has anybody touched anything". A cosmetic
// setting must not count, or a genuinely blank appliance that names its
// listen address never gets its first-boot wizard - and the wizard could
// then only ever be reached on the default port.
func TestAnyConfigured(t *testing.T) {
	only := func(name string) func(string) string {
		return func(n string) string {
			if n == name {
				return "something"
			}
			return ""
		}
	}
	if AnyConfigured(noEnv) {
		t.Error("AnyConfigured on an empty environment = true, want false")
	}
	for _, name := range []string{
		"S2G_ENTRA_TENANT_ID", "S2G_ENTRA_CLIENT_ID",
		"S2G_ENTRA_CLIENT_SECRET", "S2G_ENTRA_CLIENT_SECRET_FILE",
		"S2G_SMTP_PASSWORD", "S2G_SMTP_PASSWORD_FILE",
	} {
		if !AnyConfigured(only(name)) {
			t.Errorf("AnyConfigured with %s set = false, want true", name)
		}
	}
	for _, name := range []string{
		"S2G_HTTP_ADDR", "S2G_LOG_LEVEL", "S2G_UI_TITLE", "S2G_SMTP_ADDR",
		"S2G_PUBLIC_BASE_URL", "S2G_DI_ENDPOINT",
		"S2G_GRAPH_BASE_URL", // hand-edited: for the e2e harness, not a secret
	} {
		if AnyConfigured(only(name)) {
			t.Errorf("AnyConfigured with only %s set = true; nothing there is worth protecting", name)
		}
	}
}

func TestSetupToken(t *testing.T) {
	sum := sha256Of(setupToken)

	t.Run("the token in the URL becomes a cookie", func(t *testing.T) {
		h := newSetupHarness(t, SetupOptions{TokenHash: sum})
		c := h.client()
		resp, _ := h.get(c, "/setup?t="+setupToken)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status %d, want 303", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "/setup" {
			t.Errorf("Location = %q, want /setup, so the token leaves the address bar", loc)
		}
		cookies := resp.Cookies()
		if len(cookies) != 1 || cookies[0].Name != setupCookie {
			t.Fatalf("cookies = %v, want one %s", cookies, setupCookie)
		}
		// Plain http on the LAN: a Secure cookie would never come back.
		if cookies[0].Secure || !cookies[0].HttpOnly {
			t.Errorf("cookie Secure=%v HttpOnly=%v, want false/true", cookies[0].Secure, cookies[0].HttpOnly)
		}
		// The jar now has it, so the form itself is reachable.
		resp, body := h.get(c, "/setup")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d with the cookie, want 200", resp.StatusCode)
		}
		if !strings.Contains(body, "S2G_ENTRA_TENANT_ID") {
			t.Error("the form does not mention S2G_ENTRA_TENANT_ID")
		}
	})

	t.Run("without the token nothing is here", func(t *testing.T) {
		h := newSetupHarness(t, SetupOptions{TokenHash: sum})
		c := h.client()
		for _, path := range []string{"/", "/setup", "/setup?t=" + setupToken + "x", "/static/style.css"} {
			resp, _ := h.get(c, path)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
			}
		}
		if resp, _ := h.post(c, validForm()); resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST /setup: status %d, want 404", resp.StatusCode)
		}
	})

	t.Run("a fresh install needs no token", func(t *testing.T) {
		h := newSetupHarness(t, SetupOptions{})
		c := h.client()
		resp, body := h.get(c, "/setup")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if !strings.Contains(body, "Set up scan2graph") {
			t.Error("the form is not the form")
		}
		if resp, _ := h.get(c, "/"); resp.StatusCode != http.StatusSeeOther ||
			resp.Header.Get("Location") != "/setup" {
			t.Errorf("GET /: status %d to %q, want 303 to /setup", resp.StatusCode, resp.Header.Get("Location"))
		}
		if resp, _ := h.get(c, "/nope"); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET /nope: status %d, want 404", resp.StatusCode)
		}
	})
}

func TestSetupRejectsAndAttributes(t *testing.T) {
	h := newSetupHarness(t, SetupOptions{Path: filepath.Join(t.TempDir(), "scan2graph.env")})
	form := validForm()
	form.Set("S2G_LOG_LEVEL", "loud")
	c := h.claimed()
	resp, body := h.post(c, form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want the form back with 200", resp.StatusCode)
	}
	if _, err := os.Stat(h.path); err == nil {
		t.Fatal("an invalid submission wrote the configuration file")
	}
	// One bad setting, named once: it belongs under its own box, not in the
	// list above the form.
	field, ok := strings.CutPrefix(body[strings.Index(body, `<div class="field bad">`):], `<div class="field bad">`)
	if !ok {
		t.Fatal("no field is marked bad")
	}
	field, _, _ = strings.Cut(field, "</div>")
	if !strings.Contains(field, `id="S2G_LOG_LEVEL"`) || !strings.Contains(field, "must be one of") {
		t.Errorf("the error is not under S2G_LOG_LEVEL:\n%s", field)
	}
	if strings.Contains(body, "problems") {
		t.Error("a field's own error was also listed above the form")
	}
	// The secret is never rendered back, but this page is holding it, so the
	// hint offering to keep whatever an empty box would keep is the truth
	// here - and correcting the one bad box must not cost the operator the
	// secret they typed into the form that was rejected.
	if strings.Contains(body, testClientSecret) {
		t.Fatal("the re-rendered form rendered the client secret")
	}
	if !strings.Contains(body, "configured — leave empty to keep") {
		t.Error("the page does not offer to keep the secret it is holding")
	}
	fixed := validForm()
	fixed.Set("form", h.formID(body))
	fixed.Del("S2G_ENTRA_CLIENT_SECRET") // taking that offer up
	fixed.Set("action", "save")
	if _, body := h.post(c, fixed); !strings.Contains(body, "Saved") {
		t.Fatalf("the corrected submission did not save: %s", body)
	}
	if got := loads(t, h.path)["S2G_ENTRA_CLIENT_SECRET"]; got != testClientSecret {
		t.Errorf("the file holds %q, want the secret the rejected submission carried", got)
	}
}

func TestSetupSaves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan2graph.env")
	h := newSetupHarness(t, SetupOptions{
		Path: path,
		// A hand-added line the wizard knows nothing about, and a setting it
		// does: both have to survive.
		FileValues: map[string]string{"S2G_FUTURE_SETTING": "kept", "S2G_UI_TITLE": "Hallway printer"},
	})
	form := validForm()
	form.Set("action", "save")
	form.Set("S2G_UI_TITLE", "Hallway printer")
	form.Set("S2G_SMTP_ALLOW_ANONYMOUS", "true")
	resp, body := h.post(h.claimed(), form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, path) || !strings.Contains(body, "Restart scan2graph") {
		t.Errorf("the success page does not say where it went and what to do next:\n%s", body)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600: it holds a client secret", info.Mode().Perm())
	}
	values := loads(t, path)
	if values["S2G_FUTURE_SETTING"] != "kept" {
		t.Error("a key the field table does not know was dropped")
	}
	if values["S2G_ENTRA_CLIENT_SECRET"] != testClientSecret {
		t.Error("the submitted client secret was not written")
	}
	if values["S2G_SMTP_ALLOW_ANONYMOUS"] != "true" {
		t.Error("the checkbox was not written")
	}
	if _, ok := values["S2G_LOG_LEVEL"]; ok {
		t.Error("an empty box was written out instead of being left to the default")
	}
}

// TestSetupKeepsAFileSuppliedValue pins that a blank box never deletes a
// value the file supplies through its S2G_..._FILE spelling: no box can show
// what that file holds, so a save that only touches an unrelated field must
// leave it, and whatever it enables, in place. A secret and an ordinary
// setting reach the same blank box by different paths - fieldSecret's own
// case in values(), and simply having no other spelling set - so both need
// the guarantee.
func TestSetupKeepsAFileSuppliedValue(t *testing.T) {
	for _, tc := range []struct {
		name, fileField, content string
		extra                    map[string]string // other FileValues an unrelated save must also leave alone
	}{
		{"a secret", "S2G_ENTRA_CLIENT_SECRET_FILE", testClientSecret, nil},
		{"a plain setting", "S2G_GRAPH_SENDER_FILE", "scanner@example.com\n",
			map[string]string{"S2G_ALLOWED_RECIPIENT_DOMAINS": "example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			valuePath := filepath.Join(dir, "value")
			if err := os.WriteFile(valuePath, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			fileValues := map[string]string{tc.fileField: valuePath}
			for k, v := range tc.extra {
				fileValues[k] = v
			}
			path := filepath.Join(dir, "scan2graph.env")
			h := newSetupHarness(t, SetupOptions{Path: path, FileValues: fileValues})
			c := h.client()
			h.claim(c)

			// The box is empty because no box can show what is in that other
			// file, so the page has to say that leaving it empty is what keeps
			// it - without ever rendering the value itself.
			name := strings.TrimSuffix(tc.fileField, "_FILE")
			_, body := h.get(c, "/setup")
			if strings.Contains(body, tc.content) {
				t.Fatal("the configured value was rendered into the page")
			}
			field, _, _ := strings.Cut(body[strings.Index(body, `id="`+name+`"`):], "</div>")
			if !strings.Contains(field, "configured — leave empty to keep") {
				t.Errorf("the page does not say that an empty box keeps the configured value:\n%s", field)
			}

			// A save that changes something else entirely.
			form := validForm()
			form.Del(name) // left blank, as a browser sends it
			for k, v := range tc.extra {
				form.Set(k, v)
			}
			form.Set("S2G_UI_TITLE", "Hallway printer")
			form.Set("action", "save")
			if resp, body := h.post(c, form); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Saved") {
				t.Fatalf("status %d, body:\n%s", resp.StatusCode, body)
			}
			values := loads(t, path)
			if values[tc.fileField] != valuePath {
				t.Errorf("%s = %q, want the path it had", tc.fileField, values[tc.fileField])
			}
			if _, ok := values[name]; ok {
				t.Error("both spellings were written, which the next start refuses")
			}
			if values["S2G_UI_TITLE"] != "Hallway printer" {
				t.Errorf("the save that was meant to happen did not: S2G_UI_TITLE = %q", values["S2G_UI_TITLE"])
			}
		})
	}
}

func TestSetupDownloads(t *testing.T) {
	h := newSetupHarness(t, SetupOptions{}) // no Path: download is all there is
	c := h.client()
	h.claim(c)
	_, form := h.get(c, "/setup")
	if strings.Contains(form, `value="save"`) {
		t.Error("a save button is offered although there is nowhere to save to")
	}

	values := validForm()
	values.Set("action", "save") // and it is still a download
	resp, body := h.post(c, values)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="scan2graph.env"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	loads(t, path)
}

// roundTrip writes values the way Save does and reads them back with the real
// parser, so a value that cannot survive the file format shows up here rather
// than as an appliance that starts with something else than the wizard
// validated.
func roundTrip(t *testing.T, values map[string]string) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	if err := writeFile(path, serialize(values)); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	got, err := config.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile of what serialize wrote: %v", err)
	}
	return got
}

// FuzzSetupFileRoundTrip is the untrusted-input property: whatever a browser
// puts in a box, the file the wizard writes must read back as exactly the map
// config.Load just validated. Anything else means the appliance starts with a
// value nobody checked. Two fields share every value, so a collision between
// settings would show up too. The seeds are the corpus a plain `go test` runs
// as ordinary subtests, without needing -fuzz at all.
func FuzzSetupFileRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"", " ", "#", "'", `"`, "a=b", "x\ny", "'q'", "\x00", "\xff",
		"plain",
		"  padded  ",
		"\ttabbed\t",
		"has # hash",
		"#leading",
		"trailing#",
		"''",
		`""`,
		"'quoted'",
		`"quoted"`,
		"it's",
		"ends'",
		"'starts",
		`'"`,
		`"'`,
		"a==b",
		"=leading",
		"export FOO=bar",
		"# comment",
		"line\nbreak",
		"carriage\rreturn",
		"trailing\n",
		"\nleading",
		"null\x00byte",
		"invalid\xffutf8",
		" nbsp ",
		strings.Repeat("x", 4096),
		`{"printer@scanner.local":{"email":false,"web":true,"ocr":true}}`,
		"S2G_ENTRA_CLIENT_SECRET=injected",
		"x\nS2G_SMTP_ALLOW_ANONYMOUS=true",
		"x\rS2G_SMTP_ALLOW_ANONYMOUS=true",
	} {
		f.Add(seed)
	}
	s := &setupServer{}
	f.Fuzz(func(t *testing.T, v string) {
		values, _ := s.values(url.Values{"S2G_UI_TITLE": {v}, "S2G_TEMP_DIR": {v}})
		got := roundTrip(t, values)
		if len(got) != len(values) {
			t.Errorf("input %q: wrote %d settings, read back %d: %#v", v, len(values), len(got), got)
			return
		}
		for k, want := range values {
			if got[k] != want {
				t.Errorf("input %q: %s read back as %q, want %q", v, k, got[k], want)
			}
		}
	})
}

// FuzzSetupFilePreservesTheFileItRead is the round-trip property from the
// other end: the wizard also carries over every setting the file already
// held - including names no box on the form can show - and re-serializes
// them. FuzzSetupFileRoundTrip fuzzes only what a browser types, with an
// empty FileValues, so nothing there exercises that half.
func FuzzSetupFilePreservesTheFileItRead(f *testing.F) {
	for _, seed := range []string{
		"S2G_UI_TITLE=plain\n",
		"S2G_UI_TITLE='  padded  '\n",
		"S2G_ENTRA_AUTHORITY_URL=http://idp.example.test/tenant/v2.0\n",
		"export S2G_UI_TITLE=exported\n",
		"S2G_UI_TITLE=\"has # hash\"\n",
		"A#B=c\n",
		"S2G_UI_TITLE=a\rb\n",
		"S2G_UI_TITLE=''\n",
		"S2G_UI_TITLE=\n",
		"\ufeffS2G_UI_TITLE=bom\n",
		"S2G_PROFILES={\"p@scanner.local\":{\"web\":true}}\n",
		"S2G_UI_TITLE=$HOME\n",
		"export=weird\n",
		"S2G_ENTRA_CLIENT_SECRET_FILE=/run/secrets/s\n",
	} {
		f.Add(seed, "")
	}
	f.Fuzz(func(t *testing.T, file, typed string) {
		path := filepath.Join(t.TempDir(), "in.env")
		if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
			t.Fatal(err)
		}
		fileValues, err := config.ParseFile(path)
		if err != nil {
			t.Skip() // not a configuration file at all
		}
		s := &setupServer{SetupOptions: SetupOptions{FileValues: fileValues}}
		values, _ := s.values(url.Values{"S2G_UI_TITLE": {typed}})
		got := roundTrip(t, values)
		if len(got) != len(values) {
			t.Fatalf("file %q typed %q: wrote %d settings, read back %d: %#v", file, typed, len(values), len(got), got)
		}
		for k, want := range values {
			if got[k] != want {
				t.Fatalf("file %q typed %q: %s read back as %q, want %q", file, typed, k, got[k], want)
			}
		}
	})
}

// TestSetupSecondSaveKeepsTheSecret pins that a submission folds into the
// file as it now stands, not as it was at process start: save a new client
// secret, then save anything else with the secret box left blank - which the
// page itself invites, "leave this empty to keep it" - and the second save
// must keep the secret the first one just wrote.
func TestSetupSecondSaveKeepsTheSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	h := newSetupHarness(t, SetupOptions{
		Path:       path,
		FileValues: map[string]string{"S2G_ENTRA_CLIENT_SECRET": "old-" + testClientSecret},
	})
	c := h.claimed()

	first := validForm() // carries the new secret
	first.Set("action", "save")
	if resp, body := h.post(c, first); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Saved") {
		t.Fatalf("first save: status %d, body:\n%s", resp.StatusCode, body)
	}
	if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != testClientSecret {
		t.Fatalf("after the first save the secret is %q, want the submitted one", got)
	}

	second := validForm()
	second.Del("S2G_ENTRA_CLIENT_SECRET") // left blank, as a browser sends it
	second.Set("S2G_UI_TITLE", "Hallway printer")
	second.Set("action", "save")
	if resp, body := h.post(c, second); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Saved") {
		t.Fatalf("second save: status %d, body:\n%s", resp.StatusCode, body)
	}
	values := loads(t, path)
	if values["S2G_UI_TITLE"] != "Hallway printer" {
		t.Errorf("the second save did not take: S2G_UI_TITLE = %q", values["S2G_UI_TITLE"])
	}
	if got := values["S2G_ENTRA_CLIENT_SECRET"]; got != testClientSecret {
		t.Errorf("the second save reverted the client secret to %q, want the one the first save wrote", got)
	}
}

// TestSetupTestThenSaveKeepsTheTestedSecret is the rotation an operator comes
// to this wizard for: the file holds a secret Entra has stopped accepting,
// they paste the new one, press "Test the connection" and are shown green
// lines. The results render the form back with the password box empty - it is
// a password box - so the Save they press next submits a blank secret, which
// means "keep what is configured". What the wizard just handed back has to be
// what that keeps, or the appliance keeps the expired secret and the page
// says "Saved".
func TestSetupTestThenSaveKeepsTheTestedSecret(t *testing.T) {
	// The secret the tenant accepts from now on; the file still holds the
	// expired one. Both are the one fixture credential with a word in front,
	// the way the other tests here spell a second copy of it.
	const rotated = "rotated-" + testClientSecret
	stub := newMSStub(t)
	stub.secret = rotated

	form, file := testForm(stub)
	file["S2G_ENTRA_CLIENT_SECRET"] = testClientSecret // expired, as the file has it

	path := filepath.Join(t.TempDir(), setupFileName)
	h := newSetupHarness(t, SetupOptions{FileValues: file, Path: path})
	c := h.claimed()

	// The operator pastes the new secret and presses Test.
	form.Set("S2G_ENTRA_CLIENT_SECRET", rotated)
	_, body := h.post(c, form)
	if strings.Contains(body, `class="fail"`) {
		t.Fatalf("the rotated secret did not pass its own check: %s", body)
	}
	if !strings.Contains(body, `id="S2G_ENTRA_CLIENT_SECRET" name="S2G_ENTRA_CLIENT_SECRET" value=""`) {
		t.Fatal("the results page no longer empties the client secret box; this test is out of date")
	}

	// The browser submits that empty box on the next press, along with the
	// hidden field naming the page it is on, so this is Save exactly as the
	// operator performs it.
	form.Set("form", h.formID(body))
	form.Set("S2G_ENTRA_CLIENT_SECRET", "")
	form.Set("action", "save")
	if _, body := h.post(c, form); !strings.Contains(body, "Saved") {
		t.Fatalf("the save did not go through: %s", body)
	}
	if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != rotated {
		t.Errorf("the file holds %q, want the secret the operator tested; "+
			"a green Test followed by Save wrote the expired one back", got)
	}
}

// TestSetupClaim is the gate, whole: an unclaimed wizard offers the claim
// page to anybody, and the browser that presses "Start configuration" takes
// it away from everybody. Claiming on that press rather than on the first
// save is what leaves nothing to re-check later - the door shuts while there
// is still, by construction, nothing behind it to disclose, so no request can
// be admitted to an appliance with nothing to lose and answered by one with
// something.
func TestSetupClaim(t *testing.T) {
	t.Run("two simultaneous presses have exactly one winner", func(t *testing.T) {
		// Driven directly rather than over a socket, for the reason
		// TestSetupConcurrentSavesAndReads gives: httptest.Server would order
		// these two against each other itself.
		h := NewSetup(SetupOptions{Getenv: noEnv})
		type press struct {
			code    int
			cookies []*http.Cookie
		}
		presses := make([]press, 2)
		gun := make(chan struct{})
		var wg sync.WaitGroup
		for i := range presses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := httptest.NewRecorder()
				<-gun
				h.ServeHTTP(rec, httptest.NewRequest("POST", "/setup/start", nil))
				presses[i] = press{rec.Code, rec.Result().Cookies()}
			}()
		}
		close(gun)
		wg.Wait()

		won := 0
		for _, p := range presses {
			switch p.code {
			case http.StatusSeeOther:
				won++
				if len(p.cookies) != 1 || p.cookies[0].Name != setupCookie {
					t.Errorf("the press that won was handed %v, want the one %s", p.cookies, setupCookie)
				}
			case http.StatusNotFound:
				if len(p.cookies) != 0 {
					t.Errorf("the press that lost was handed a cookie anyway: %v", p.cookies)
				}
			default:
				t.Errorf("status %d, want 303 or 404", p.code)
			}
		}
		if won != 1 {
			t.Errorf("%d of two simultaneous presses claimed the wizard, want exactly 1", won)
		}
	})

	t.Run("a look claims nothing", func(t *testing.T) {
		h := newSetupHarness(t, SetupOptions{Path: filepath.Join(t.TempDir(), "scan2graph.env")})
		// Nothing a browser does on its own - a prefetch, an omnibox guess,
		// the operator opening the page twice - takes the wizard: only the
		// press does, so two browsers still both see the offer.
		for i, c := range []*http.Client{h.client(), h.client()} {
			resp, body := h.get(c, "/setup")
			if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Start configuration") {
				t.Fatalf("browser %d: GET /setup on an unclaimed wizard: status %d, body:\n%s", i, resp.StatusCode, body)
			}
			if len(resp.Cookies()) != 0 {
				t.Errorf("browser %d: a GET minted a token: %v", i, resp.Cookies())
			}
			if strings.Contains(body, "S2G_ENTRA_TENANT_ID") {
				t.Errorf("browser %d: the claim page rendered the form it stands in front of", i)
			}
		}
	})

	t.Run("the browser that claimed it keeps it, and nobody else gets in", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "scan2graph.env")
		h := newSetupHarness(t, SetupOptions{Path: path}) // a fresh install: no token
		operator := h.client()
		h.claim(operator)

		// The cookie that press set is the key from here on - for the form,
		// and for the save that writes the client secret.
		resp, body := h.get(operator, "/setup")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "S2G_ENTRA_TENANT_ID") {
			t.Fatalf("the form, to the browser that claimed it: status %d, body:\n%s", resp.StatusCode, body)
		}
		form := validForm()
		form.Set("action", "save")
		if resp, body := h.post(operator, form); resp.StatusCode != http.StatusOK ||
			!strings.Contains(body, "Saved") || strings.Contains(body, testClientSecret) {
			t.Fatalf("the save: status %d, body:\n%s", resp.StatusCode, body)
		}
		if resp, _ := h.get(operator, "/setup"); resp.StatusCode != http.StatusOK {
			t.Errorf("the browser that claimed the wizard, after saving: status %d, want 200", resp.StatusCode)
		}

		stranger := h.client() // another browser on the LAN, with no cookie
		if resp, body := h.get(stranger, "/setup"); resp.StatusCode != http.StatusNotFound ||
			strings.Contains(body, testClientSecret) {
			t.Errorf("GET /setup from a second browser: status %d, body:\n%s", resp.StatusCode, body)
		}
		if resp := h.start(stranger); resp.StatusCode != http.StatusNotFound {
			t.Errorf("a second press of Start configuration: status %d, want 404", resp.StatusCode)
		}
		// Download is what would leak: a blank secret box keeps the secret
		// the file holds, so posting the form straight back hands the whole
		// file over to whoever posted it.
		blank := validForm()
		blank.Del("S2G_ENTRA_CLIENT_SECRET")
		blank.Set("action", "download")
		resp, body = h.post(stranger, blank)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST /setup (download) from a second browser: status %d, want 404", resp.StatusCode)
		}
		if strings.Contains(body, testClientSecret) {
			t.Error("an anonymous download returned the saved client secret")
		}
	})

	t.Run("a token-gated wizard is never claimed", func(t *testing.T) {
		// The marker path: main constructed this one with a hash already, so
		// there is no claim page and nothing mints a hash over the top of it.
		h := newSetupHarness(t, SetupOptions{TokenHash: sha256Of(setupToken)})
		stranger := h.client()
		for _, path := range []string{"/", "/setup"} {
			if resp, _ := h.get(stranger, path); resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
			}
		}
		if resp := h.start(stranger); resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST /setup/start: status %d, want 404", resp.StatusCode)
		}
		// The token that was printed still opens it, which it would not if
		// any of the above had replaced the hash.
		operator := h.client()
		if resp, _ := h.get(operator, "/setup?t="+setupToken); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("the printed token: status %d, want 303", resp.StatusCode)
		}
		if resp, body := h.get(operator, "/setup"); resp.StatusCode != http.StatusOK ||
			!strings.Contains(body, "S2G_ENTRA_TENANT_ID") {
			t.Errorf("the form, with the marker's token: status %d, body:\n%s", resp.StatusCode, body)
		}
	})
}

// readAll is the body, drained and closed, for the tests below that read one
// from a goroutine where t.Fatal is not available: an unreadable body is
// simply an empty string, which no assertion here mistakes for a leak.
func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// TestSetupClaimRaceShowsTheFormToANonHolder is the one window in which the
// gate moves underneath a request in flight: authenticate reads the hash once
// and lets an unclaimed request through, and the handler behind it must not
// read it a second time and hand the form - seeded from the configuration
// file - to a browser that holds no cookie and gets 404 from its next request
// on. Asking holder, which is false for an unclaimed wizard too, keeps the
// claim page exactly where it was and closes the window.
func TestSetupClaimRaceShowsTheFormToANonHolder(t *testing.T) {
	for round := range 200 {
		h := newSetupHarness(t, SetupOptions{
			FileValues: map[string]string{"S2G_GRAPH_SENDER": "scanner@example.com"},
		})
		anon := h.client()
		claimer := h.client()

		var wg sync.WaitGroup
		leaked := make(chan struct{}, 1)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 64 {
					resp, err := anon.Get(h.ts.URL + "/setup")
					if err != nil {
						return
					}
					if strings.Contains(readAll(resp), "scanner@example.com") {
						select {
						case leaked <- struct{}{}:
						default:
						}
						return
					}
				}
			}()
		}
		h.claim(claimer)
		wg.Wait()
		select {
		case <-leaked:
			t.Fatalf("round %d: a browser that never claimed the wizard was served the form, "+
				"with the configuration file's values in it", round)
		default:
		}
	}
}

// postForm is one submission as a browser sends it, ready to be served
// directly rather than over a socket.
func postForm(body io.Reader) *http.Request {
	r := httptest.NewRequest("POST", "/setup", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestSetupWritesJSONUnquoted pins quoteValue's rule for a JSON-valued
// setting: it must never come out wrapped, because `docker run --env-file`
// strips nothing, so a quoted value would reach the appliance with the quotes
// still on and fail as invalid JSON. Reading the file back is the whole check
// - no Docker involved, since what docker does with the line is "take it
// verbatim".
func TestSetupWritesJSONUnquoted(t *testing.T) {
	const profiles = `{"scan-web@scanner.local":{"email":false,"web":true,"ocr":false}}`
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	h := newSetupHarness(t, SetupOptions{Path: path})
	form := validForm()
	form.Set("S2G_PROFILES", profiles)
	form.Set("action", "save")
	if resp, body := h.post(h.claimed(), form); resp.StatusCode != http.StatusOK ||
		!strings.Contains(body, "Saved") {
		t.Fatalf("status %d, body:\n%s", resp.StatusCode, body)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "S2G_PROFILES=" + profiles + "\n"; !strings.Contains(string(written), want) {
		t.Errorf("the JSON value did not come out verbatim; the file says:\n%s", written)
	}
	if got := loads(t, path)["S2G_PROFILES"]; got != profiles {
		t.Errorf("S2G_PROFILES read back as %q", got)
	}
}

// TestSetupChoiceKeepsAnUnlistedValue pins the defect that a <select> silently
// dropped a value it had no option for: S2G_LOG_LEVEL=warning is valid to the
// loader, so the box showed "(default)" and the next save deleted a setting
// nobody had touched.
func TestSetupChoiceKeepsAnUnlistedValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	h := newSetupHarness(t, SetupOptions{
		Path:       path,
		FileValues: map[string]string{"S2G_LOG_LEVEL": "warning"},
	})
	c := h.client()
	h.claim(c)
	_, body := h.get(c, "/setup")
	if !strings.Contains(body, `<option value="warning" selected>warning</option>`) {
		t.Errorf("the configured log level is not an option the box can show:\n%s",
			body[strings.Index(body, `id="S2G_LOG_LEVEL"`):][:400])
	}

	// And what the browser then submits - the option that was selected -
	// survives the save rather than being deleted.
	form := validForm()
	form.Set("S2G_LOG_LEVEL", "warning")
	form.Set("action", "save")
	if resp, body := h.post(c, form); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Saved") {
		t.Fatalf("status %d, body:\n%s", resp.StatusCode, body)
	}
	if got := loads(t, path)["S2G_LOG_LEVEL"]; got != "warning" {
		t.Errorf("S2G_LOG_LEVEL = %q after the save, want it kept", got)
	}
}

// TestSetupErrorsUseTheLabel: the loader names the setting, the operator reads
// a label. Stripping the name outright left "is required because ..." with no
// subject at all, so view substitutes the label instead.
// A submitted value can carry a setting name - a text box takes anything -
// and that must not decide where its own error appears. Attribution reads the
// name the loader's message opens with, not any name the line happens to
// contain.
func TestSetupErrorStaysUnderItsOwnBox(t *testing.T) {
	h := newSetupHarness(t, SetupOptions{Path: filepath.Join(t.TempDir(), "scan2graph.env")})
	form := validForm()
	form.Set("S2G_JOB_TTL", "S2G_HTTP_ADDR") // invalid, and it names another setting
	_, body := h.post(h.claimed(), form)
	field, ok := strings.CutPrefix(body[strings.Index(body, `<div class="field bad">`):], `<div class="field bad">`)
	if !ok {
		t.Fatal("no field is marked bad")
	}
	field, _, _ = strings.Cut(field, "</div>")
	if !strings.Contains(field, `id="S2G_JOB_TTL"`) || !strings.Contains(field, "invalid duration") {
		t.Errorf("the error is not under the box that caused it:\n%s", field)
	}
	if strings.Contains(body, "problems") {
		t.Error("the error was pushed above the form by a value that merely names another setting")
	}
}

func TestSetupErrorsUseTheLabel(t *testing.T) {
	h := newSetupHarness(t, SetupOptions{Path: filepath.Join(t.TempDir(), "scan2graph.env")})
	form := validForm()
	form.Del("S2G_ENTRA_CLIENT_ID") // required, and the message says why
	_, body := h.post(h.claimed(), form)
	if !strings.Contains(body, "Application (client) ID is required") {
		t.Errorf("the required-field message has no subject:\n%s", body)
	}
	if strings.Contains(body, ">S2G_ENTRA_CLIENT_ID is required") ||
		strings.Contains(body, ">is required") {
		t.Errorf("the error still repeats the setting name, or lost its subject:\n%s", body)
	}
}

// TestSetupConcurrentSavesAndReads is the race the wizard's mutable state
// introduces: a successful save replaces the map every other request
// goroutine renders the form from, while every one of them also reads the
// token hash to authenticate. `go test -race` is the assertion. The hash
// itself is written once, by the claim below, and never again - which is why
// none of this needs a second answer at any later boundary.
//
// One browser claims the wizard and every request here carries its cookie,
// because that is the only shape this can have: a claimed wizard answers
// everything else 404, and an unclaimed one has no form to save from.
//
// The handler is driven directly rather than over a socket: httptest.Server
// locks a mutex of its own around every request it tracks, which orders these
// goroutines against each other and would hide the very race this is for.
func TestSetupConcurrentSavesAndReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	h := NewSetup(SetupOptions{
		Getenv:     noEnv,
		Path:       path,
		FileValues: map[string]string{"S2G_ENTRA_CLIENT_SECRET": "old-" + testClientSecret},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/setup/start", nil))
	key := rec.Result().Cookies()
	if rec.Code != http.StatusSeeOther || len(key) != 1 {
		t.Fatalf("claiming the wizard: status %d with cookies %v", rec.Code, key)
	}
	serve := func(what string, i int, r *http.Request) {
		r.AddCookie(key[0])
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("%s %d: status %d, want 200", what, i, rec.Code)
		}
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 3 {
				form := validForm()
				form.Set("S2G_UI_TITLE", "Hallway printer "+strconv.Itoa(i))
				form.Set("action", "save")
				serve("save", i, postForm(strings.NewReader(form.Encode())))
			}
		}()
		go func() {
			defer wg.Done()
			for range 3 {
				serve("read", i, httptest.NewRequest("GET", "/setup", nil))
			}
		}()
	}
	wg.Wait()
	// Whichever save landed last, the secret it wrote is the new one: no
	// concurrent reader can put the start-up value back.
	if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != testClientSecret {
		t.Errorf("the client secret is %q, want the one the saves submitted", got)
	}
}

// TestSetupTwoPagesKeepTheirOwnSecret is what the form id is for. Two pages
// are open at once - a second tab, or the Back button - and a different
// secret has been typed into each, which "Test the connection" hands back
// with the password box empty, because it always is. The Save that follows
// means "keep what is configured", and what that keeps is what was typed into
// the page the operator pressed it on: the other page is not an older answer
// to be ordered against, it is a different question. Both save orders are
// driven, because either page can be the one that rendered last.
// A save landing while a check is still running leaves that check's page
// holding an answer to a file that no longer exists. Saving from it must not
// put the pre-save secret back: the id proves which page the values came
// from, not that they are still about the current file.
func TestSetupSaveDuringATestWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	s := &setupServer{SetupOptions: SetupOptions{Path: path, Getenv: noEnv}}

	// The slow test folds first, and its results page will carry this id.
	slow, slowFile := s.values(validForm())
	slowPage := "the-slow-test's-page"

	// The other tab saves a rotated secret while that test is still waiting.
	rotated := validForm()
	rotated.Set("S2G_ENTRA_CLIENT_SECRET", "rotated-"+testClientSecret)
	saved, _ := s.values(rotated)
	if err := s.save(saved); err != nil {
		t.Fatal(err)
	}

	// Only now does the test answer and render its page.
	s.remember(slowPage, slow, slowFile)

	// Saving from that page, with the box blank as it must be.
	blank := validForm()
	blank.Del("S2G_ENTRA_CLIENT_SECRET")
	blank.Set("form", slowPage)
	next, _ := s.values(blank)
	if got := next["S2G_ENTRA_CLIENT_SECRET"]; got != "rotated-"+testClientSecret {
		t.Errorf("a blank box folded into %q, want the secret the save wrote", got)
	}
}

func TestSetupTwoPagesKeepTheirOwnSecret(t *testing.T) {
	secrets := [2]string{"first-" + testClientSecret, "second-" + testClientSecret}
	for from := range secrets {
		t.Run("saving from page "+strconv.Itoa(from+1), func(t *testing.T) {
			stub := newMSStub(t)
			form, file := testForm(stub)
			file["S2G_ENTRA_CLIENT_SECRET"] = "stale-" + testClientSecret
			path := filepath.Join(t.TempDir(), setupFileName)
			h := newSetupHarness(t, SetupOptions{FileValues: file, Path: path})
			c := h.claimed()

			var page [2]string // what each render calls the page it hands back
			for i, secret := range secrets {
				form.Set("S2G_ENTRA_CLIENT_SECRET", secret)
				_, body := h.post(c, form)
				page[i] = h.formID(body)
			}
			if page[0] == page[1] {
				t.Fatal("both renders carry the same form id, so neither page can have an answer of its own")
			}

			save := validForm()
			save.Del("S2G_ENTRA_CLIENT_SECRET") // as the empty box arrives
			save.Set("action", "save")
			save.Set("form", page[from])
			if _, body := h.post(c, save); !strings.Contains(body, "Saved") {
				t.Fatalf("the save did not go through: %s", body)
			}
			if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != secrets[from] {
				t.Fatalf("the file holds %q, want what was typed into the page the save came from", got)
			}

			// That save answers for both pages: the other one is still on
			// screen, and a press on it now keeps what is in the file rather
			// than putting its own secret back over a completed save.
			save.Set("form", page[1-from])
			if _, body := h.post(c, save); !strings.Contains(body, "Saved") {
				t.Fatalf("the save from the other page did not go through: %s", body)
			}
			if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != secrets[from] {
				t.Errorf("a save from the other page wrote %q; a save clears what every page remembered", got)
			}
		})
	}
}

// Two overlapping saves must leave the file and what the wizard reads back
// agreeing: landing on disk in one order and in memory in the other would let
// a later blank box - which the page invites for a configured secret - write
// the loser's value over the winner's.
func TestSetupOverlappingSavesAgreeWithTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	h := newSetupHarness(t, SetupOptions{Path: path})
	c := h.claimed()

	for range 20 {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, title := range []string{"one", "two"} {
			form := validForm()
			form.Set("S2G_UI_TITLE", title)
			form.Set("action", "save")
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				h.post(c, form)
			}()
		}
		close(start)
		wg.Wait()

		// Whichever won, the file and the map the next save folds into must
		// be the same submission: fold a blank-secret save in and see it come
		// back unchanged.
		onDisk := loads(t, path)["S2G_UI_TITLE"]
		blank := validForm()
		blank.Set("S2G_UI_TITLE", onDisk)
		blank.Del("S2G_ENTRA_CLIENT_SECRET") // kept from whatever is published
		blank.Set("action", "save")
		if resp, body := h.post(c, blank); resp.StatusCode != http.StatusOK {
			t.Fatalf("follow-up save: status %d, body:\n%s", resp.StatusCode, body)
		}
		if got := loads(t, path)["S2G_ENTRA_CLIENT_SECRET"]; got != testClientSecret {
			t.Fatalf("a blank box restored a stale secret %q after overlapping saves", got)
		}
	}
}

// TestSetupConcurrentSavesAreRaceFree drives real concurrent saves and reads
// over a socket, so -race sees FileValues being replaced while other
// goroutines render the form from it. It asserts only that the file the
// wizard leaves behind is one whole submission, never a blend of two.
func TestSetupConcurrentSavesAreRaceFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env")
	h := newSetupHarness(t, SetupOptions{Path: path, TokenHash: sha256Of(setupToken)})
	c := h.client()
	// The marker's token, once in the address bar and in the jar from here on.
	if resp, _ := h.get(c, "/setup?t="+setupToken); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("presenting the printed token: status %d, want 303", resp.StatusCode)
	}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			form := validForm()
			form.Set("S2G_UI_TITLE", "browser-"+string(rune('a'+i)))
			form.Set("action", "save")
			for range 10 {
				resp, err := c.PostForm(h.ts.URL+"/setup", form)
				if err != nil {
					return
				}
				readAll(resp)
				resp, err = c.Get(h.ts.URL + "/setup")
				if err != nil {
					return
				}
				readAll(resp)
			}
		}()
	}
	wg.Wait()
	got, err := config.ParseFile(path)
	if err != nil {
		t.Fatalf("the file the wizard left behind does not parse: %v", err)
	}
	if got["S2G_ENTRA_CLIENT_SECRET"] != testClientSecret {
		t.Errorf("client secret is %q, want the one every submission carried", got["S2G_ENTRA_CLIENT_SECRET"])
	}
	if !strings.HasPrefix(got["S2G_UI_TITLE"], "browser-") {
		t.Errorf("S2G_UI_TITLE is %q, want one browser's whole submission", got["S2G_UI_TITLE"])
	}
}

// TestSetupConcurrentClaimsHaveOneWinner is TestSetupClaim's two presses at
// sixteen, over a socket and repeatedly: the look and the mint are one
// critical section, so every press but one must find the wizard already
// claimed and answer 404 without a cookie.
func TestSetupConcurrentClaimsHaveOneWinner(t *testing.T) {
	for range 50 {
		h := newSetupHarness(t, SetupOptions{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var tokens []string
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := h.client().PostForm(h.ts.URL+"/setup/start", nil)
				if err != nil {
					return
				}
				readAll(resp)
				for _, c := range resp.Cookies() {
					if c.Name == setupCookie && c.Value != "" {
						mu.Lock()
						tokens = append(tokens, c.Value)
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
		if len(tokens) != 1 {
			t.Fatalf("%d browsers were handed a setup cookie, want exactly 1", len(tokens))
		}
	}
}
