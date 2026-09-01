package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// testClientSecret is as fake as it looks: the only credential this file
// invents, reused everywhere one is needed.
const testClientSecret = "not-a-real-client-secret"

// validForm is the smallest submission config.Load accepts on its own: an
// Entra app registration, plus the public URL that turns the web UI on.
func validForm() url.Values {
	return url.Values{
		"S2G_ENTRA_TENANT_ID":     {"00000000-0000-0000-0000-000000000000"},
		"S2G_ENTRA_CLIENT_ID":     {"00000000-0000-0000-0000-000000000001"},
		"S2G_ENTRA_CLIENT_SECRET": {testClientSecret},
		"S2G_PUBLIC_BASE_URL":     {"https://scan2graph.example.com"},
	}
}

// TestWizardValidatesSubmittedValue pins that the wizard validates a
// submission against itself, not against the stale file value a setting
// already held: a corrected typo must be accepted rather than reported
// broken by the very value it just replaced. It drives the real wizard over
// a real socket, exactly as a browser would, against a real (broken)
// configuration file already on disk.
func TestWizardValidatesSubmittedValue(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	path := filepath.Join(t.TempDir(), "scan2graph.env")
	// S2G_LOG_LEVEL=loud is invalid, and nothing in the process environment
	// mentions it - only the file, which the form below is about to
	// correct, holds it.
	body := "S2G_LOG_LEVEL=loud\nS2G_HTTP_ADDR=" + addr + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	go wizard(path, nil)

	base := "http://" + addr + "/setup"
	var resp *http.Response
	for range 100 {
		resp, err = http.Get(base)
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("wizard never came up: %v", err)
	}

	// One browser, keeping the cookie: an unclaimed wizard shows the claim
	// page and refuses everything else, so pressing Start comes first.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar}
	if resp, err = c.PostForm(base+"/start", nil); err != nil {
		t.Fatalf("POST /setup/start: %v", err)
	}
	resp.Body.Close()

	form := validForm()
	form.Set("S2G_LOG_LEVEL", "info") // the correction
	form.Set("action", "download")
	resp, err = c.PostForm(base, form)
	if err != nil {
		t.Fatalf("POST /setup: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Disposition") == "" {
		t.Fatalf("the corrected S2G_LOG_LEVEL was rejected - still validating against "+
			"the file's stale value instead of the submission:\n%s", got)
	}
	if !strings.Contains(string(got), "S2G_LOG_LEVEL=info") {
		t.Errorf("the downloaded file does not contain the corrected value:\n%s", got)
	}
}

// only answers for one setting: a getenv that answers for every name would
// have S2G_X and S2G_X_FILE both set, which the resolver refuses outright.
func only(name, value string) func(string) string {
	return func(n string) string {
		if n == name {
			return value
		}
		return ""
	}
}

// The one typo the repair tool has to survive: a marker-armed start spends
// its marker before it binds, so an address that will not listen would take
// the printed token with it and read the same way on every retry. Only
// binding can tell - a name that does not resolve is shaped perfectly well.
func TestSetupListenerFallsBack(t *testing.T) {
	for _, addr := range []string{"not-an-address", ":badport", "does-not-exist.invalid:9000"} {
		ln, got := setupListener(only("S2G_HTTP_ADDR", addr), "127.0.0.1:0")
		ln.Close()
		if got == addr {
			t.Errorf("setupListener(%q) kept an address it cannot listen on", addr)
		}
	}
	// A usable address is left alone, port and all.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	free.Close()
	ln, got := setupListener(only("S2G_HTTP_ADDR", addr), "127.0.0.1:0")
	defer ln.Close()
	if got != addr {
		t.Errorf("setupListener(%q) = %q, want it left alone", addr, got)
	}
}

func TestSetupURL(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }

	if got, want := setupURL(getenv, ":8080", ""), "http://localhost:8080/setup"; got != want {
		t.Errorf("setupURL = %q, want %q", got, want)
	}
	if got, want := setupURL(getenv, ":8080", "tok123"), "http://localhost:8080/setup?t=tok123"; got != want {
		t.Errorf("setupURL = %q, want %q", got, want)
	}

	// A configured public base URL wins over deriving one from the listen
	// address, trailing slash and all.
	env["S2G_PUBLIC_BASE_URL"] = "https://scan2graph.example.com/"
	if got, want := setupURL(getenv, ":8080", ""), "https://scan2graph.example.com/setup"; got != want {
		t.Errorf("setupURL = %q, want %q", got, want)
	}

	// But only a value the appliance would actually accept is a link. A
	// misconfigured public base URL is exactly what someone runs setup to
	// repair, and printing it back - as the only copy of the one-shot token -
	// would send the operator somewhere nothing serves, while the wizard
	// itself binds and looks healthy on localhost.
	for _, bad := range []string{"/just/a/path", "https://scan2graph.example.com/scans", "ftp://scan2graph.example.com", "not a url"} {
		env["S2G_PUBLIC_BASE_URL"] = bad
		if got, want := setupURL(getenv, ":8080", "tok123"), "http://localhost:8080/setup?t=tok123"; got != want {
			t.Errorf("setupURL with S2G_PUBLIC_BASE_URL=%q = %q, want the localhost fallback %q", bad, got, want)
		}
	}
}

// runMainEnv, when present, makes this test binary re-execute as the real
// command: TestMain hands its value to main() as the argument list and never
// reaches m.Run(). It is how the run-mode dispatch below is exercised as
// scan2graph itself - os.Exit, stderr banner and all - rather than as a
// function call that cannot exit.
const runMainEnv = "S2G_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if v, ok := os.LookupEnv(runMainEnv); ok {
		os.Args = append([]string{"scan2graph"}, strings.Fields(v)...)
		main()
		return
	}
	os.Exit(m.Run())
}

// freePort returns an address nothing is listening on, for a child process to
// bind.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// mainProc is one run of the real command in its own process, with an
// environment of exactly what the test sets - nothing of the test runner's
// leaks in, so "nothing at all is configured" really means nothing. Its two
// streams go to two files rather than one, because which of them the setup
// token comes out on is itself something to assert.
type mainProc struct {
	cmd              *exec.Cmd
	outPath, errPath string // where its two streams go, readable while it runs
	t                *testing.T
}

func startMain(t *testing.T, args string, env map[string]string) *mainProc {
	t.Helper()
	dir := t.TempDir()
	p := &mainProc{t: t, outPath: filepath.Join(dir, "stdout.log"), errPath: filepath.Join(dir, "stderr.log")}
	out, err := os.Create(p.outPath)
	if err != nil {
		t.Fatal(err)
	}
	errOut, err := os.Create(p.errPath)
	if err != nil {
		t.Fatal(err)
	}
	p.cmd = exec.Command(os.Args[0])
	p.cmd.Stdout, p.cmd.Stderr = out, errOut
	p.cmd.Env = []string{runMainEnv + "=" + args}
	for k, v := range env {
		p.cmd.Env = append(p.cmd.Env, k+"="+v)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		out.Close()
		errOut.Close()
	})
	return p
}

// output is everything the command wrote to stderr: its banners, its startup
// failures, and the setup token, which deliberately goes nowhere else.
func (p *mainProc) output() string { return p.read(p.errPath) }

// stdout is the stream a launcher or a wrapper may well have redirected, so
// nothing the operator has to see may come out here.
func (p *mainProc) stdout() string { return p.read(p.outPath) }

func (p *mainProc) read(path string) string {
	p.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		p.t.Fatal(err)
	}
	return string(b)
}

// wait runs the command to completion and returns its exit code and output.
func (p *mainProc) wait() (int, string) {
	p.t.Helper()
	err := p.cmd.Wait()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		p.t.Fatalf("waiting for the command: %v", err)
	}
	return code, p.output()
}

// waitListening blocks until the child answers on addr, or fails the test.
func (p *mainProc) waitListening(addr string) {
	p.t.Helper()
	for range 200 {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("nothing listening on %s after 4s; output:\n%s", addr, p.output())
}

// TestDefaultModeDispatch is the security-shaped decision in main: with no
// subcommand, only a genuinely blank appliance may open the wizard without a
// token. A half-configured one - the secret file that went missing - has to
// exit, because a plain "Load failed, open the wizard" would turn a broken
// appliance into an unauthenticated configuration editor on the LAN.
// web.AnyConfigured's own test proves the helper works; this proves main
// actually asks it, and at the right point in the switch.
func TestDefaultModeDispatch(t *testing.T) {
	const identity = "S2G_ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000\n" +
		"S2G_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000001\n" +
		"S2G_PUBLIC_BASE_URL=https://scan2graph.example.com\n"

	t.Run("half configured exits instead of opening the wizard", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "scan2graph.env")
		// Everything but the secret, whose file is not there - the exact
		// shape of a Docker secret that failed to mount.
		body := identity + "S2G_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "gone") + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := startMain(t, "", map[string]string{
			"S2G_CONFIG_FILE": path,
			"S2G_HTTP_ADDR":   freePort(t),
		}).wait()
		if code != 1 {
			t.Errorf("exit code %d, want 1", code)
		}
		if !strings.Contains(out, "invalid configuration") {
			t.Errorf("output does not report the configuration error:\n%s", out)
		}
		if strings.Contains(out, "Setup wizard") {
			t.Errorf("a half-configured appliance opened the wizard:\n%s", out)
		}
	})

	// A cosmetic setting - the listen address, a log level - must not by
	// itself make a genuinely blank appliance refuse to open its first-boot
	// wizard: "there is something here to protect" is the rule, and a port
	// number is not that.
	t.Run("a blank appliance opens the wizard unauthenticated", func(t *testing.T) {
		addr := freePort(t)
		p := startMain(t, "", map[string]string{
			"S2G_CONFIG_FILE": filepath.Join(t.TempDir(), "scan2graph.env"), // not there yet
			"S2G_HTTP_ADDR":   addr,
			"S2G_LOG_LEVEL":   "info",
		})
		p.waitListening(addr)
		out := p.output()
		if !strings.Contains(out, "Setup wizard") || !strings.Contains(out, "No token yet") {
			t.Errorf("a blank appliance did not open the unauthenticated wizard:\n%s", out)
		}
		resp, err := http.Get("http://" + addr + "/setup")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /setup: status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("a marker gates the wizard and is gone before the listener opens", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "scan2graph.env")
		// A configuration that loads perfectly well: the marker still wins,
		// which is what makes "revisit the settings" possible at all.
		if err := os.WriteFile(path, []byte(identity+
			"S2G_ENTRA_CLIENT_SECRET="+testClientSecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		addr := freePort(t)
		env := map[string]string{"S2G_CONFIG_FILE": path, "S2G_HTTP_ADDR": addr}

		mint := startMain(t, "setup-next-start", env)
		code, out := mint.wait()
		if code != 0 {
			t.Fatalf("setup-next-start exit code %d, want 0; output:\n%s", code, out)
		}
		_, token, ok := strings.Cut(strings.TrimSpace(out), "?t=")
		if !ok {
			t.Fatalf("setup-next-start printed no token URL:\n%s", out)
		}
		if s := mint.stdout(); s != "" {
			t.Errorf("the token went to stdout, where a redirect loses it:\n%s", s)
		}
		if _, err := os.Stat(path + ".setup"); err != nil {
			t.Fatalf("setup-next-start left no marker: %v", err)
		}

		p := startMain(t, "", env)
		p.waitListening(addr)
		// Consumed before anything could serve, so a crash loop cannot
		// re-open the wizard forever.
		if _, err := os.Stat(path + ".setup"); !os.IsNotExist(err) {
			t.Errorf("the marker survived into a listening wizard (stat err = %v)", err)
		}
		if out := p.output(); !strings.Contains(out, "one-shot token is required") {
			t.Errorf("the wizard does not say a token gates it:\n%s", out)
		}
		if strings.Contains(p.output(), token) {
			t.Error("the token was printed again by the start that consumed it")
		}

		// No redirect following and no cookie jar: each request stands or
		// falls on what it presents.
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		base := "http://" + addr
		if resp, err := c.Get(base + "/setup"); err != nil {
			t.Fatal(err)
		} else if resp.Body.Close(); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET /setup without the token: status %d, want 404", resp.StatusCode)
		}
		if resp, err := c.Get(base + "/setup?t=" + token); err != nil {
			t.Fatal(err)
		} else if resp.Body.Close(); resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET /setup with the token: status %d, want 303", resp.StatusCode)
		}
	})
}

// TestSubcommandAfterAFlagIsNotDropped pins that a flag written before the
// subcommand cannot silently change the run mode. flag stops at the first
// non-flag argument and main only ever looks at os.Args[1], so
//
//	scan2graph --config /etc/scan2graph/scan2graph.env serve
//
// used to run the *default* mode with "serve" thrown away - and the two
// diverge in the dangerous direction on a path that cannot be read: serve
// refuses to start, while the default mode takes a missing file for a fresh
// install and opens the unauthenticated wizard on S2G_HTTP_ADDR, which is
// :8080 on every interface unless the operator set it. configSource refuses
// the leftover argument instead, so no run is ever the mode nobody asked for.
func TestSubcommandAfterAFlagIsNotDropped(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "scan2graph.env")
	p := startMain(t, "--config "+missing+" serve", map[string]string{
		"S2G_HTTP_ADDR": freePort(t),
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(p.output(), "unexpected argument") {
		if strings.Contains(p.output(), "Setup wizard") {
			t.Fatalf("%q ran the default mode and opened the wizard instead of refusing:\n%s",
				"--config <missing> serve", p.output())
		}
		time.Sleep(50 * time.Millisecond)
	}
	code, out := p.wait()
	if code != 1 || !strings.Contains(out, `unexpected argument "serve"`) {
		t.Errorf("exit code %d, want 1 naming the argument that was dropped; output:\n%s", code, out)
	}
}

// TestSetupModeToken is the second security-shaped decision: "setup" serves
// the wizard on every interface, and the form's Download button hands back the
// whole configuration file, client secret included. So it may only stay
// unauthenticated while there is nothing in that file worth taking - which is
// the same rule, over the same values, that the default mode's first boot
// turns on.
func TestSetupModeToken(t *testing.T) {
	const identity = "S2G_ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000\n" +
		"S2G_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000001\n" +
		"S2G_PUBLIC_BASE_URL=https://scan2graph.example.com\n"

	// write puts body in a fresh directory and returns the path; an empty
	// body means the file is not there at all.
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "scan2graph.env")
		if body != "" {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}

	// The token itself gating a request is TestDefaultModeDispatch's fullest
	// path; this only has to see the banner ask for one.
	t.Run("a file holding a secret demands a token", func(t *testing.T) {
		addr := freePort(t)
		path := write(t, identity+"S2G_ENTRA_CLIENT_SECRET="+testClientSecret+"\n")
		p := startMain(t, "setup", map[string]string{"S2G_CONFIG_FILE": path, "S2G_HTTP_ADDR": addr})
		p.waitListening(addr)
		out := p.output()
		if !strings.Contains(out, "one-shot token is required") {
			t.Fatalf("setup over a configured file served an unauthenticated wizard:\n%s", out)
		}
		// Anchored on the URL itself: the banner beside it spells out the
		// "?t=TOKEN" shape in prose, and that is not a token.
		if !regexp.MustCompile(`https?://\S+/setup\?t=\S+`).MatchString(out) {
			t.Fatalf("setup printed no token URL to open:\n%s", out)
		}
		if strings.Contains(out, testClientSecret) {
			t.Error("the configured client secret was printed")
		}
		if s := p.stdout(); s != "" {
			t.Errorf("the token went to stdout, where a redirect loses it:\n%s", s)
		}
	})

	// The other half of the same rule: a first boot has nothing to give away,
	// so it stays frictionless - no token to copy, and a cosmetic setting
	// does not change that.
	for name, body := range map[string]string{
		"no file at all":       "",
		"only cosmetic values": "S2G_LOG_LEVEL=info\nS2G_UI_TITLE=Hallway printer\n",
	} {
		t.Run(name+" needs no token", func(t *testing.T) {
			addr := freePort(t)
			p := startMain(t, "setup", map[string]string{
				"S2G_CONFIG_FILE": write(t, body), "S2G_HTTP_ADDR": addr,
			})
			p.waitListening(addr)
			if out := p.output(); !strings.Contains(out, "No token yet") {
				t.Fatalf("a blank appliance was gated by a token:\n%s", out)
			}
			resp, err := http.Get("http://" + addr + "/setup")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET /setup: status %d, want 200", resp.StatusCode)
			}
		})
	}
}

// TestSetupModesOverAMalformedFile pins that a configuration file the wizard
// cannot parse does not stop either mode from starting, and does not open the
// repair window to the LAN either: the wizard they reach gates itself, since
// a file that yields no values otherwise reads as a fresh install with
// nothing to protect. TestDefaultModeDispatch's marker subtest is where a
// token actually gates a request; both cases here only need to see the
// banner ask for one.
func TestSetupModesOverAMalformedFile(t *testing.T) {
	// One line that is not KEY=value, in a file that is plainly somebody's
	// configuration all the same.
	const junk = "S2G_ENTRA_TENANT_ID 00000000-0000-0000-0000-000000000000\n"

	junkFile := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "scan2graph.env")
		if err := os.WriteFile(path, []byte(junk), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tokenPrinted := func(t *testing.T, out string) {
		t.Helper()
		if !regexp.MustCompile(`/setup\?t=\S+`).MatchString(out) {
			t.Fatalf("no token URL was printed:\n%s", out)
		}
	}

	t.Run("setup serves the form, behind a token", func(t *testing.T) {
		path, addr := junkFile(t), freePort(t)
		p := startMain(t, "setup", map[string]string{"S2G_CONFIG_FILE": path, "S2G_HTTP_ADDR": addr})
		p.waitListening(addr)
		out := p.output()
		if !strings.Contains(out, "expected KEY=value") {
			t.Errorf("the operator is not told why the form came up empty:\n%s", out)
		}
		// The form does not only hand the file out, it writes one: an
		// unauthenticated repair window lets any LAN client save its own
		// tenant over this appliance's.
		if !strings.Contains(out, "one-shot token is required") {
			t.Fatalf("the repair window was opened to the whole LAN:\n%s", out)
		}
		tokenPrinted(t, out)
	})

	t.Run("a marker-armed start opens the gated wizard instead of exiting", func(t *testing.T) {
		path, addr := junkFile(t), freePort(t)
		env := map[string]string{"S2G_CONFIG_FILE": path, "S2G_HTTP_ADDR": addr}

		code, out := startMain(t, "setup-next-start", env).wait()
		if code != 0 {
			t.Fatalf("setup-next-start exit code %d, want 0; output:\n%s", code, out)
		}
		tokenPrinted(t, out)
		if _, err := os.Stat(markerPath(path)); err != nil {
			t.Fatalf("no marker was written: %v", err)
		}

		// The marker is read before the file's parse error can stop anything,
		// so the wizard it promised opens rather than leaving the marker
		// armed and unreachable.
		p := startMain(t, "", env)
		p.waitListening(addr)
		if _, err := os.Stat(markerPath(path)); !os.IsNotExist(err) {
			t.Errorf("the marker survived into a listening wizard (stat err = %v)", err)
		}
		if out := p.output(); !strings.Contains(out, "one-shot token is required") {
			t.Errorf("the wizard does not say a token gates it:\n%s", out)
		}
	})
}

// TestSetupFollowsFileIndirection pins that the wizard's own two settings -
// where to listen and which URL to print - follow the documented S2G_X_FILE
// indirection like every other setting, rather than a raw lookup that would
// silently fall back to the default port and hand the operator a filesystem
// path as a URL - found out, on a marker-armed start, only once the one-shot
// marker is already spent.
func TestSetupFollowsFileIndirection(t *testing.T) {
	dir := t.TempDir()
	addr, base := freePort(t), "http://scan2graph.example.com"
	// The trailing newline a mounted file or an editor leaves behind is part
	// of the case: the value is what resolve trims it to.
	write := func(name, value string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p := startMain(t, "setup", map[string]string{
		"S2G_CONFIG_FILE":          filepath.Join(dir, "scan2graph.env"), // not written yet
		"S2G_HTTP_ADDR_FILE":       write("http-addr", addr),
		"S2G_PUBLIC_BASE_URL_FILE": write("public-base-url", base),
	})
	p.waitListening(addr) // fails here if the file indirection were ignored
	if out := p.output(); !strings.Contains(out, base+"/setup") {
		t.Errorf("the wizard did not print the configured public base URL:\n%s", out)
	}
}
