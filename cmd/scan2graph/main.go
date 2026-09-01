// Command scan2graph is a LAN SMTP gateway that turns "scan to email" messages
// from printers into OCRed PDFs delivered via Microsoft Graph and/or a small
// Entra-authenticated web UI.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/docintel"
	"github.com/georg-jung/scan2graph/internal/graphmail"
	"github.com/georg-jung/scan2graph/internal/jobs"
	"github.com/georg-jung/scan2graph/internal/msapi"
	"github.com/georg-jung/scan2graph/internal/pipeline"
	"github.com/georg-jung/scan2graph/internal/smtpin"
	"github.com/georg-jung/scan2graph/internal/web"
)

// defaultHTTPAddr is what the wizard falls back to, and what config.Load
// defaults S2G_HTTP_ADDR to; the two have to agree or the form would be
// somewhere other than where the appliance will be.
const defaultHTTPAddr = ":8080"

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	args := os.Args[1:]
	mode, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, rest = args[0], args[1:]
	}
	switch mode {
	case "serve":
		runServeMode(rest)
	case "setup":
		runSetupMode(rest)
	case "setup-next-start":
		runSetupNextStartMode(rest)
	case "":
		runDefaultMode(rest)
	default:
		fatal("unknown subcommand %q (want serve, setup, setup-next-start, or none)", mode)
	}
}

// check exits, in the shape every startup failure uses, when err is not nil.
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

// fatal prints a message to stderr, prefixed like every other startup
// failure, and exits 1.
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "scan2graph: "+format+"\n", args...)
	os.Exit(1)
}

// runServeMode is the "serve" subcommand: today's behaviour exactly, with
// no setup routes in existence at all. Invalid or missing configuration is
// the usual multi-error exit.
func runServeMode(args []string) {
	getenv, path, overridden, _, err := configSource(args, false)
	check(err)
	// "serve" neither opens the wizard nor consumes the marker, so a token
	// minted by "setup-next-start" is still live and still opens the wizard
	// at the next start without a subcommand. That is the marker's documented
	// behaviour, and surprising enough to say out loud.
	if path != "" {
		if _, statErr := os.Stat(markerPath(path)); statErr == nil {
			fmt.Fprintf(os.Stderr, "scan2graph: the setup marker %s is still armed; a start without a subcommand will open the setup wizard instead of serving\n", markerPath(path))
		}
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		// Configuration errors are for humans reading container logs, and
		// there can be several at once, so print them plainly instead of
		// squeezing a multi-line list into one log record.
		fatal("invalid configuration:\n%v", err)
	}
	serve(cfg, path, overridden)
}

// serve logs how configuration was resolved and then runs the appliance.
// Shared by the "serve" subcommand and the default mode's serve outcome.
func serve(cfg *config.Config, configFile string, overridden []string) {
	slog.SetDefault(newLogger(cfg.LogFormat, cfg.LogLevel))
	if configFile != "" {
		// Paths and setting names only - never a value, since this file is
		// where the client secret usually lives.
		slog.Info("configuration file read", "path", configFile, "overridden_by_environment", overridden)
	}
	if err := run(cfg); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// runDefaultMode is "scan2graph" with no subcommand. The marker is consumed
// before anything else runs - before the configuration file is even required
// to parse - so a crash loop can never re-open the wizard forever, and the
// file the wizard was armed to repair cannot stop it from opening. A marker
// always wins; short of that, configuration that loads serves, a
// configuration with nothing in it worth protecting opens the wizard
// unauthenticated (nothing to steal means nothing to gate), and anything
// else - notably a half-configured appliance whose secret file went missing -
// is the ordinary error exit rather than a silent slide into an
// unauthenticated configuration editor.
func runDefaultMode(args []string) {
	getenv, path, overridden, read, err := configSource(args, true)

	// The marker is read before err is allowed to stop anything:
	// "setup-next-start" promises that the next start opens the wizard, and
	// the file it was pointed at is quite possibly one that will not parse.
	// Exiting on the parse error first would leave the marker armed and that
	// promise unkept.
	var markerHash []byte
	if path != "" {
		var markerErr error
		markerHash, markerErr = consumeMarker(markerPath(path))
		check(markerErr)
	}
	if markerHash != nil {
		wizard(path, markerHash)
		return
	}
	check(err)

	cfg, loadErr := config.Load(getenv)
	switch {
	case loadErr == nil:
		loggedPath := "" // nothing was actually read from path; do not claim otherwise
		if read {
			loggedPath = path
		}
		serve(cfg, loggedPath, overridden)
	case !worthProtecting(readConfigFile(path)):
		wizard(path, nil)
	default:
		fatal("invalid configuration:\n%v", loadErr)
	}
}

// worthProtecting answers the one question both of the wizard's doors turn
// on: is there something here an anonymous LAN visitor could take or
// overwrite? It reads the configuration file layered under the process
// environment, since a client secret can live in the file alone, and treats
// a file this cannot parse the same as one holding something - the layered
// view of nothing would otherwise read as a blank appliance. runDefaultMode
// and wizard both call this one function so the answer cannot drift between
// the two doors.
func worthProtecting(fileValues map[string]string, parsed bool) bool {
	return !parsed || web.AnyConfigured(config.Layer(fileValues, os.Getenv))
}

// readConfigFile is the configuration file as the wizard should seed itself
// from: what it holds, or nothing at all when there is no file - and also
// when there is one that does not parse, since the wizard is the tool that
// repairs exactly that and refusing to start over it would leave an editor
// and a shell as the only way back. parsed is false for that last case alone,
// a file that exists and holds something this cannot read; an absent file and
// an empty one parse to nothing without complaint, and are the fresh install
// worthProtecting leaves open. The reason goes to stderr; ParseFile's message
// names the file and the line number but never the line, which may well be
// where the client secret is.
func readConfigFile(path string) (values map[string]string, parsed bool) {
	if path == "" {
		return nil, true
	}
	values, err := config.ParseFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "scan2graph: %v; the setup wizard will start with an empty form, and saving replaces the file\n", err)
		return nil, false
	}
	return values, true
}

// runSetupMode is the "setup" subcommand: the wizard, started in the
// foreground on purpose - either to do initial setup, or to revisit an
// already-configured appliance's settings file. wizard decides whether a
// token gates it; revisiting a configured file is exactly the case that
// needs one.
func runSetupMode(args []string) {
	_, path, _, _, _ := configSource(args, true) // only the path: see readConfigFile
	wizard(path, nil)
}

// runSetupNextStartMode is "setup-next-start": mint a one-shot token, leave
// only its hash on disk, and print the URL - including the token - for the
// operator to copy. It never starts a listener.
func runSetupNextStartMode(args []string) {
	_, path, _, _, _ := configSource(args, true) // only the path, for the same reason "setup" does
	if path == "" {
		fatal("setup-next-start needs a configuration file; pass --config or set S2G_CONFIG_FILE")
	}
	token, err := createMarker(markerPath(path))
	check(err)
	fileValues, _ := readConfigFile(path)
	getenv := config.Layer(fileValues, os.Getenv)
	// Straight to stderr, the way a generated SMTP password goes: this is the
	// operator's only copy of the token, and stdout is exactly where it can
	// vanish without a trace - a launcher or a wrapper that redirects it
	// swallows the one line that mattered.
	fmt.Fprintln(os.Stderr, setupURL(getenv, setupAddr(getenv), token))
}

// wizard resolves what the setup form should show, decides whether a token
// gates it, and serves it: the same health endpoints as run(), but no SMTP
// listener, no job store and no pipeline - nothing is configured yet for any
// of those to run against. There is never a validated *config.Config to build
// a logger from here - the wizard's entire point is that one is not
// available yet - so it logs at the package's own fixed defaults. Unlike
// run(), no scan is ever in flight here, so there is nothing worth a graceful
// shutdown for; a bare SIGINT/SIGTERM ending the process is enough, and
// ListenAndServe's error is always fatal - nothing here ever calls Close or
// Shutdown for it to report instead.
func wizard(path string, tokenHash []byte) {
	slog.SetDefault(newLogger("json", slog.LevelInfo))
	fileValues, parsed := readConfigFile(path)
	getenv := config.Layer(fileValues, os.Getenv)
	// Before anything is printed: the URL the operator is handed, token and
	// all, has to name the address this actually ended up on.
	ln, addr := setupListener(getenv, defaultHTTPAddr)
	if tokenHash == nil && worthProtecting(fileValues, parsed) {
		// The form's Download button hands back the whole configuration file,
		// client secret and all, and Save writes a replacement over it - and
		// this listens on every interface, so leaving it unauthenticated is
		// only safe while there is nothing here to take and nothing worth
		// overwriting. Mint a one-shot token instead, and print the URL to
		// stderr, the way "setup-next-start" does. A first boot with nothing
		// configured reaches this too, and stays frictionless.
		var token string
		token, tokenHash = mintToken()
		fmt.Fprintln(os.Stderr, setupURL(getenv, addr, token))
	}
	announceSetupWizard(setupURL(getenv, addr, ""), tokenHash != nil)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", plainOK)
	mux.HandleFunc("GET /readyz", plainOK)
	mux.Handle("/", web.NewSetup(web.SetupOptions{
		Getenv:     os.Getenv,
		FileValues: fileValues,
		Path:       path,
		TokenHash:  tokenHash,
	}))

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("http listening", "addr", addr)
	if err := srv.Serve(ln); err != nil {
		slog.Error("fatal", "err", fmt.Errorf("http server: %w", err))
		os.Exit(1)
	}
}

// setupAddr and setupURL read their two settings the way Load does, through
// the config package's own resolvers: every setting is documented as also
// readable from S2G_X_FILE, and a raw lookup silently misses that spelling -
// the listener would fall back to the default and bind a port nobody
// published, and the URL the operator is handed would be a filesystem path.
// On a marker-armed start that is found out only once the one-shot marker is
// already spent.
// setupAddr is the address the wizard is configured for, read the way Load
// reads it so the documented S2G_HTTP_ADDR_FILE spelling is not silently
// missed - a raw lookup would fall back to the default and bind a port
// nobody published.
func setupAddr(getenv func(string) string) string {
	return cmp.Or(config.Resolve(getenv, "S2G_HTTP_ADDR"), defaultHTTPAddr)
}

// setupListener opens that address, falling back to fallback when it will
// not bind. Binding is the only honest test of an address - a name that does
// not resolve and an interface this host does not have are both shaped
// perfectly well - and it matters here because a marker-armed start has
// already spent its one-shot marker by the time a listener fails, so the
// token it printed dies with the process and the next attempt reads the same
// bad value and fails the same way. That is the one typo the repair tool has
// to survive. "serve" keeps failing loudly on it: it has no marker to lose.
func setupListener(getenv func(string) string, fallback string) (net.Listener, string) {
	addr := setupAddr(getenv)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, addr
	}
	fmt.Fprintf(os.Stderr, "scan2graph: S2G_HTTP_ADDR %q will not listen (%v); the wizard is on %s instead\n", addr, err, fallback)
	ln, err = net.Listen("tcp", fallback)
	check(err)
	return ln, ln.Addr().String()
}

// setupURL is the URL to open for the setup wizard: the configured public
// base URL when one is usable (a re-run against an appliance whose only
// problem is a stale secret already has one), else http://localhost on
// addr's port, or the built-in default's port for an address shaped so
// unusually that it has none, since nothing else is necessarily valid yet.
// Usable is ResolveRootBaseURL's question rather than "is it set": a value
// the loader refuses - a bare path, a scheme nothing browses - is exactly
// what someone runs setup to repair, and printing it back as the one link
// carrying the one-shot token would send the operator where nothing serves.
// token, when not empty, is the one-shot query parameter "setup-next-start"
// prints; the wizard's own startup banner never has one to show.
func setupURL(getenv func(string) string, addr, token string) string {
	base := config.ResolveRootBaseURL(getenv, "S2G_PUBLIC_BASE_URL")
	if base == "" {
		port := "8080"
		if _, p, err := net.SplitHostPort(addr); err == nil {
			port = p
		}
		base = "http://localhost:" + port
	}
	u := strings.TrimSuffix(base, "/") + "/setup"
	if token != "" {
		u += "?t=" + token
	}
	return u
}

// announceSetupWizard tells the operator, in the same style as
// announceDefaultProfile below, that this run is the setup wizard rather
// than the appliance: which URL opens it, and whether a token gates it.
// The token itself is never repeated here - whichever command minted it,
// "setup-next-start" or this one, printed it once already.
func announceSetupWizard(url string, tokenRequired bool) {
	access := "No token yet: the first browser to press \"Start configuration\" claims this wizard, and every other one is then refused. Until that press anybody who can reach this address can do it, so keep it on a trusted network. Restarting scan2graph re-opens it."
	if tokenRequired {
		access = "A one-shot token is required: open the URL printed when it was minted, which carries it as ?t=TOKEN. It is not shown again."
	}
	fmt.Fprintf(os.Stderr,
		"\n  ┌─ Setup wizard ─────────────────────────────────────────────\n"+
			"  │ Not the appliance - open this URL to configure it:\n"+
			"  │     %s\n"+
			"  │ %s\n"+
			"  └─────────────────────────────────────────────────────────────\n\n",
		url, access)
}

// configSource resolves the optional configuration file - --config, else
// S2G_CONFIG_FILE - and returns the getenv Load reads through together with
// what to tell the operator about it. No location is baked in: the
// container, the systemd unit and a hand-started binary each pass their own
// path, and a file that was explicitly asked for but cannot be read is a
// startup failure rather than a silent fall back to the environment alone.
// lenient additionally treats a file that does not exist yet as no file at
// all, rather than an error: every wizard-adjacent mode exists specifically
// to create that file, so its absence is the ordinary starting point rather
// than a failure - the fresh-install case "setup-next-start" points
// --config/S2G_CONFIG_FILE at on purpose, before anything has written it.
// read reports whether a file was actually found and parsed, since serve()'s
// log line about reading one should only fire then.
func configSource(args []string, lenient bool) (getenv func(string) string, path string, overridden []string, read bool, err error) {
	fs := flag.NewFlagSet("scan2graph", flag.ExitOnError)
	configFlag := fs.String("config", "",
		"read settings from this KEY=value file (default $S2G_CONFIG_FILE); environment variables still win")
	_ = fs.Parse(args) // ExitOnError: an unusable flag has already exited
	// flag stops at the first non-flag argument, and main reads only
	// os.Args[1] for the mode, so "scan2graph --config path serve" would
	// otherwise run the *default* mode with "serve" thrown away - and that
	// mode answers an unreadable path with the unauthenticated wizard, which
	// is precisely what "serve" promises never to do. It would consume an
	// armed marker on the way, too.
	if fs.NArg() > 0 {
		fatal("unexpected argument %q; the subcommand comes first", fs.Arg(0))
	}
	path = cmp.Or(*configFlag, os.Getenv("S2G_CONFIG_FILE"))
	getenv, overridden, err = config.FileEnv(path, os.Getenv)
	if lenient && errors.Is(err, os.ErrNotExist) {
		return os.Getenv, path, nil, false, nil
	}
	return getenv, path, overridden, err == nil && path != "", err
}

func newLogger(format string, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func run(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("starting scan2graph", "version", version, "config", cfg)
	announceDefaultProfile(cfg)
	announceSMTPCredentials(cfg)

	store, err := jobs.New(jobs.Options{
		Root:    cfg.TempDir,
		TTL:     cfg.JobTTL,
		MaxJobs: cfg.Limits.MaxJobs,
	})
	if err != nil {
		return fmt.Errorf("create job store: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			slog.Warn("job store cleanup failed", "err", err)
		}
	}()

	go store.Run(ctx)

	var ocr pipeline.OCR // interface-typed: a nil *docintel.Client would not be nil here
	if cfg.DIEndpoint != "" {
		client, _ := msClient(cfg, cfg.DIScope) // no permission of its own to read
		ocr = &docintel.Client{
			HTTP:       client,
			Endpoint:   cfg.DIEndpoint,
			APIVersion: cfg.DIAPIVersion,
		}
	}

	var mailer pipeline.Mailer // same reason: interface-typed even when nil
	if cfg.GraphSender != "" {
		client, tokens := msClient(cfg, cfg.GraphScope)
		m := &graphmail.Client{
			HTTP:       client,
			BaseURL:    cfg.GraphBaseURL,
			Sender:     cfg.GraphSender,
			LargeScans: mailReadWrite(tokens),
		}
		announceGraphCeiling(cfg, m.LargeScans)
		mailer = m
	}

	pipe := pipeline.New(pipeline.Options{
		Store:   store,
		OCR:     ocr,
		Mailer:  mailer,
		BaseURL: cfg.PublicBaseURL,
		Workers: cfg.Limits.MaxConcurrentJobs,
		Logger:  slog.Default(),
	})
	// The workers get their own context, cancelled only after the SMTP
	// listener is closed: a scan accepted while they are already gone would
	// be answered with 250 and then dropped on the floor.
	pipeCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	pipeDone := make(chan struct{})
	go func() {
		defer close(pipeDone)
		pipe.Run(pipeCtx)
	}()

	errCh := make(chan error, 2)

	// Built before anything can accept a scan: this is where OIDC discovery
	// happens, and a printer must not be told 250 for a scan the appliance
	// is about to lose because it could not reach the identity provider.
	handler, err := newHTTPHandler(ctx, cfg, store)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	smtpSrv := smtpin.New(cfg, store, pipe, slog.Default())
	go func() {
		slog.Info("smtp listening", "addr", cfg.SMTPAddr)
		if err := smtpSrv.ListenAndServe(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			errCh <- fmt.Errorf("smtp server: %w", err)
		}
	}()

	go func() {
		slog.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	// The SMTP listener goes first: it answers 250 as soon as a scan is
	// staged, so it must stop making that promise before the workers that
	// would have to keep it are on their way out.
	if err := smtpSrv.Close(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
		slog.Warn("smtp server close failed", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)

	// Only now that nothing can hand them another scan do the workers wind
	// down. Whatever they were doing is lost either way - that is the
	// ephemeral contract.
	stopWorkers()
	<-pipeDone
	return err
}

// msClient returns an HTTP client that attaches an app-only access token for
// one scope, acquired with the Entra app registration and refreshed as needed,
// together with the token source behind it - which is the same one, so a
// caller that reads a token at startup does not mint a second one.
func msClient(cfg *config.Config, scope string) (*http.Client, oauth2.TokenSource) {
	base := &http.Client{
		Timeout: 5 * time.Minute,
		// Never follow a redirect: this client attaches the bearer token to
		// whatever URL it is handed, so a 3xx could walk it to another origin.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	cc := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
		Scopes:       []string{scope},
	}
	// Deliberately not the process context: oauth2 keeps whatever context it
	// is given for every future token request, so cancelling it on SIGTERM
	// would leave the shutdown notice unable to get a token - the one message
	// that has to go out when everything else is failing. The base client's
	// timeout is what bounds a hung Entra instead.
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, base)
	ts := cc.TokenSource(tokenCtx)
	c := oauth2.NewClient(tokenCtx, ts)
	c.Timeout = base.Timeout
	c.CheckRedirect = base.CheckRedirect
	return c, ts
}

// mailReadWrite answers whether the app registration was granted
// Mail.ReadWrite, which is what lets graphmail send a scan too large for
// sendMail. It reads one app-only token's roles claim rather than asking the
// operator to configure what they have already granted.
//
// A token that cannot be fetched leaves large scans off instead of failing
// the start: Graph is a per-job dependency, and an appliance that will not
// boot because Entra was briefly unreachable is worse than one that sends a
// notice for the first big scan. The token source is the process-lifetime one
// msClient built, deliberately not tied to the signal context, so this
// startup fetch is also the token every later request reuses.
func mailReadWrite(tokens oauth2.TokenSource) bool {
	tok, err := tokens.Token()
	if err != nil {
		// err is Entra's refusal, never a token: a token request that failed
		// did not come back with one.
		slog.Warn("could not read the Graph token's permissions at startup; large scans stay off until a restart", "err", err)
		return false
	}
	// The token itself and every other claim in it stay here.
	return slices.Contains(msapi.TokenRoles(tok.AccessToken), "Mail.ReadWrite")
}

// announceGraphCeiling says how large a scan this appliance can actually
// email. That is not one number: with Mail.ReadWrite granted an oversized
// attachment goes up in chunks, so the SMTP cap is the only ceiling left;
// without it, sendMail's is. The box appears for the one combination an
// operator should act on - scans this will accept over SMTP and then have to
// refuse - and never otherwise.
func announceGraphCeiling(cfg *config.Config, largeScans bool) {
	ceiling := int64(graphmail.MaxAttachmentBytes)
	if largeScans {
		ceiling = cfg.Limits.MaxMessageBytes
	}
	slog.Info("email delivery enabled", "mail_read_write", largeScans, "largest_emailable_scan_bytes", ceiling)
	if largeScans || cfg.Limits.MaxMessageBytes <= graphmail.MaxAttachmentBytes {
		return
	}
	fmt.Fprintf(os.Stderr,
		"\n"+
			"  ┌─ Large scans ───────────────────────────────────────────────\n"+
			"  │ This app registration has Mail.Send but not Mail.ReadWrite,\n"+
			"  │ so a scan over %.1f MB cannot be emailed and whoever scanned\n"+
			"  │ it gets a \"too large\" notice instead - while the SMTP\n"+
			"  │ listener accepts scans of up to %.1f MB.\n"+
			"  │\n"+
			"  │ Grant the Mail.ReadWrite application permission to the app\n"+
			"  │ registration, consent to it, and restart: scans that big\n"+
			"  │ then go out in an upload session rather than a notice.\n"+
			"  └─────────────────────────────────────────────────────────────\n\n",
		megabytes(graphmail.MaxAttachmentBytes), megabytes(cfg.Limits.MaxMessageBytes))
}

// megabytes renders a byte count the way the notice the user would get talks
// about it, so the two figures cannot disagree.
func megabytes(n int64) float64 { return float64(n) / (1 << 20) }

// announceDefaultProfile explains what happens to a scan when no sender
// profiles are configured, since then the enabled features are inferred from
// which other settings are present. Printed rather than logged: an operator
// who ends up without OCR or without email delivery needs to see why, at any
// log level.
func announceDefaultProfile(cfg *config.Config) {
	if len(cfg.Profiles) > 0 {
		return
	}
	feature := func(on bool, name, hint string) string {
		if on {
			return fmt.Sprintf("  │     %-14s on\n", name+":")
		}
		return fmt.Sprintf("  │     %-14s off - %s\n", name+":", hint)
	}
	fmt.Fprint(os.Stderr,
		"\n"+
			"  ┌─ Sender profiles ───────────────────────────────────────────\n"+
			"  │ No S2G_PROFILES configured, so every scanner address gets\n"+
			"  │ the same treatment:\n"+
			"  │\n"+
			feature(cfg.DefaultProfile.Email, "email", "set S2G_GRAPH_SENDER")+
			feature(cfg.DefaultProfile.Web, "web downloads", "set S2G_PUBLIC_BASE_URL")+
			feature(cfg.DefaultProfile.OCR, "OCR", "set S2G_DI_ENDPOINT")+
			"  │\n"+
			"  │ Set S2G_PROFILES to give the printer's sender addresses\n"+
			"  │ different feature combinations.\n"+
			"  └─────────────────────────────────────────────────────────────\n\n")
}

// announceSMTPCredentials tells the operator how the SMTP listener is
// authenticated. A generated password is printed on purpose — it is the only
// way to learn it — together with how to make it permanent.
func announceSMTPCredentials(cfg *config.Config) {
	switch {
	case cfg.SMTPAllowAnonymous:
		slog.Warn("SMTP AUTH is disabled (S2G_SMTP_ALLOW_ANONYMOUS=true); " +
			"anyone who can reach the SMTP port can submit scans")
	case cfg.SMTPPasswordGenerated:
		// Printed directly, not logged: this is the operator's only chance to
		// learn the password, so it must survive S2G_LOG_LEVEL=error.
		fmt.Fprintf(os.Stderr,
			"\n"+
				"  ┌─ SMTP AUTH ─────────────────────────────────────────────────\n"+
				"  │ No SMTP password configured, generated an ephemeral one:\n"+
				"  │\n"+
				"  │     username: %s\n"+
				"  │     password: %s\n"+
				"  │\n"+
				"  │ It changes on every restart. Set S2G_SMTP_PASSWORD (or\n"+
				"  │ S2G_SMTP_PASSWORD_FILE) to keep it stable, or set\n"+
				"  │ S2G_SMTP_ALLOW_ANONYMOUS=true to run without SMTP AUTH.\n"+
				"  └─────────────────────────────────────────────────────────────\n\n",
			cfg.SMTPUsername, cfg.SMTPPassword)
	default:
		slog.Info("SMTP AUTH enabled", "smtp_username", cfg.SMTPUsername)
	}
}

// newHTTPHandler serves the health endpoints always, and mounts the web UI
// underneath them when a profile enables web downloads. Discovery against
// Entra happens here, so a wrong authority is a startup failure rather than a
// surprise at the first sign-in.
func newHTTPHandler(ctx context.Context, cfg *config.Config, store *jobs.Store) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", plainOK)
	mux.HandleFunc("GET /readyz", plainOK)

	if cfg.PublicBaseURL == "" {
		slog.Info("web UI disabled: no profile enables web downloads")
		return mux, nil
	}
	ui, err := web.New(ctx, web.Options{Store: store, Config: cfg, Logger: slog.Default()})
	if err != nil {
		return nil, fmt.Errorf("web UI: %w", err)
	}
	mux.Handle("/", ui.Handler())
	slog.Info("web UI enabled", "base_url", cfg.PublicBaseURL)
	return mux, nil
}

func plainOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}
