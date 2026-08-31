// Command scan2graph is a LAN SMTP gateway that turns "scan to email" messages
// from printers into OCRed PDFs delivered via Microsoft Graph and/or a small
// Entra-authenticated web UI.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/docintel"
	"github.com/georg-jung/scan2graph/internal/graphmail"
	"github.com/georg-jung/scan2graph/internal/jobs"
	"github.com/georg-jung/scan2graph/internal/pipeline"
	"github.com/georg-jung/scan2graph/internal/smtpin"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		// Configuration errors are for humans reading container logs, and
		// there can be several at once, so print them plainly instead of
		// squeezing a multi-line list into one log record.
		fmt.Fprintf(os.Stderr, "scan2graph: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	slog.SetDefault(newLogger(cfg.LogFormat, cfg.LogLevel))

	if err := run(cfg); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
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

	pipe := pipeline.New(pipeline.Options{
		Store:   store,
		OCR:     newOCR(ctx, cfg),
		Mailer:  newMailer(ctx, cfg),
		BaseURL: cfg.PublicBaseURL,
		Workers: cfg.Limits.MaxConcurrentJobs,
		Logger:  slog.Default(),
	})
	pipeDone := make(chan struct{})
	go func() {
		defer close(pipeDone)
		pipe.Run(ctx)
	}()

	smtpSrv := smtpin.New(cfg, store, pipe, slog.Default())
	smtpErrCh := make(chan error, 1)
	go func() {
		slog.Info("smtp listening", "addr", cfg.SMTPAddr)
		if err := smtpSrv.ListenAndServe(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			smtpErrCh <- fmt.Errorf("smtp server: %w", err)
		}
	}()
	defer smtpSrv.Close()

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           newHTTPHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case err := <-smtpErrCh:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)

	// The SMTP listener is already closing (deferred above), so no new job can
	// arrive; wait for the workers to notice the cancelled context. Whatever
	// they were doing is lost either way - that is the ephemeral contract.
	<-pipeDone
	return err
}

// newOCR builds the Document Intelligence client, or returns nil when no
// profile asks for OCR. The token source caches and refreshes on its own.
// It returns the interface type on purpose: a nil *docintel.Client in an
// interface field would not compare equal to nil.
func newOCR(ctx context.Context, cfg *config.Config) pipeline.OCR {
	if cfg.DIEndpoint == "" {
		return nil
	}
	return &docintel.Client{
		HTTP:       msClient(ctx, cfg, cfg.DIScope),
		Endpoint:   cfg.DIEndpoint,
		APIVersion: cfg.DIAPIVersion,
	}
}

// newMailer builds the Graph client, or returns nil when no profile asks for
// email delivery. Interface-typed for the same reason as newOCR.
func newMailer(ctx context.Context, cfg *config.Config) pipeline.Mailer {
	if cfg.GraphSender == "" {
		return nil
	}
	return &graphmail.Client{
		HTTP:    msClient(ctx, cfg, cfg.GraphScope),
		BaseURL: cfg.GraphBaseURL,
		Sender:  cfg.GraphSender,
	}
}

// msClient returns an HTTP client that attaches an app-only access token for
// one scope, acquired with the Entra app registration and refreshed as needed.
func msClient(ctx context.Context, cfg *config.Config, scope string) *http.Client {
	cc := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
		Scopes:       []string{scope},
	}
	c := cc.Client(ctx)
	c.Timeout = 5 * time.Minute
	return c
}

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

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", plainOK)
	mux.HandleFunc("GET /readyz", plainOK)
	return mux
}

func plainOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}
