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
	"sync"
	"syscall"
	"time"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/jobs"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	slog.SetDefault(newLogger("json", slog.LevelInfo))

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

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

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
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx)
	wg.Wait()
	return shutdownErr
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
		slog.Warn("no SMTP password configured, generated an ephemeral one",
			"smtp_username", cfg.SMTPUsername,
			"smtp_password", cfg.SMTPPassword,
			"note", "this password changes on every restart; configure S2G_SMTP_PASSWORD "+
				"(or S2G_SMTP_PASSWORD_FILE) to keep it stable, or set "+
				"S2G_SMTP_ALLOW_ANONYMOUS=true to run without SMTP AUTH")
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
