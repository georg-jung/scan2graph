// Package smtpin is the SMTP listener printers send scans to.
//
// It is not a mail relay: it accepts one message, decides from the envelope
// sender which sender profile (capabilities) applies and from the envelope
// recipients who the scan is for, extracts the PDF attachments, hands a job
// to the pipeline and answers 250 -- all before any OCR or Graph work
// happens. MIME From:/To: headers are never used for routing; see the
// project spec's domain model.
package smtpin

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/jobs"
)

// Handler enqueues an accepted job with the processing pipeline.
type Handler interface {
	Enqueue(job jobs.Job) error
}

// New builds a *smtp.Server for incoming scans. The caller starts it (Serve)
// and shuts it down; New itself never listens or blocks.
//
// The listener runs on plain TCP by design -- it lives on a restricted LAN
// -- so AllowInsecureAuth is set unconditionally.
func New(cfg *config.Config, store *jobs.Store, h Handler, log *slog.Logger) *smtp.Server {
	srv := smtp.NewServer(&backend{cfg: cfg, store: store, handler: h, log: log})
	srv.Addr = cfg.SMTPAddr
	srv.MaxMessageBytes = cfg.Limits.MaxMessageBytes
	srv.MaxRecipients = 16
	srv.AllowInsecureAuth = true
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = 5 * time.Minute
	srv.ErrorLog = errorLogger{log}
	return srv
}

// backend is the go-smtp Backend: one session per connection.
type backend struct {
	cfg     *config.Config
	store   *jobs.Store
	handler Handler
	log     *slog.Logger
}

// NewSession returns a session that additionally implements smtp.AuthSession
// unless anonymous SMTP is allowed -- that absence is how go-smtp is told to
// neither advertise nor require AUTH (see session.go).
func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &session{
		cfg:     b.cfg,
		store:   b.store,
		handler: b.handler,
		log:     b.log,
	}
	if b.cfg.SMTPAllowAnonymous {
		return s, nil
	}
	return &authSession{session: s}, nil
}

// errorLogger routes go-smtp's internal error log into slog.
type errorLogger struct{ log *slog.Logger }

func (l errorLogger) Printf(format string, v ...any) {
	l.log.Error(fmt.Sprintf(format, v...))
}

func (l errorLogger) Println(v ...any) { l.log.Error(fmt.Sprint(v...)) }
