// Package pipeline is the worker pool between the SMTP listener and
// delivery: it takes an accepted job through OCR, email and its final
// resting state (ready for the web UI, or deleted) without ever blocking
// the printer's SMTP transaction.
//
// There is no persistence and no retry queue here. Each client owns its own
// bounded retry loop, so an error coming back from OCR or the mailer is
// final and fails the job. A failed job whose profile has email still
// tells its recipients what happened (see notice).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/georg-jung/scan2graph/internal/graphmail"
	"github.com/georg-jung/scan2graph/internal/jobs"
)

// jobTimeout bounds one job's whole trip through the pipeline. OCR on a
// large scan is slow and the clients retry internally, so this is generous;
// it exists to stop a wedged HTTP call from owning a worker forever.
const jobTimeout = 30 * time.Minute

// noticeTimeout bounds a notice send. A notice is often sent because the
// job's own context is gone (the budget above expired, or the process is
// shutting down), so it gets a fresh deadline of its own - but a short one,
// because it has to fit inside a container stop grace period, which is ten
// seconds by default. If Graph cannot take the notice in five seconds, the
// thing that would have carried it is broken anyway.
const noticeTimeout = 5 * time.Second

// queuePerWorker is how many accepted jobs may wait per worker before
// Enqueue starts refusing. The store's own MaxJobs is the real ceiling on
// outstanding scans; this only keeps a burst from being dropped.
const queuePerWorker = 8

// User-visible failure reasons. They are stored on the job (the web UI shows
// them) and used as the notice text, so they never name an internal error, a
// path or a token.
const (
	reasonOCRFailed = "Text recognition failed, so the scan was not delivered."
	// With web the scan is still there to download, so saying it was not
	// delivered would contradict both the link below it and the web UI.
	reasonOCRFailedWeb = "Text recognition failed, so the scan could not be made searchable."
	reasonSendFailed   = "The scan could not be sent by email."
	reasonTooLargeFmt  = "The scan is %.1f MB, which is larger than the %.1f MB an email can carry."
)

// OCR turns a PDF into a searchable one. Implemented by *docintel.Client.
type OCR interface {
	SearchablePDF(ctx context.Context, pdf io.ReadSeeker, out io.Writer) error
}

// Mailer sends one composed message. Implemented by *graphmail.Client.
type Mailer interface {
	Send(ctx context.Context, m graphmail.Message) error
}

// Options configures a Pipeline. OCR and Mailer may be nil exactly when no
// sender profile enables that capability, since a job only reaches them
// through its own Caps.
type Options struct {
	Store   *jobs.Store
	OCR     OCR    // nil when no profile enables ocr
	Mailer  Mailer // nil when no profile enables email
	BaseURL string // public base URL for links in notices; "" when no web
	Workers int
	Logger  *slog.Logger
}

// Pipeline is the worker pool. Enqueue is safe for concurrent use and never
// blocks; Run owns the workers.
type Pipeline struct {
	store   *jobs.Store
	ocr     OCR
	mailer  Mailer
	baseURL string
	workers int
	log     *slog.Logger
	queue   chan jobs.Job
}

// New creates a Pipeline. opts.Workers must be at least one; config
// validation already guarantees that.
func New(opts Options) *Pipeline {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Pipeline{
		store:   opts.Store,
		ocr:     opts.OCR,
		mailer:  opts.Mailer,
		baseURL: opts.BaseURL,
		workers: opts.Workers,
		log:     log,
		queue:   make(chan jobs.Job, opts.Workers*queuePerWorker),
	}
}

// Enqueue hands an accepted job to the workers. It is called from inside an
// SMTP transaction while the printer waits, so it never blocks: a full queue
// returns an error immediately.
func (p *Pipeline) Enqueue(job jobs.Job) error {
	select {
	case p.queue <- job:
		return nil
	default:
		return errors.New("pipeline: queue is full")
	}
}

// Run starts the workers and returns once ctx is done and every in-flight
// job has finished. Jobs still queued at that point are dropped; the store
// expires them.
func (p *Pipeline) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range p.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// Checked before the select: with both cases ready Go picks
				// at random, so a full queue could otherwise start job after
				// job that is already doomed, each spending its notice
				// timeout, and push shutdown past the container's grace.
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case job := <-p.queue:
					p.process(ctx, job)
				}
			}
		}()
	}
	wg.Wait()
}

// process runs one job to its final state. The job value is the worker's own
// copy and is updated in place as OCR replaces documents, so the email step
// attaches whatever is current.
func (p *Pipeline) process(parent context.Context, job jobs.Job) {
	ctx, cancel := context.WithTimeout(parent, jobTimeout)
	defer cancel()

	// SetStatus is also the "is this job still there" check: it fails when
	// the job expired or was deleted while it sat in the queue.
	if err := p.store.SetStatus(job.ID, jobs.StatusProcessing, ""); err != nil {
		p.log.Warn("pipeline: job is gone, skipping", "job_id", job.ID, "err", err)
		return
	}

	if job.Caps.OCR {
		if err := p.runOCR(ctx, &job); err != nil {
			p.log.Warn("pipeline: ocr failed", "job_id", job.ID, "err", err)
			reason := reasonOCRFailed
			if job.Caps.Web {
				reason = reasonOCRFailedWeb
			}
			p.fail(ctx, job, reason)
			return
		}
	}

	if job.Caps.Email {
		if err := p.deliver(ctx, job); err != nil {
			p.log.Warn("pipeline: send failed", "job_id", job.ID, "err", err)
			p.fail(ctx, job, reasonSendFailed)
			return
		}
	}

	if job.Caps.Web {
		if err := p.store.SetStatus(job.ID, jobs.StatusReady, ""); err != nil {
			p.log.Warn("pipeline: could not mark job ready", "job_id", job.ID, "err", err)
		}
		return
	}
	// Without web the files have no further purpose.
	p.deleteJob(job.ID)
}

// runOCR replaces every document with its searchable version, one after
// another, so the worker count is also the OCR concurrency cap. Any error is
// permanent: the caller fails the job rather than falling back to the
// original PDF, which the spec forbids.
func (p *Pipeline) runOCR(ctx context.Context, job *jobs.Job) error {
	for i := range job.Documents {
		doc := &job.Documents[i]
		src, err := os.Open(doc.Path)
		if err != nil {
			return err
		}
		out, err := p.store.CreateFile(job.ID, "ocr")
		if err != nil {
			src.Close()
			return err
		}
		err = p.ocr.SearchablePDF(ctx, src, out)
		src.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if err := p.store.ReplaceDocument(job.ID, doc.ID, out.Name(), true); err != nil {
			return err
		}
		// Size too, not just the path: the too-large notice adds these up,
		// and a stale pre-OCR size makes it quote a nonsense figure.
		fi, err := os.Stat(out.Name())
		if err != nil {
			return err
		}
		doc.Path, doc.Size, doc.OCRApplied = out.Name(), fi.Size(), true
	}
	return nil
}

// deliver composes and sends the scan itself. A message that is too large for
// Graph is not a delivery failure: the recipients get a notice instead, and
// the job carries on as delivered.
func (p *Pipeline) deliver(ctx context.Context, job jobs.Job) error {
	subject := job.Subject
	if subject == "" {
		subject = "Scan " + job.ReceivedAt.Format("2006-01-02")
	}
	attachments := make([]graphmail.Attachment, 0, len(job.Documents))
	var total int64
	for _, d := range job.Documents {
		attachments = append(attachments, graphmail.Attachment{Name: d.DisplayName, Path: d.Path})
		total += d.Size
	}

	err := p.mailer.Send(ctx, graphmail.Message{
		To:          job.Recipients,
		Subject:     subject,
		Body:        "Your scan is attached.",
		Attachments: attachments,
	})
	if errors.Is(err, graphmail.ErrTooLarge) {
		p.log.Warn("pipeline: scan too large to email, sending a notice", "job_id", job.ID, "bytes", total)
		p.notice(ctx, job, fmt.Sprintf(reasonTooLargeFmt, megabytes(total), megabytes(graphmail.MaxAttachmentBytes)))
		return nil
	}
	return err
}

// fail marks the job failed with a user-safe reason, tells the recipients
// when the job has email, and drops a job that has no web UI to show it in.
func (p *Pipeline) fail(ctx context.Context, job jobs.Job, reason string) {
	if err := p.store.SetStatus(job.ID, jobs.StatusFailed, reason); err != nil {
		p.log.Warn("pipeline: could not mark job failed", "job_id", job.ID, "err", err)
	}
	if job.Caps.Email {
		p.notice(ctx, job, reason)
	}
	if !job.Caps.Web {
		p.deleteJob(job.ID)
	}
}

// notice sends the reason as a plain message with no attachments, so a user
// is never left with nothing. It is sent once: the job is already failing (or
// already undeliverable), so a notice that fails is logged and dropped.
func (p *Pipeline) notice(ctx context.Context, job jobs.Job, reason string) {
	// Detached from the job's context on purpose: when the failure *is* the
	// context expiring, inheriting it would make Send return before it ever
	// asked Graph for anything, and the user would hear nothing at all.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), noticeTimeout)
	defer cancel()

	body := reason + "\n\n"
	if job.Caps.Web && p.baseURL != "" {
		body += fmt.Sprintf("You can download the scan here for the next %d minutes:\n%s/scan/%s\n",
			int(time.Until(job.ExpiresAt).Minutes()), p.baseURL, job.ID)
	} else {
		body += "Try scanning fewer pages or at a lower resolution, " +
			"or ask your administrator to enable web downloads.\n"
	}
	subject := "Scan not delivered"
	if job.Subject != "" {
		subject += ": " + job.Subject
	}
	if err := p.mailer.Send(ctx, graphmail.Message{To: job.Recipients, Subject: subject, Body: body}); err != nil {
		p.log.Warn("pipeline: notice failed", "job_id", job.ID, "err", err)
	}
}

// megabytes renders a byte count the way a notice talks about it.
func megabytes(n int64) float64 { return float64(n) / (1 << 20) }

func (p *Pipeline) deleteJob(id string) {
	if err := p.store.Delete(id); err != nil {
		p.log.Warn("pipeline: could not delete job", "job_id", id, "err", err)
	}
}
