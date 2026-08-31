package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georg-jung/scan2graph/internal/graphmail"
	"github.com/georg-jung/scan2graph/internal/jobs"
)

const (
	testRecipient = "user@example.invalid"
	testBaseURL   = "https://scan.example.invalid"
	adviceLine    = "Try scanning fewer pages"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newStore(t *testing.T) *jobs.Store {
	t.Helper()
	st, err := jobs.New(jobs.Options{Root: t.TempDir(), TTL: time.Hour, MaxJobs: 64, Logger: testLogger()})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// commit stages one job with a document per content string and commits it.
func commit(t *testing.T, st *jobs.Store, caps jobs.Capabilities, subject string, contents ...string) jobs.Job {
	t.Helper()
	staging, err := st.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	docs := make([]jobs.NewDocument, 0, len(contents))
	for i, c := range contents {
		f, err := staging.CreateFile("doc")
		if err != nil {
			t.Fatalf("staging CreateFile: %v", err)
		}
		if _, err := f.WriteString(c); err != nil {
			t.Fatalf("write staged document: %v", err)
		}
		f.Close()
		docs = append(docs, jobs.NewDocument{DisplayName: fmt.Sprintf("scan%d.pdf", i), Path: f.Name()})
	}
	job, err := staging.Commit(jobs.NewJob{
		Profile:    "printer@example.invalid",
		Caps:       caps,
		Subject:    subject,
		Recipients: []string{testRecipient},
		Documents:  docs,
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return job
}

// fakeOCR prefixes the input with "OCR:" unless it is told to fail. block,
// when set, is waited on (or ctx cancellation) before returning.
type fakeOCR struct {
	err   error
	block chan struct{}

	mu      sync.Mutex
	calls   int
	entered chan struct{}
}

func (f *fakeOCR) SearchablePDF(ctx context.Context, pdf io.ReadSeeker, out io.Writer) error {
	f.mu.Lock()
	f.calls++
	entered := f.entered
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}

	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.err != nil {
		return f.err
	}
	b, err := io.ReadAll(pdf)
	if err != nil {
		return err
	}
	_, err = out.Write(append([]byte("OCR:"), b...))
	return err
}

func (f *fakeOCR) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// sent records one Send call plus the attachment bytes as they were on disk
// at send time, since the job's files may be deleted right afterwards.
type sent struct {
	msg   graphmail.Message
	files []string
}

type fakeMailer struct {
	err       error // returned for a message with attachments
	noticeErr error // returned for a message without attachments

	mu       sync.Mutex
	messages []sent
}

func (f *fakeMailer) Send(ctx context.Context, m graphmail.Message) error {
	// A real client makes no request at all on a dead context, so neither
	// does this one: nothing is recorded.
	if err := ctx.Err(); err != nil {
		return err
	}
	rec := sent{msg: m}
	for _, a := range m.Attachments {
		b, _ := os.ReadFile(a.Path)
		rec.files = append(rec.files, string(b))
	}
	f.mu.Lock()
	f.messages = append(f.messages, rec)
	f.mu.Unlock()
	if len(m.Attachments) == 0 {
		return f.noticeErr
	}
	return f.err
}

func (f *fakeMailer) sent() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sent(nil), f.messages...)
}

// waitFor polls cond until it holds or the test fails after a second.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// runJobs enqueues every job, runs the pool until each has reached a terminal
// state (gone, ready or failed), then cancels and waits for Run to return.
func runJobs(t *testing.T, p *Pipeline, st *jobs.Store, list ...jobs.Job) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	for _, j := range list {
		if err := p.Enqueue(j); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	waitFor(t, "jobs to finish", func() bool {
		for _, j := range list {
			cur, ok := st.Get(j.ID)
			if ok && cur.Status != jobs.StatusReady && cur.Status != jobs.StatusFailed {
				return false
			}
		}
		return true
	})
	cancel()
	<-done
}

func TestProcess(t *testing.T) {
	tooLarge := fmt.Errorf("compose: %w", graphmail.ErrTooLarge)

	tests := []struct {
		name       string
		caps       jobs.Capabilities
		ocrErr     error
		sendErr    error
		noticeErr  error
		wantOCR    int
		wantSends  int
		wantAttach string      // attachment bytes of the document message
		wantNotice []string    // substrings the notice body must contain
		wantStatus jobs.Status // "" means the job must be gone from the store
		wantStored string      // document bytes the store serves afterwards
	}{
		{
			name:       "web only",
			caps:       jobs.Capabilities{Web: true},
			wantStatus: jobs.StatusReady,
			wantStored: "scan",
		},
		{
			name:       "ocr and web",
			caps:       jobs.Capabilities{Web: true, OCR: true},
			wantOCR:    1,
			wantStatus: jobs.StatusReady,
			wantStored: "OCR:scan",
		},
		{
			name:       "ocr and email deletes the job",
			caps:       jobs.Capabilities{Email: true, OCR: true},
			wantOCR:    1,
			wantSends:  1,
			wantAttach: "OCR:scan",
		},
		{
			name:       "email only deletes the job",
			caps:       jobs.Capabilities{Email: true},
			wantSends:  1,
			wantAttach: "scan",
		},
		{
			name:       "ocr failure without web",
			caps:       jobs.Capabilities{Email: true, OCR: true},
			ocrErr:     errors.New("document intelligence said no"),
			wantOCR:    1,
			wantSends:  1,
			wantNotice: []string{reasonOCRFailed, adviceLine},
		},
		{
			name:       "ocr failure with web keeps the original",
			caps:       jobs.Capabilities{Email: true, Web: true, OCR: true},
			ocrErr:     errors.New("document intelligence said no"),
			wantOCR:    1,
			wantSends:  1,
			wantNotice: []string{reasonOCRFailedWeb, "download the scan", testBaseURL + "/scan/"},
			wantStatus: jobs.StatusFailed,
			wantStored: "scan",
		},
		{
			name:       "ocr failure notice that itself fails is not retried",
			caps:       jobs.Capabilities{Email: true, OCR: true},
			ocrErr:     errors.New("document intelligence said no"),
			noticeErr:  errors.New("graph is down"),
			wantOCR:    1,
			wantSends:  1,
			wantNotice: []string{reasonOCRFailed},
		},
		{
			name:       "too large with web links to the download",
			caps:       jobs.Capabilities{Email: true, Web: true},
			sendErr:    tooLarge,
			wantSends:  2,
			wantAttach: "scan",
			wantNotice: []string{"larger than the 2.2 MB", testBaseURL + "/scan/"},
			wantStatus: jobs.StatusReady,
			wantStored: "scan",
		},
		{
			name:       "too large without web advises the user",
			caps:       jobs.Capabilities{Email: true},
			sendErr:    tooLarge,
			wantSends:  2,
			wantAttach: "scan",
			wantNotice: []string{"larger than the 2.2 MB", adviceLine},
		},
		{
			name:       "send failure fails the job",
			caps:       jobs.Capabilities{Email: true, Web: true},
			sendErr:    errors.New("graph is down"),
			wantSends:  2,
			wantAttach: "scan",
			wantNotice: []string{reasonSendFailed},
			wantStatus: jobs.StatusFailed,
			wantStored: "scan",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			ocr := &fakeOCR{err: tc.ocrErr}
			mailer := &fakeMailer{err: tc.sendErr, noticeErr: tc.noticeErr}
			p := New(Options{
				Store: st, OCR: ocr, Mailer: mailer,
				BaseURL: testBaseURL, Workers: 2, Logger: testLogger(),
			})

			job := commit(t, st, tc.caps, "Invoice", "scan")
			runJobs(t, p, st, job)

			if got := ocr.count(); got != tc.wantOCR {
				t.Errorf("OCR calls = %d, want %d", got, tc.wantOCR)
			}
			msgs := mailer.sent()
			if len(msgs) != tc.wantSends {
				t.Fatalf("Send calls = %d, want %d", len(msgs), tc.wantSends)
			}
			for _, m := range msgs {
				if len(m.msg.To) != 1 || m.msg.To[0] != testRecipient {
					t.Errorf("To = %v, want [%s]", m.msg.To, testRecipient)
				}
			}
			if tc.wantAttach != "" {
				m := msgs[0]
				if len(m.files) != 1 || m.files[0] != tc.wantAttach {
					t.Errorf("attachment content = %q, want [%q]", m.files, tc.wantAttach)
				}
			}
			if len(tc.wantNotice) > 0 {
				n := msgs[len(msgs)-1]
				if len(n.msg.Attachments) != 0 {
					t.Errorf("notice has %d attachments, want none", len(n.msg.Attachments))
				}
				for _, want := range tc.wantNotice {
					if !strings.Contains(n.msg.Body, want) {
						t.Errorf("notice body %q does not contain %q", n.msg.Body, want)
					}
				}
			}

			cur, ok := st.Get(job.ID)
			if tc.wantStatus == "" {
				if ok {
					t.Fatalf("job still in the store with status %q, want it deleted", cur.Status)
				}
				return
			}
			if !ok {
				t.Fatalf("job is gone, want status %q", tc.wantStatus)
			}
			if cur.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", cur.Status, tc.wantStatus)
			}
			b, err := os.ReadFile(cur.Documents[0].Path)
			if err != nil {
				t.Fatalf("read served document: %v", err)
			}
			if string(b) != tc.wantStored {
				t.Errorf("served document = %q, want %q", b, tc.wantStored)
			}
			if wantOCRApplied := tc.wantStored == "OCR:scan"; cur.Documents[0].OCRApplied != wantOCRApplied {
				t.Errorf("OCRApplied = %v, want %v", cur.Documents[0].OCRApplied, wantOCRApplied)
			}
		})
	}
}

func TestSubjectFallsBackToScanAndDate(t *testing.T) {
	st := newStore(t)
	mailer := &fakeMailer{}
	p := New(Options{Store: st, Mailer: mailer, Workers: 1, Logger: testLogger()})

	job := commit(t, st, jobs.Capabilities{Email: true}, "", "scan")
	runJobs(t, p, st, job)

	want := "Scan " + job.ReceivedAt.Format("2006-01-02")
	if got := mailer.sent()[0].msg.Subject; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
}

// A job that fails *because* its context expired - the 30 minute budget, or
// a SIGTERM - is exactly when the recipients have nothing else to go on, so
// the notice must not inherit the context that killed the job.
func TestNoticeSurvivesACancelledJobContext(t *testing.T) {
	st := newStore(t)
	mailer := &fakeMailer{}
	p := New(Options{
		Store: st, OCR: &fakeOCR{err: context.Canceled}, Mailer: mailer,
		Workers: 1, Logger: testLogger(),
	})

	job := commit(t, st, jobs.Capabilities{Email: true, OCR: true}, "Invoice", "scan")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.process(ctx, job)

	msgs := mailer.sent()
	if len(msgs) != 1 {
		t.Fatalf("Send calls = %d, want exactly one notice", len(msgs))
	}
	if len(msgs[0].msg.Attachments) != 0 {
		t.Errorf("notice has %d attachments, want none", len(msgs[0].msg.Attachments))
	}
	if !strings.Contains(msgs[0].msg.Body, reasonOCRFailed) {
		t.Errorf("notice body %q does not say why", msgs[0].msg.Body)
	}
}

// The email step works from the worker's own copy of the job, so OCR has to
// refresh the size there as well as the path: the too-large notice adds
// those sizes up and quotes the total back to the user.
func TestRunOCRRefreshesTheDocumentSize(t *testing.T) {
	st := newStore(t)
	p := New(Options{Store: st, OCR: &fakeOCR{}, Workers: 1, Logger: testLogger()})

	job := commit(t, st, jobs.Capabilities{Web: true, OCR: true}, "", "scan")
	if err := p.runOCR(context.Background(), &job); err != nil {
		t.Fatalf("runOCR: %v", err)
	}
	if want := int64(len("OCR:scan")); job.Documents[0].Size != want {
		t.Errorf("Size after OCR = %d, want %d (the searchable PDF, not the original)", job.Documents[0].Size, want)
	}
}

func TestEnqueueRefusesWhenFull(t *testing.T) {
	p := New(Options{Store: newStore(t), Workers: 1, Logger: testLogger()})
	for i := range queuePerWorker {
		if err := p.Enqueue(jobs.Job{ID: fmt.Sprint(i)}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
	if err := p.Enqueue(jobs.Job{ID: "one too many"}); err == nil {
		t.Error("Enqueue on a full queue = nil, want an error")
	}
}

func TestWorkersRunConcurrentlyUpToTheLimit(t *testing.T) {
	const workers = 2
	st := newStore(t)
	ocr := &fakeOCR{block: make(chan struct{}), entered: make(chan struct{}, 8)}
	p := New(Options{Store: st, OCR: ocr, Workers: workers, Logger: testLogger()})

	list := make([]jobs.Job, 6)
	for i := range list {
		list[i] = commit(t, st, jobs.Capabilities{Web: true, OCR: true}, "", "scan")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	for _, j := range list {
		if err := p.Enqueue(j); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	for range workers {
		<-ocr.entered
	}
	select {
	case <-ocr.entered:
		t.Fatal("a third job started while both workers were busy")
	case <-time.After(50 * time.Millisecond):
	}

	close(ocr.block)
	waitFor(t, "all jobs to finish", func() bool { return ocr.count() == len(list) })
	cancel()
	<-done
}

func TestRunReturnsAfterCancel(t *testing.T) {
	st := newStore(t)
	ocr := &fakeOCR{block: make(chan struct{}), entered: make(chan struct{}, 1)} // never closed
	mailer := &fakeMailer{}
	p := New(Options{Store: st, OCR: ocr, Mailer: mailer, Workers: 2, Logger: testLogger()})

	job := commit(t, st, jobs.Capabilities{Web: true, OCR: true}, "", "scan")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	if err := p.Enqueue(job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	<-ocr.entered // the job is in flight
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
	cur, ok := st.Get(job.ID)
	if !ok || cur.Status != jobs.StatusFailed {
		t.Errorf("abandoned job = (%v, %v), want a failed job", cur.Status, ok)
	}
}

func TestVanishedJobIsSkipped(t *testing.T) {
	st := newStore(t)
	ocr := &fakeOCR{}
	mailer := &fakeMailer{}
	p := New(Options{Store: st, OCR: ocr, Mailer: mailer, Workers: 1, Logger: testLogger()})

	job := commit(t, st, jobs.Capabilities{Email: true, OCR: true}, "", "scan")
	if err := st.Delete(job.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	if err := p.Enqueue(job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitFor(t, "the queue to drain", func() bool { return len(p.queue) == 0 })
	cancel()
	<-done

	if ocr.count() != 0 || len(mailer.sent()) != 0 {
		t.Errorf("vanished job produced %d OCR calls and %d sends, want none", ocr.count(), len(mailer.sent()))
	}
}
