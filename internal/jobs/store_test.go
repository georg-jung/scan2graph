package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a simple injectable, mutex-protected clock for deterministic TTL
// tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(start time.Time) *clock {
	return &clock{t: start}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestStore(t *testing.T, opts Options) (*Store, *clock) {
	t.Helper()
	if opts.Root == "" {
		opts.Root = t.TempDir()
	}
	if opts.TTL == 0 {
		opts.TTL = time.Hour
	}
	if opts.MaxJobs == 0 {
		opts.MaxJobs = 8
	}
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	var c *clock
	if opts.Now == nil {
		c = newClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
		opts.Now = c.now
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, c
}

// writeStagedFile creates a file inside st's directory with the given
// content and returns its path.
func writeStagedFile(t *testing.T, st *Staging, name, content string) string {
	t.Helper()
	f, err := st.CreateFile(name)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	return f.Name()
}

func TestReserveCommitGetRoundtrip(t *testing.T) {
	s, clk := newTestStore(t, Options{TTL: time.Hour})

	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if st.Dir() == "" {
		t.Fatal("Dir() is empty")
	}
	if fi, err := os.Stat(st.Dir()); err != nil || !fi.IsDir() {
		t.Fatalf("staging dir does not exist: %v", err)
	}

	path := writeStagedFile(t, st, "doc", "hello world")

	job, err := st.Commit(NewJob{
		Profile:    "scan-web@printer.local",
		Caps:       Capabilities{Web: true},
		Subject:    "Scan",
		Recipients: []string{"alice@example.com"},
		Documents: []NewDocument{
			{DisplayName: "report.pdf", Path: path},
		},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if job.ID == "" {
		t.Fatal("job.ID is empty")
	}
	if len(job.Documents) != 1 {
		t.Fatalf("expected 1 document, got %d", len(job.Documents))
	}
	if job.Documents[0].ID == "" {
		t.Fatal("document ID is empty")
	}
	if job.Documents[0].DisplayName != "report.pdf" {
		t.Errorf("DisplayName = %q, want report.pdf", job.Documents[0].DisplayName)
	}
	if job.Status != StatusPending {
		t.Errorf("Status = %q, want pending", job.Status)
	}
	if !job.ReceivedAt.Equal(clk.now()) {
		t.Errorf("ReceivedAt = %v, want %v", job.ReceivedAt, clk.now())
	}
	wantExpiry := clk.now().Add(time.Hour)
	if !job.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", job.ExpiresAt, wantExpiry)
	}

	got, ok := s.Get(job.ID)
	if !ok {
		t.Fatal("Get: job not found")
	}
	if got.ID != job.ID || len(got.Documents) != 1 || got.Documents[0].Path != path {
		t.Errorf("Get returned unexpected job: %+v", got)
	}

	if _, ok := s.Get("does-not-exist"); ok {
		t.Error("Get of unknown id returned ok=true")
	}
}

func TestCommitSanitizesDisplayNames(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "x")

	job, err := st.Commit(NewJob{
		Caps: Capabilities{Web: true},
		Documents: []NewDocument{
			{DisplayName: "../../etc/passwd", Path: path},
		},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got, want := job.Documents[0].DisplayName, "passwd.pdf"; got != want {
		t.Errorf("DisplayName = %q, want %q", got, want)
	}
}

func TestCommitRejectsPathOutsideStagingDir(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	outside := filepath.Join(t.TempDir(), "evil.pdf")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = st.Commit(NewJob{
		Caps:      Capabilities{Web: true},
		Documents: []NewDocument{{DisplayName: "evil.pdf", Path: outside}},
	})
	if err == nil {
		t.Fatal("Commit: expected error for path outside staging dir, got nil")
	}

	// The store must not be left half-committed: capacity slot still held
	// by the reservation, and the job must not exist under any id.
	if s.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (reservation still outstanding)", s.Len())
	}

	// A parent-relative escape must also be rejected.
	escapePath := filepath.Join(st.Dir(), "..", "escaped.pdf")
	_, err = st.Commit(NewJob{
		Caps:      Capabilities{Web: true},
		Documents: []NewDocument{{DisplayName: "escaped.pdf", Path: escapePath}},
	})
	if err == nil {
		t.Fatal("Commit: expected error for ../ escape, got nil")
	}

	// So must a file that merely sits in the staging directory without
	// having been created through it - that is how a symlinked subdirectory
	// would smuggle an external file in.
	planted := filepath.Join(st.Dir(), "planted.pdf")
	if err := os.WriteFile(planted, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err = st.Commit(NewJob{
		Caps:      Capabilities{Web: true},
		Documents: []NewDocument{{DisplayName: "planted.pdf", Path: planted}},
	})
	if err == nil {
		t.Fatal("Commit: expected error for a file the staging did not create, got nil")
	}

	st.Abort()
}

func TestCapacityExhaustionAndRelease(t *testing.T) {
	s, _ := newTestStore(t, Options{MaxJobs: 2})

	st1, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve 1: %v", err)
	}
	st2, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve 2: %v", err)
	}

	if _, err := s.Reserve(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("Reserve 3: got %v, want ErrCapacity", err)
	}

	// Freeing via Abort makes room again.
	st1.Abort()
	if s.Len() != 1 {
		t.Fatalf("Len() after abort = %d, want 1", s.Len())
	}
	st3, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve after abort: %v", err)
	}

	// Commit st2, then Delete it to free the slot again.
	path := writeStagedFile(t, st2, "doc", "x")
	job, err := st2.Commit(NewJob{Caps: Capabilities{Web: true}, Documents: []NewDocument{{DisplayName: "a.pdf", Path: path}}})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len() after commit = %d, want 2 (commit keeps one slot, does not add a second)", s.Len())
	}

	if _, err := s.Reserve(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("Reserve while full: got %v, want ErrCapacity", err)
	}

	if err := s.Delete(job.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("Len() after delete = %d, want 1", s.Len())
	}

	st3.Abort()
}

func TestAbortIdempotentAndRemovesFiles(t *testing.T) {
	s, _ := newTestStore(t, Options{MaxJobs: 4})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	dir := st.Dir()
	writeStagedFile(t, st, "doc", "x")

	st.Abort()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging dir still exists after Abort: err=%v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("Len() after abort = %d, want 0", s.Len())
	}

	// Idempotent: calling again must not panic and must not double-free
	// capacity.
	st.Abort()
	st.Abort()
	if s.Len() != 0 {
		t.Fatalf("Len() after repeated abort = %d, want 0", s.Len())
	}

	// Commit after Abort must fail cleanly.
	_, err = st.Commit(NewJob{Caps: Capabilities{Web: true}})
	if err == nil {
		t.Fatal("Commit after Abort: expected error")
	}
}

func TestAbortAfterCommitIsNoop(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "x")
	job, err := st.Commit(NewJob{Caps: Capabilities{Web: true}, Documents: []NewDocument{{DisplayName: "a.pdf", Path: path}}})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	st.Abort() // must be a no-op: must not delete the now-committed job
	if _, ok := s.Get(job.ID); !ok {
		t.Fatal("job disappeared after Abort following Commit")
	}
	if _, err := os.Stat(job.Documents[0].Path); err != nil {
		t.Fatalf("job file removed by Abort-after-Commit: %v", err)
	}
}

func TestTTLExpiryRemovesFilesFromDisk(t *testing.T) {
	s, clk := newTestStore(t, Options{TTL: 10 * time.Minute})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "x")
	job, err := st.Commit(NewJob{Caps: Capabilities{Web: true}, Documents: []NewDocument{{DisplayName: "a.pdf", Path: path}}})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if n := s.CleanExpired(); n != 0 {
		t.Fatalf("CleanExpired before TTL = %d, want 0", n)
	}
	if _, err := os.Stat(job.Documents[0].Path); err != nil {
		t.Fatalf("file missing before expiry: %v", err)
	}

	clk.advance(10*time.Minute + time.Second)

	if n := s.CleanExpired(); n != 1 {
		t.Fatalf("CleanExpired after TTL = %d, want 1", n)
	}
	if _, ok := s.Get(job.ID); ok {
		t.Error("job still present after CleanExpired")
	}
	if _, err := os.Stat(job.Documents[0].Path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after expiry: err=%v", err)
	}
	// The whole job directory should be gone too.
	if _, err := os.Stat(filepath.Dir(job.Documents[0].Path)); !os.IsNotExist(err) {
		t.Fatalf("job directory still exists after expiry: err=%v", err)
	}
}

func TestStaleStagingCleanup(t *testing.T) {
	s, clk := newTestStore(t, Options{TTL: time.Hour})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	dir := st.Dir()
	writeStagedFile(t, st, "doc", "x")

	clk.advance(staleReservationAfter + time.Minute)
	s.CleanExpired()

	if s.Len() != 0 {
		t.Fatalf("Len() after stale cleanup = %d, want 0 (reservation reclaimed)", s.Len())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("stale staging dir still exists: err=%v", err)
	}
}

func TestListForUserFiltering(t *testing.T) {
	s, clk := newTestStore(t, Options{TTL: 5 * time.Minute, MaxJobs: 16})

	commit := func(web bool, recipients []string) Job {
		st, err := s.Reserve()
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		path := writeStagedFile(t, st, "doc", "x")
		job, err := st.Commit(NewJob{
			Caps:       Capabilities{Web: web},
			Recipients: recipients,
			Documents:  []NewDocument{{DisplayName: "a.pdf", Path: path}},
		})
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
		return job
	}

	// Committed first, then the clock is advanced past this store's TTL so
	// this one job (and only this one) is expired by the time we list —
	// the others below are committed after the advance, each getting a
	// fresh TTL window from "now".
	expiredJob := commit(true, []string{"alice@example.com"})
	clk.advance(6 * time.Minute) // > 5 minute TTL

	webJobAlice := commit(true, []string{"alice@example.com"})
	clk.advance(time.Minute)
	webJobBoth := commit(true, []string{"alice@example.com", "bob@example.com"})
	clk.advance(time.Minute)
	emailOnlyJob := commit(false, []string{"alice@example.com"})
	clk.advance(time.Minute)
	webJobCarol := commit(true, []string{"carol@example.com"})

	got := s.ListForUser([]string{"alice@example.com"})
	if len(got) != 2 {
		t.Fatalf("ListForUser(alice) returned %d jobs, want 2: %+v", len(got), got)
	}
	// Newest first.
	if got[0].ID != webJobBoth.ID || got[1].ID != webJobAlice.ID {
		t.Errorf("ListForUser(alice) order = [%s, %s], want [%s, %s]", got[0].ID, got[1].ID, webJobBoth.ID, webJobAlice.ID)
	}
	for _, j := range got {
		if j.ID == emailOnlyJob.ID {
			t.Error("ListForUser returned an email-only (non-web) job")
		}
		if j.ID == expiredJob.ID {
			t.Error("ListForUser returned an expired job")
		}
	}

	if got := s.ListForUser([]string{"carol@example.com"}); len(got) != 1 || got[0].ID != webJobCarol.ID {
		t.Errorf("ListForUser(carol) = %+v, want [webJobCarol]", got)
	}

	if got := s.ListForUser([]string{"nobody@example.com"}); len(got) != 0 {
		t.Errorf("ListForUser(nobody) = %+v, want empty", got)
	}

	if got := s.ListForUser(nil); len(got) != 0 {
		t.Errorf("ListForUser(nil) = %+v, want empty (never all jobs)", got)
	}
	if got := s.ListForUser([]string{}); len(got) != 0 {
		t.Errorf("ListForUser([]) = %+v, want empty", got)
	}

	// Case sensitivity: caller is expected to have lowercased; an
	// uppercase variant must not match.
	if got := s.ListForUser([]string{"Alice@example.com"}); len(got) != 0 {
		t.Errorf("ListForUser(mismatched case) = %+v, want empty (comparison is case-sensitive)", got)
	}
}

func TestListForUserDeepCopyIsolation(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "x")
	job, err := st.Commit(NewJob{
		Caps:       Capabilities{Web: true},
		Recipients: []string{"alice@example.com"},
		Documents:  []NewDocument{{DisplayName: "a.pdf", Path: path}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got := s.ListForUser([]string{"alice@example.com"})
	if len(got) != 1 {
		t.Fatalf("expected 1 job, got %d", len(got))
	}
	got[0].Recipients[0] = "mutated@example.com"
	got[0].Documents[0].DisplayName = "mutated.pdf"
	got[0].Status = StatusFailed

	stored, ok := s.Get(job.ID)
	if !ok {
		t.Fatal("job disappeared")
	}
	if stored.Recipients[0] != "alice@example.com" {
		t.Errorf("store recipient mutated via ListForUser copy: %q", stored.Recipients[0])
	}
	if stored.Documents[0].DisplayName != "a.pdf" {
		t.Errorf("store document mutated via ListForUser copy: %q", stored.Documents[0].DisplayName)
	}
	if stored.Status != StatusPending {
		t.Errorf("store status mutated via ListForUser copy: %q", stored.Status)
	}

	// Same isolation guarantee for Get.
	got2, _ := s.Get(job.ID)
	got2.Recipients[0] = "mutated2@example.com"
	stored2, _ := s.Get(job.ID)
	if stored2.Recipients[0] != "alice@example.com" {
		t.Errorf("store recipient mutated via Get copy: %q", stored2.Recipients[0])
	}
}

func TestReplaceDocument(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	oldPath := writeStagedFile(t, st, "doc", "original")
	job, err := st.Commit(NewJob{
		Caps:      Capabilities{Web: true},
		Documents: []NewDocument{{DisplayName: "a.pdf", Path: oldPath}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	docID := job.Documents[0].ID

	nf, err := s.CreateFile(job.ID, "ocr")
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if _, err := nf.WriteString("searchable pdf content"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	nf.Close()
	newPath := nf.Name()

	if err := s.ReplaceDocument(job.ID, docID, newPath, true); err != nil {
		t.Fatalf("ReplaceDocument: %v", err)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old file still exists after ReplaceDocument: err=%v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("new file missing after ReplaceDocument: %v", err)
	}

	got, ok := s.Get(job.ID)
	if !ok {
		t.Fatal("job not found")
	}
	d := got.Documents[0]
	if d.Path != newPath {
		t.Errorf("Path = %q, want %q", d.Path, newPath)
	}
	if want := int64(len("searchable pdf content")); d.Size != want {
		t.Errorf("Size = %d, want %d", d.Size, want)
	}
	if !d.OCRApplied {
		t.Error("OCRApplied = false, want true")
	}

	// Unknown job/document.
	if err := s.ReplaceDocument("no-such-job", docID, newPath, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReplaceDocument(unknown job) = %v, want ErrNotFound", err)
	}
	if err := s.ReplaceDocument(job.ID, "no-such-doc", newPath, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReplaceDocument(unknown doc) = %v, want ErrNotFound", err)
	}

	// A file the store did not create for this job must be rejected, even
	// when it sits inside the job's own directory (e.g. planted through a
	// symlinked subdirectory).
	planted := filepath.Join(filepath.Dir(newPath), "planted.pdf")
	if err := os.WriteFile(planted, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := s.ReplaceDocument(job.ID, docID, planted, true); err == nil {
		t.Error("ReplaceDocument with a file the store did not create: expected error, got nil")
	}
	outside := filepath.Join(t.TempDir(), "evil.pdf")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := s.ReplaceDocument(job.ID, docID, outside, true); err == nil {
		t.Error("ReplaceDocument with outside path: expected error, got nil")
	}
	if _, err := s.CreateFile("no-such-job", "ocr"); !errors.Is(err, ErrNotFound) {
		t.Errorf("CreateFile(unknown job) = %v, want ErrNotFound", err)
	}
}

func TestReplaceDocumentSamePathKeepsFile(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "content")
	job, err := st.Commit(NewJob{
		Caps:      Capabilities{Web: true},
		Documents: []NewDocument{{DisplayName: "a.pdf", Path: path}},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if err := s.ReplaceDocument(job.ID, job.Documents[0].ID, path, true); err != nil {
		t.Fatalf("ReplaceDocument: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file removed even though path did not change: %v", err)
	}
}

func TestSetStatusAndError(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "x")
	job, err := st.Commit(NewJob{Caps: Capabilities{Web: true}, Documents: []NewDocument{{DisplayName: "a.pdf", Path: path}}})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if err := s.SetStatus(job.ID, StatusProcessing, ""); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	got, _ := s.Get(job.ID)
	if got.Status != StatusProcessing || got.Error != "" {
		t.Errorf("got Status=%q Error=%q, want Processing/\"\"", got.Status, got.Error)
	}

	if err := s.SetStatus(job.ID, StatusFailed, "OCR failed permanently"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	got, _ = s.Get(job.ID)
	if got.Status != StatusFailed || got.Error != "OCR failed permanently" {
		t.Errorf("got Status=%q Error=%q, want Failed/\"OCR failed permanently\"", got.Status, got.Error)
	}

	// Moving away from Failed clears Error.
	if err := s.SetStatus(job.ID, StatusReady, ""); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	got, _ = s.Get(job.ID)
	if got.Error != "" {
		t.Errorf("Error = %q after leaving Failed, want \"\"", got.Error)
	}

	if err := s.SetStatus("no-such-job", StatusReady, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetStatus(unknown) = %v, want ErrNotFound", err)
	}
}

func TestDeleteUnknownID(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	if err := s.Delete("no-such-job"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(unknown) = %v, want ErrNotFound", err)
	}
}

func TestCloseRemovesEverythingAndBlocksReserve(t *testing.T) {
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	path := writeStagedFile(t, st, "doc", "x")
	job, err := st.Commit(NewJob{Caps: Capabilities{Web: true}, Documents: []NewDocument{{DisplayName: "a.pdf", Path: path}}})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	storeDir := filepath.Dir(filepath.Dir(job.Documents[0].Path))

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(storeDir); !os.IsNotExist(err) {
		t.Fatalf("store directory still exists after Close: err=%v", err)
	}
	if _, err := s.Reserve(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Reserve after Close = %v, want ErrClosed", err)
	}

	// Idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRunStopsOnContextDone(t *testing.T) {
	s, _ := newTestStore(t, Options{TTL: 4 * time.Minute}) // interval = 1 minute (min(TTL/4, 1m))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestConcurrencyRace(t *testing.T) {
	s, _ := newTestStore(t, Options{TTL: 50 * time.Millisecond, MaxJobs: 12})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	const workers = 8
	const opsPerWorker = 60

	var wg sync.WaitGroup
	var committed int64
	var capacityHits int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				switch i % 5 {
				case 0, 1:
					st, err := s.Reserve()
					if err != nil {
						if errors.Is(err, ErrCapacity) {
							atomic.AddInt64(&capacityHits, 1)
							continue
						}
						if errors.Is(err, ErrClosed) {
							continue
						}
						t.Errorf("Reserve: %v", err)
						continue
					}
					path := writeStagedFile(t, st, "doc", "x")
					if i%2 == 0 {
						job, err := st.Commit(NewJob{
							Caps:       Capabilities{Web: true},
							Recipients: []string{"alice@example.com", fmt.Sprintf("worker%d@example.com", worker)},
							Documents:  []NewDocument{{DisplayName: fmt.Sprintf("scan-%d-%d.pdf", worker, i), Path: path}},
						})
						if err != nil {
							t.Errorf("Commit: %v", err)
							continue
						}
						atomic.AddInt64(&committed, 1)
						_, _ = s.Get(job.ID)
						_ = s.SetStatus(job.ID, StatusReady, "")
					} else {
						st.Abort()
					}
				case 2:
					_ = s.ListForUser([]string{"alice@example.com"})
				case 3:
					_ = s.Len()
					_ = s.CleanExpired()
				case 4:
					_, _ = s.Get(strconv.Itoa(worker*1000 + i))
				}
			}
		}(w)
	}

	wg.Wait()
	cancel()

	if committed == 0 {
		t.Error("no jobs were ever committed; test is not exercising Commit")
	}
	// Clean up whatever is left; failures here would show up under -race.
	s.CleanExpired()
}

func TestSanitizeDisplayName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"path traversal", "../../etc/passwd", "passwd.pdf"},
		{"windows path", `C:\Users\bob\file.pdf`, "file.pdf"},
		{"crlf", "a\r\nb.pdf", "ab.pdf"},
		{"quoted", `"quoted".pdf`, "quoted.pdf"},
		{"control bytes", "a\x00\x01\x1fb.pdf", "ab.pdf"},
		{"invalid utf8", "\xff\xfefoo.pdf", "foo.pdf"},
		{"empty", "", "scan.pdf"},
		{"only separators", "///", "scan.pdf"},
		{"whitespace only", "   ", "scan.pdf"},
		{"foo.txt keeps double ext", "foo.txt", "foo.txt.pdf"},
		{"already pdf, uppercase ext kept as-is", "Report.PDF", "Report.PDF"},
		{"leading dots stripped", "...hidden.pdf", "hidden.pdf"},
		{"leading dots and space", " ..hidden.pdf", "hidden.pdf"},
		{"collapses internal whitespace", "my   scan   doc.pdf", "my scan doc.pdf"},
		{"unicode preserved", "résumé_文件.pdf", "résumé_文件.pdf"},
		{"backslash stripped", `weird\name.pdf`, "name.pdf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeDisplayName(tt.in)
			if got != tt.want {
				t.Errorf("SanitizeDisplayName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("300 char name truncated to 100 runes with extension kept", func(t *testing.T) {
		in := strings.Repeat("a", 300)
		got := SanitizeDisplayName(in)
		if n := len([]rune(got)); n != 100 {
			t.Fatalf("length = %d runes, want 100: %q", n, got)
		}
		if !strings.HasSuffix(got, ".pdf") {
			t.Fatalf("result does not end in .pdf: %q", got)
		}
	})

	t.Run("result is always valid utf-8", func(t *testing.T) {
		got := SanitizeDisplayName("\xff\xfe\x00bad")
		for _, r := range got {
			if r == '\ufffd' {
				t.Fatalf("result contains replacement rune: %q", got)
			}
		}
	})

	t.Run("result never exceeds 100 runes", func(t *testing.T) {
		in := strings.Repeat("日", 300) + ".pdf"
		got := SanitizeDisplayName(in)
		if n := len([]rune(got)); n > 100 {
			t.Fatalf("length = %d runes, want <= 100", n)
		}
	})
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := New(Options{TTL: time.Hour, MaxJobs: 1}); err == nil {
		t.Error("New with empty Root: expected error")
	}
	if _, err := New(Options{Root: t.TempDir(), MaxJobs: 1}); err == nil {
		t.Error("New with zero TTL: expected error")
	}
	if _, err := New(Options{Root: t.TempDir(), TTL: time.Hour}); err == nil {
		t.Error("New with zero MaxJobs: expected error")
	}
}

func TestReserveCommitDirPermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission bits are not enforced when running as root")
	}
	s, _ := newTestStore(t, Options{})
	st, err := s.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	fi, err := os.Stat(st.Dir())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0700 {
		t.Errorf("staging dir perm = %o, want 0700", perm)
	}

	f, err := st.CreateFile("doc")
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	defer f.Close()
	fi, err = f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("staged file perm = %o, want 0600", perm)
	}
	st.Abort()
}

func TestNewRemovesLeftoversFromAPreviousProcess(t *testing.T) {
	root := t.TempDir()

	first, err := New(Options{Root: root, TTL: time.Hour, MaxJobs: 4, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st, err := first.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	leftover := writeStagedFile(t, st, "doc", "a scan nobody will ever see again")

	// Simulate a crash: the process goes away without Close, so the files
	// are still on disk when the next process starts.
	second, err := New(Options{Root: root, TTL: time.Hour, MaxJobs: 4, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	defer second.Close()

	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover file survived a restart: err=%v", err)
	}
	if second.Len() != 0 {
		t.Errorf("Len() = %d after restart, want 0", second.Len())
	}
}
