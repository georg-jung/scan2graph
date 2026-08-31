package jobs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Sentinel errors returned by Store and Staging methods. Callers may branch
// on these with errors.Is.
var (
	ErrCapacity = errors.New("jobs: store is at capacity")
	ErrClosed   = errors.New("jobs: store is closed")
	ErrNotFound = errors.New("jobs: not found")
)

// staleReservationAfter is the leak-protection threshold: a reservation
// that is neither committed nor aborted within this long is treated as a
// bug and cleaned up by CleanExpired.
const staleReservationAfter = 15 * time.Minute

// Options configures a Store.
type Options struct {
	// Root is the parent directory; the store creates its own private
	// subdirectory inside it and never writes outside that subdirectory.
	// It is created (0700) if it does not already exist.
	Root string

	// TTL is how long a job stays visible before CleanExpired removes it.
	// ExpiresAt is ReceivedAt + TTL at commit, and starts again from the
	// moment the job becomes ready (see SetStatus).
	TTL time.Duration

	// MaxJobs bounds outstanding reservations plus committed jobs.
	MaxJobs int

	// Now, if set, replaces time.Now for testing.
	Now func() time.Time

	// Logger, if set, replaces slog.Default().
	Logger *slog.Logger
}

// Store is the ephemeral, disk-backed job store described in the package
// doc comment. All exported methods are safe for concurrent use.
//
// Locking: a single mutex guards the jobs/reservations bookkeeping. File
// I/O (creating/removing directories and files) is deliberately done
// outside the critical section wherever the bookkeeping doesn't strictly
// require it to be atomic with a disk operation, so a slow filesystem never
// blocks unrelated Get/List/SetStatus calls.
type Store struct {
	dir     string
	ttl     time.Duration
	maxJobs int
	now     func() time.Time
	log     *slog.Logger

	mu           sync.Mutex
	jobs         map[string]*jobRecord
	reservations map[string]*reservation
	closed       bool
}

// jobRecord is the store's internal bookkeeping for one committed job. dir
// is tracked explicitly (rather than derived from Documents) so a job's
// directory can always be found and removed, even for a document-less job.
type jobRecord struct {
	job Job
	dir string
	// files are the paths this store created for the job (staged documents
	// plus anything CreateFile produced later). Only these may ever be
	// referenced by a Document, which is what keeps a symlink or a stray
	// path from turning into "serve this arbitrary file".
	files map[string]bool
}

// reservation is the store's internal bookkeeping for one outstanding
// Staging that has not yet been committed or aborted.
type reservation struct {
	dir        string
	reservedAt time.Time
}

// New creates a Store with its own private subdirectory inside opts.Root.
func New(opts Options) (*Store, error) {
	if opts.Root == "" {
		return nil, errors.New("jobs: Options.Root is required")
	}
	if opts.TTL <= 0 {
		return nil, errors.New("jobs: Options.TTL must be positive")
	}
	if opts.MaxJobs <= 0 {
		return nil, errors.New("jobs: Options.MaxJobs must be positive")
	}

	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("jobs: resolve root directory: %w", err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("jobs: create root directory: %w", err)
	}
	// A fixed directory name, wiped on startup: nothing here survives a
	// restart by design, so files left behind by a previous (crashed)
	// process are garbage that would otherwise fill the temp directory
	// forever. This assumes one instance per root, which is the appliance's
	// deployment model.
	dir := filepath.Join(root, "scan2graph")
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("jobs: remove leftover store directory: %w", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, fmt.Errorf("jobs: create store directory: %w", err)
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Store{
		dir:          dir,
		ttl:          opts.TTL,
		maxJobs:      opts.MaxJobs,
		now:          now,
		log:          logger,
		jobs:         make(map[string]*jobRecord),
		reservations: make(map[string]*reservation),
	}, nil
}

// Reserve takes one capacity slot and creates a private staging directory
// for a new job. The caller must eventually call Commit or Abort on the
// returned Staging so the slot is freed. Returns ErrCapacity when the store
// is full (len(jobs)+outstanding reservations >= MaxJobs) and ErrClosed
// after Close.
func (s *Store) Reserve() (*Staging, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if len(s.jobs)+len(s.reservations) >= s.maxJobs {
		s.mu.Unlock()
		return nil, ErrCapacity
	}
	id, err := newID()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	dir := filepath.Join(s.dir, id)
	s.reservations[id] = &reservation{dir: dir, reservedAt: s.now()}
	s.mu.Unlock()

	if err := os.MkdirAll(dir, 0700); err != nil {
		s.releaseReservation(id)
		return nil, fmt.Errorf("jobs: create staging directory: %w", err)
	}

	// Close may have run while the directory was being created, in which case
	// it already removed the store tree and dropped this reservation. Undo
	// the directory rather than handing out a Staging on a closed store.
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		s.releaseReservation(id)
		os.RemoveAll(dir)
		return nil, ErrClosed
	}

	return &Staging{store: s, id: id, dir: dir, files: make(map[string]bool)}, nil
}

// releaseReservation drops reservation id, freeing its capacity slot. It
// does not touch the filesystem.
func (s *Store) releaseReservation(id string) {
	s.mu.Lock()
	delete(s.reservations, id)
	s.mu.Unlock()
}

// commitReservation atomically turns reservation id into job, keeping the
// same capacity slot (one reservation becomes exactly one job, never two
// slots). It fails if the store is closed or the reservation is already
// gone (double commit/abort).
func (s *Store) commitReservation(id string, job Job, dir string, files map[string]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, ok := s.reservations[id]; !ok {
		return fmt.Errorf("jobs: reservation %s is gone", id)
	}
	delete(s.reservations, id)
	s.jobs[job.ID] = &jobRecord{job: job, dir: dir, files: files}
	return nil
}

// live reports whether a job is still there to be seen. It is the single
// definition of "expired" in this package: every reader and the sweep use
// it, so a job can never be hidden from the web UI while its files are
// still on disk, or the other way round.
//
// A job a worker is holding is always live: the download window starts when
// the pipeline finishes with it (see SetStatus), so until then the deadline
// on the record is the arrival one and has nothing to say yet. The worker's
// own budget bounds how long that can last, so nothing leaks for ever.
func live(j Job, now time.Time) bool {
	return j.Status == StatusProcessing || now.Before(j.ExpiresAt)
}

// Get returns a deep copy of the job with the given id. Expired jobs are
// reported as missing even before CleanExpired has removed them, so callers
// never have to repeat the TTL check themselves.
func (s *Store) Get(id string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.jobs[id]
	if !ok || !live(rec.job, s.now()) {
		return Job{}, false
	}
	return cloneJob(rec.job), true
}

// ListForUser returns deep copies of every non-expired, web-visible job
// whose Recipients contain at least one of identities, sorted newest
// first. identities must already be canonical; matching is case-sensitive
// (the caller is expected to have lowercased). An empty or nil identities
// returns an empty result, never every job.
func (s *Store) ListForUser(identities []string) []Job {
	if len(identities) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(identities))
	for _, id := range identities {
		if id == "" {
			continue
		}
		want[id] = struct{}{}
	}
	if len(want) == 0 {
		return nil
	}

	s.mu.Lock()
	now := s.now()
	out := make([]Job, 0, len(s.jobs))
	for _, rec := range s.jobs {
		j := rec.job
		if !j.Caps.Web || !live(j, now) {
			continue
		}
		recipient := false
		for _, r := range j.Recipients {
			if _, ok := want[r]; ok {
				recipient = true
				break
			}
		}
		if !recipient {
			continue
		}
		out = append(out, cloneJob(j))
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, k int) bool { return out[i].ReceivedAt.After(out[k].ReceivedAt) })
	return out
}

// SetStatus updates a job's lifecycle status. errMsg is kept only when st
// is StatusFailed; it is cleared for every other status, preserving the
// invariant that Error is "" unless the job failed.
func (s *Store) SetStatus(id string, st Status, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.jobs[id]
	if !ok {
		return fmt.Errorf("jobs: set status: job %s: %w", id, ErrNotFound)
	}
	rec.job.Status = st
	if st == StatusFailed {
		rec.job.Error = errMsg
	} else {
		rec.job.Error = ""
	}
	// The TTL is how long a finished scan can be picked up, so it starts
	// when the job reaches its final state. Measured from arrival instead,
	// work slower than the TTL would produce a job that is finished and
	// expired in the same instant, invisible to the person it was scanned
	// for - and a failed job needs the window as much as a ready one,
	// because its notice mail links to the scan it could not deliver.
	if st == StatusReady || st == StatusFailed {
		rec.job.ExpiresAt = s.now().Add(s.ttl)
	}
	return nil
}

// ReplaceDocument swaps in a processed file (e.g. the searchable PDF
// produced by OCR) for an existing document and deletes the previous file
// if its path changed. newPath must be inside the job's own directory.
func (s *Store) ReplaceDocument(jobID, docID, newPath string, ocrApplied bool) error {
	fi, err := os.Lstat(newPath)
	if err != nil {
		return fmt.Errorf("jobs: replace document: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("jobs: replace document: %q is not a regular file", newPath)
	}

	s.mu.Lock()
	rec, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("jobs: replace document: job %s: %w", jobID, ErrNotFound)
	}
	if !rec.files[filepath.Clean(newPath)] {
		s.mu.Unlock()
		return fmt.Errorf("jobs: replace document: %q was not created by this store", newPath)
	}
	idx := -1
	for i := range rec.job.Documents {
		if rec.job.Documents[i].ID == docID {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return fmt.Errorf("jobs: replace document: document %s: %w", docID, ErrNotFound)
	}
	cleanPath := filepath.Clean(newPath)
	oldPath := rec.job.Documents[idx].Path
	rec.job.Documents[idx].Path = cleanPath
	rec.job.Documents[idx].Size = fi.Size()
	rec.job.Documents[idx].OCRApplied = ocrApplied
	s.mu.Unlock()

	if oldPath != cleanPath {
		if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
			s.log.Warn("jobs: failed to remove replaced document file", "job_id", jobID, "err", err)
		}
	}
	return nil
}

// CreateFile creates a new, empty 0600 file inside a committed job's
// directory and registers it, so it can later be passed to ReplaceDocument.
// This is how processed documents (e.g. a searchable PDF) get on disk.
func (s *Store) CreateFile(jobID, prefix string) (*os.File, error) {
	s.mu.Lock()
	rec, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("jobs: create file: job %s: %w", jobID, ErrNotFound)
	}
	dir := rec.dir
	s.mu.Unlock()

	f, err := createTempFile(dir, prefix)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	rec, ok = s.jobs[jobID]
	if !ok {
		// The job was deleted or expired while the file was being created.
		s.mu.Unlock()
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("jobs: create file: job %s: %w", jobID, ErrNotFound)
	}
	rec.files[f.Name()] = true
	s.mu.Unlock()
	return f, nil
}

// Delete removes a job's metadata and its directory. Directory removal is
// best-effort: a failure is logged at warn (with the job id, never the
// subject) but the metadata is dropped regardless.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	rec, ok := s.jobs[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("jobs: delete: job %s: %w", id, ErrNotFound)
	}
	delete(s.jobs, id)
	s.mu.Unlock()

	if err := os.RemoveAll(rec.dir); err != nil {
		s.log.Warn("jobs: failed to remove job directory", "job_id", id, "err", err)
	}
	return nil
}

// CleanExpired deletes every job past its ExpiresAt and every staging
// directory reserved more than 15 minutes ago that was never committed or
// aborted (a leak; logged at warn since it indicates a bug in the caller).
// It returns the number of jobs removed.
func (s *Store) CleanExpired() int {
	now := s.now()

	type removal struct{ id, dir string }
	var expiredJobs, leaked []removal

	s.mu.Lock()
	for id, rec := range s.jobs {
		if !live(rec.job, now) {
			expiredJobs = append(expiredJobs, removal{id, rec.dir})
			delete(s.jobs, id)
		}
	}
	for id, r := range s.reservations {
		if now.Sub(r.reservedAt) > staleReservationAfter {
			leaked = append(leaked, removal{id, r.dir})
			delete(s.reservations, id)
		}
	}
	s.mu.Unlock()

	for _, j := range expiredJobs {
		if err := os.RemoveAll(j.dir); err != nil {
			s.log.Warn("jobs: failed to remove expired job directory", "job_id", j.id, "err", err)
		}
	}
	for _, r := range leaked {
		s.log.Warn("jobs: staging reservation was never committed or aborted, cleaning up", "reservation_id", r.id)
		if err := os.RemoveAll(r.dir); err != nil {
			s.log.Warn("jobs: failed to remove leaked staging directory", "reservation_id", r.id, "err", err)
		}
	}

	return len(expiredJobs)
}

// Run calls CleanExpired on a ticker (min(TTL/4, 1 minute)) until ctx is
// done, then returns.
func (s *Store) Run(ctx context.Context) {
	interval := s.ttl / 4
	if interval <= 0 || interval > time.Minute {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CleanExpired()
		}
	}
}

// Len reports how many capacity slots are currently occupied: committed
// jobs plus outstanding reservations (see Options.MaxJobs).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobs) + len(s.reservations)
}

// Close stops the store from accepting new reservations and removes its
// entire directory tree, including every job's and every outstanding
// staging's files. It is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	dir := s.dir
	s.jobs = make(map[string]*jobRecord)
	s.reservations = make(map[string]*reservation)
	s.mu.Unlock()

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("jobs: close: remove store directory: %w", err)
	}
	return nil
}

// stagingState tracks whether a Staging is still open, has been committed,
// or has been aborted, so Commit/Abort can be made idempotent/safe.
type stagingState int

const (
	stagingOpen stagingState = iota
	stagingCommitted
	stagingAborted
)

// Staging is a reserved, private directory for one not-yet-committed job.
// It is obtained from Store.Reserve and must end in exactly one call to
// Commit or Abort.
type Staging struct {
	store *Store
	id    string
	dir   string

	mu    sync.Mutex
	state stagingState
	files map[string]bool
}

// Dir returns the staging directory's absolute path.
func (st *Staging) Dir() string { return st.dir }

// CreateFile creates a new, empty, 0600 file inside the staging directory.
// The name is generated by os.CreateTemp so it can neither collide nor be
// predicted from prefix alone.
func (st *Staging) CreateFile(prefix string) (*os.File, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.state != stagingOpen {
		return nil, fmt.Errorf("jobs: staging %s is no longer open", st.id)
	}
	f, err := createTempFile(st.dir, prefix)
	if err != nil {
		return nil, err
	}
	st.files[f.Name()] = true
	return f, nil
}

// createTempFile creates a 0600 file with an unpredictable name inside dir.
func createTempFile(dir, prefix string) (*os.File, error) {
	if prefix == "" {
		prefix = "doc"
	}
	// os.CreateTemp rejects a pattern containing a path separator itself.
	f, err := os.CreateTemp(dir, prefix+"-*")
	if err != nil {
		return nil, fmt.Errorf("jobs: create file: %w", err)
	}
	return f, nil
}

// Commit turns the staging directory into a committed job and returns a
// deep copy of it. Every document's Path must be inside the staging
// directory (checked with filepath.Clean plus a separator-bounded prefix
// check); Commit rejects the whole job otherwise, before creating or
// mutating anything. Calling Commit a second time, or after Abort, returns
// an error without side effects.
func (st *Staging) Commit(n NewJob) (Job, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	switch st.state {
	case stagingCommitted:
		return Job{}, fmt.Errorf("jobs: staging %s was already committed", st.id)
	case stagingAborted:
		return Job{}, fmt.Errorf("jobs: staging %s was already aborted", st.id)
	}

	if len(n.Documents) == 0 {
		return Job{}, errors.New("jobs: commit requires at least one document")
	}

	docs := make([]Document, 0, len(n.Documents))
	for _, d := range n.Documents {
		// Only files this staging created are acceptable. That is stricter
		// than a path check and immune to symlinks anywhere in the path.
		if !st.files[d.Path] {
			return Job{}, fmt.Errorf("jobs: document %q was not created by this staging", d.Path)
		}
		// Lstat, not Stat: a job must never be committed for a missing file,
		// and a document is always a regular file.
		fi, err := os.Lstat(d.Path)
		if err != nil {
			return Job{}, fmt.Errorf("jobs: document file: %w", err)
		}
		if !fi.Mode().IsRegular() {
			return Job{}, fmt.Errorf("jobs: document path %q is not a regular file", d.Path)
		}
		docID, err := newID()
		if err != nil {
			return Job{}, err
		}
		docs = append(docs, Document{
			ID:          docID,
			DisplayName: SanitizeDisplayName(d.DisplayName),
			Path:        filepath.Clean(d.Path),
			Size:        fi.Size(),
		})
	}

	jobID, err := newID()
	if err != nil {
		return Job{}, err
	}

	now := st.store.now()
	job := Job{
		ID:         jobID,
		ReceivedAt: now,
		ExpiresAt:  now.Add(st.store.ttl),
		Profile:    n.Profile,
		Caps:       n.Caps,
		Subject:    SanitizeSubject(n.Subject),
		Recipients: append([]string(nil), n.Recipients...),
		Documents:  docs,
		Status:     StatusPending,
	}

	files := make(map[string]bool, len(st.files))
	for f := range st.files {
		files[f] = true
	}
	if err := st.store.commitReservation(st.id, job, st.dir, files); err != nil {
		return Job{}, err
	}
	st.state = stagingCommitted

	return cloneJob(job), nil
}

// Abort releases the reservation's capacity slot and removes the staging
// directory. It is idempotent, and a no-op if the staging was already
// committed.
func (st *Staging) Abort() {
	st.mu.Lock()
	if st.state != stagingOpen {
		st.mu.Unlock()
		return
	}
	st.state = stagingAborted
	st.mu.Unlock()

	st.store.releaseReservation(st.id)

	if err := os.RemoveAll(st.dir); err != nil {
		st.store.log.Warn("jobs: failed to remove aborted staging directory", "reservation_id", st.id, "err", err)
	}
}

// newID returns an unguessable, URL-safe id: 16 bytes from crypto/rand,
// base64 RawURL encoded.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("jobs: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
