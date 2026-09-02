package smtpin

import (
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/jobs"
	"github.com/georg-jung/scan2graph/internal/mimescan"
)

// SMTP replies for the rejection cases the session rules enumerate. Messages
// are deliberately static: none of them echo attacker-controlled input back
// onto the wire.
var (
	errUnknownSender = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "sender not recognized"}
	errRecipient     = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "recipient not accepted"}
	errNoPDF         = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "message carries no usable PDF attachment"}
	errTooComplex    = &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "message exceeds structural limits"}
	errNoCapacity    = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 1}, Message: "no capacity for another job, please retry later"}
	errAborted       = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "transaction was reset before the message was accepted"}
	errInternal      = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "temporary failure, please retry later"}
)

// session is one SMTP transaction's worth of state. It implements
// smtp.Session directly. When SMTP AUTH is required, backend.NewSession
// wraps it in authSession instead, which additionally implements
// smtp.AuthSession -- a session that does *not* implement AuthSession is how
// go-smtp is told to neither advertise nor require AUTH, which is how
// anonymous mode is expressed.
type session struct {
	cfg     *config.Config
	store   *jobs.Store
	handler Handler
	log     *slog.Logger

	// mu guards every field below it. go-smtp advertises CHUNKING
	// unconditionally and runs Session.Data on its own goroutine for BDAT,
	// while its command loop concurrently serves RSET (Reset), QUIT and a
	// dropped connection (Logout) -- so these fields have two writers.
	mu sync.Mutex

	authenticated bool

	// generation identifies the current transaction. Reset bumps it, which
	// is how a Data call that is still running for an already-aborted
	// transaction learns that it must not commit anything.
	generation uint64

	// Transaction state, valid between Mail and Data/Reset.
	staging    *jobs.Staging // set only while Data is reserving/using it
	profile    string        // canonical envelope sender
	caps       config.Capabilities
	recipients []string // canonical, deduplicated, in RCPT order
}

// Reset discards the current transaction. Bumping the generation invalidates
// a Data call that may still be running on go-smtp's BDAT goroutine: it will
// abort instead of committing a message the client never got a 250 for.
func (s *session) Reset() {
	s.mu.Lock()
	staging := s.staging
	s.staging = nil
	s.generation++
	s.profile = ""
	s.caps = config.Capabilities{}
	s.recipients = nil
	s.mu.Unlock()

	// Outside the lock: Abort removes files. It is idempotent, so a Data
	// call unwinding concurrently may abort the same staging again.
	if staging != nil {
		staging.Abort()
	}
}

// Logout frees any resources the session holds.
func (s *session) Logout() error {
	s.Reset()
	return nil
}

// Mail selects the sender profile for envelopeSender via cfg.Profile. AUTH
// (when required) must already have succeeded.
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	// go-smtp accepts a second MAIL FROM without an intervening RSET, so the
	// previous transaction is discarded here rather than only in Reset --
	// otherwise its recipients and profile would carry over into this one.
	s.Reset()

	s.mu.Lock()
	authenticated := s.authenticated
	s.mu.Unlock()
	if !s.cfg.SMTPAllowAnonymous && !authenticated {
		s.reject("mail", smtp.ErrAuthRequired)
		return smtp.ErrAuthRequired
	}
	caps, ok := s.cfg.Profile(from)
	if !ok {
		s.reject("mail", errUnknownSender)
		return errUnknownSender
	}
	s.mu.Lock()
	s.profile = config.NormalizeAddress(from)
	s.caps = caps
	s.mu.Unlock()
	return nil
}

// Rcpt normalizes and authorizes one recipient, deduplicating repeats: the
// job and the web UI match a signed-in user against these addresses, so both
// sides have to have spelled them the same way. MaxRecipients (set on the
// *smtp.Server) bounds how many are accepted.
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	canon := config.NormalizeAddress(to)
	if canon == "" || !s.cfg.RecipientAllowed(canon) {
		s.reject("rcpt", errRecipient)
		return errRecipient
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.recipients, canon) {
		s.recipients = append(s.recipients, canon)
	}
	return nil
}

// Data reserves job-store capacity, extracts the PDF attachments, commits
// the job and hands it to the pipeline, replying 250 only once all of that
// succeeded. Every error path aborts the staging it reserved; the success
// path must not.
func (s *session) Data(r io.Reader) error {
	// Snapshot the transaction together with its generation, and take the
	// capacity slot, before a single body byte is read: from here on the
	// command loop may reset this session at any moment.
	s.mu.Lock()
	staging, err := s.store.Reserve()
	if err != nil {
		s.mu.Unlock()
		s.reject("data", errNoCapacity)
		return errNoCapacity
	}
	gen, profile, caps := s.generation, s.profile, s.caps
	recipients := slices.Clone(s.recipients)
	s.staging = staging
	s.mu.Unlock()

	// mimescan deliberately treats a read error as "end of this part": right
	// for a truncated attachment, wrong for the server's own errors
	// (ErrDataTooLarge, ErrTooLongLine, ErrDataReset), which must reach the
	// client instead of yielding a truncated job with a 250.
	src := &errReader{r: r}
	result, err := mimescan.Extract(src, func() (*os.File, error) { return staging.CreateFile("pdf") })
	// Every answer of 250 has to read the message to its end first. With
	// BDAT that only happens when the client sends the final chunk, and
	// Extract stops at the closing MIME boundary long before: answering
	// earlier would accept a transaction the client is still free to abort,
	// and with CHUNKING it does not even reach the client - go-smtp closes
	// the pipe under the unread remainder and answers 554 instead. It is
	// also what makes the size limit apply to a message this code would
	// otherwise never finish reading.
	if err == nil || errors.Is(err, mimescan.ErrNoAttachments) {
		_, _ = io.Copy(io.Discard, src)
	}
	if src.err != nil {
		err = src.err
	}

	docs := make([]jobs.NewDocument, len(result.PDFs))
	var totalBytes int64
	for i, p := range result.PDFs {
		docs[i] = jobs.NewDocument{DisplayName: p.DisplayName, Path: p.Path}
		totalBytes += p.Size
	}

	// Hand the transaction over under the lock, so a concurrent Reset (RSET,
	// QUIT, a dropped connection) either aborts this transaction or finds it
	// already committed -- never both, and never neither. Today go-smtp keeps
	// its command loop parked between the reader reaching EOF and Data
	// returning, so the race cannot actually occur; holding the lock across
	// the handover means this stays correct without depending on that.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staging = nil

	switch {
	case s.generation != gen:
		staging.Abort()
		s.reject("data", errAborted)
		return errAborted
	case errors.Is(err, mimescan.ErrNoAttachments):
		// A printer's "test connection" button sends a message with nothing
		// attached. Refusing it makes a working setup look broken on the
		// device's panel, so it is accepted and dropped: no job, no mail,
		// nothing to expire. A message that does carry files but no usable
		// PDF still gets a 550 below - that one is a printer set to JPEG,
		// and the rejection is the only way it will ever be told.
		staging.Abort()
		s.log.Info("smtpin: accepted a message with nothing attached", "profile", profile, "recipients", len(recipients))
		return nil
	case err != nil:
		staging.Abort()
		se := extractError(err)
		s.reject("data", se)
		return se
	}

	job, err := staging.Commit(jobs.NewJob{
		Profile:    profile,
		Caps:       jobs.Capabilities{Email: caps.Email, Web: caps.Web, OCR: caps.OCR},
		Subject:    result.Subject,
		Recipients: recipients,
		Documents:  docs,
	})
	if err != nil {
		staging.Abort()
		s.log.Warn("smtpin: commit failed", "err", err)
		s.reject("data", errInternal)
		return errInternal
	}

	if err := s.handler.Enqueue(job); err != nil {
		s.log.Warn("smtpin: enqueue failed", "err", err, "job_id", job.ID)
		s.store.Delete(job.ID)
		s.reject("data", errInternal)
		return errInternal
	}

	s.log.Info("smtpin: accepted",
		"profile", profile,
		"recipients", len(recipients),
		"pdfs", len(docs),
		"bytes", totalBytes,
		"job_id", job.ID,
	)
	return nil
}

// reject logs one rejection line: reason and reply code, never the address,
// subject, body or any credential involved.
func (s *session) reject(stage string, err *smtp.SMTPError) {
	s.log.Info("smtpin: rejected", "stage", stage, "code", err.Code, "reason", err.Message)
}

// errReader records the first non-EOF read error so Data can map that error
// to the reply, instead of the "no usable PDF" a partially read message
// would otherwise look like.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF && e.err == nil {
		e.err = err
	}
	return n, err
}

// extractError maps a mimescan.Extract error to the SMTP reply it earns. An
// *smtp.SMTPError anywhere in the chain (e.g. the server's own message-size
// limit, hit while streaming the body) is passed through unchanged.
func extractError(err error) *smtp.SMTPError {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se
	}
	switch {
	case errors.Is(err, mimescan.ErrTooComplex):
		return errTooComplex
	case errors.Is(err, mimescan.ErrStorage):
		return errInternal // a local failure: the printer should retry
	default: // mimescan.ErrNoPDF, or a message that did not parse at all
		return errNoPDF
	}
}

// authSession is a session with SMTP AUTH support: PLAIN and LOGIN, both
// verified with constant-time comparisons. Embedding lets Reset/Logout/
// Mail/Rcpt/Data pass through unchanged while adding smtp.AuthSession.
type authSession struct {
	*session
}

func (a *authSession) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (a *authSession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(_, username, password string) error {
			return a.authenticate(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{authenticate: a.authenticate}, nil
	default:
		return nil, smtp.ErrAuthUnsupported
	}
}

// authenticate verifies credentials with crypto/subtle.ConstantTimeCompare,
// comparing both username and password even once one has already mismatched.
func (a *authSession) authenticate(username, password string) error {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.cfg.SMTPUsername)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.cfg.SMTPPassword)) == 1
	if !userOK || !passOK {
		a.reject("auth", smtp.ErrAuthFailed)
		return smtp.ErrAuthFailed
	}
	a.mu.Lock()
	a.authenticated = true
	a.mu.Unlock()
	return nil
}

// loginServer implements the SMTP LOGIN authentication mechanism as a
// sasl.Server. go-sasl ships a LOGIN client but, deliberately, no server --
// old scanners frequently speak only LOGIN, never PLAIN, so this is ours to
// write. go-smtp stops calling Next once done is true, so there is no step
// beyond the one that returns done -- a trailing return covers it.
type loginServer struct {
	authenticate func(username, password string) error

	step     int
	username string
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		// No initial response: prompt for the username first.
		if response == nil {
			l.step = 1
			return []byte("Username:"), false, nil
		}
		// An initial response supplied the username already.
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 1:
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		return nil, true, l.authenticate(l.username, string(response))
	}
	return
}
