// Package jobs implements scan2graph's ephemeral, disk-backed job store.
//
// There is no database and no persistence: job metadata lives only in
// process memory, and each job's files live in a private temporary
// directory owned by the store. A process crash or restart loses every
// in-flight and web-visible job; that is a deliberate trade-off for an
// appliance that otherwise needs zero operational care (see README.md).
package jobs

import (
	"strings"
	"time"
	"unicode"
)

// Capabilities is the feature set a job was created under, derived from the
// sender profile that accepted the SMTP envelope.
type Capabilities struct {
	Email bool
	Web   bool
	OCR   bool
}

// Status is a job's lifecycle state.
type Status string

const (
	StatusPending    Status = "pending"
	StatusProcessing Status = "processing"
	StatusReady      Status = "ready"
	StatusFailed     Status = "failed"
)

// Document is one PDF belonging to a job.
type Document struct {
	ID          string // unguessable, URL-safe
	DisplayName string // sanitized, for UI + Content-Disposition only
	Path        string // absolute path of the file to serve/send right now
	Size        int64
	OCRApplied  bool
}

// Job is one accepted scan: its metadata and the documents it produced.
type Job struct {
	ID         string
	ReceivedAt time.Time
	ExpiresAt  time.Time
	Profile    string // canonical envelope sender that selected the profile
	Caps       Capabilities
	Subject    string   // decoded, may be ""
	Recipients []string // canonical recipient identities
	Documents  []Document
	Status     Status
	Error      string // short, user-safe failure reason; "" unless Status == StatusFailed
}

// NewJob describes a job to be created by Staging.Commit.
type NewJob struct {
	Profile    string
	Caps       Capabilities
	Subject    string
	Recipients []string
	Documents  []NewDocument
}

// NewDocument describes one document to attach to a NewJob. Path must point
// at a regular file inside the staging directory it was reserved for;
// Staging.Commit rejects the job otherwise and takes the size from the file.
type NewDocument struct {
	DisplayName string
	Path        string
}

// cloneJob returns a deep copy of j so callers holding it cannot mutate
// store state. Document has no reference fields of its own, so copying the
// slice headers of Recipients and Documents is sufficient.
func cloneJob(j Job) Job {
	out := j
	out.Recipients = append([]string(nil), j.Recipients...)
	out.Documents = append([]Document(nil), j.Documents...)
	return out
}

// SanitizeSubject turns a decoded, possibly hostile MIME subject into
// something safe to put back into an outgoing Subject: header and to show in
// the web UI. Non-printable runes are dropped -- control characters, and
// with them the CR/LF a subject would otherwise inject its own headers with
// -- whitespace of any kind becomes a plain space and runs of it collapse,
// and the result is trimmed, valid UTF-8 and at most 200 runes, so a
// megabyte-sized subject cannot be parked in memory for a whole TTL. May
// legitimately return "".
func SanitizeSubject(subject string) string {
	const maxRunes = 200

	subject = strings.ToValidUTF8(subject, "")

	var b strings.Builder
	b.Grow(len(subject))
	for _, r := range subject {
		switch {
		case unicode.IsSpace(r):
			b.WriteRune(' ') // a folded or multi-line subject keeps its words apart
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}

	subject = strings.Join(strings.Fields(b.String()), " ")
	if r := []rune(subject); len(r) > maxRunes {
		subject = strings.TrimSpace(string(r[:maxRunes]))
	}
	return subject
}

// SanitizeDisplayName turns an arbitrary, possibly hostile attachment
// filename into something safe to show in the web UI and to echo back in a
// Content-Disposition header: directory components are stripped, control
// characters (including CR/LF), quotes, backslashes and slashes are
// dropped, leading dots are stripped, whitespace is collapsed, the result
// is valid UTF-8, at most 100 runes (extension preserved when possible),
// and always ends in ".pdf" (case-insensitive check; appended if missing).
// Falls back to "scan.pdf" when nothing usable survives.
func SanitizeDisplayName(name string) string {
	const fallback = "scan.pdf"
	const maxRunes = 100

	name = strings.ToValidUTF8(name, "")

	// Strip directory components. Treat both slash styles as separators
	// since the original filename may come from any OS.
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}

	// Drop non-printable characters (control characters including CR/LF,
	// but also zero-width and bidi-override runes that could disguise a
	// filename) and characters that are unsafe in a Content-Disposition
	// header or on common filesystems.
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch r {
		case '"', '\'', '\\', '/':
			continue
		}
		if !unicode.IsPrint(r) && r != ' ' {
			continue
		}
		b.WriteRune(r)
	}
	name = b.String()

	// Collapse whitespace runs to a single space, then strip leading dots
	// (in that order, so " ..name" is also caught) and trim again.
	name = strings.Join(strings.Fields(name), " ")
	name = strings.TrimLeft(name, ".")
	name = strings.TrimSpace(name)

	if name == "" {
		return fallback
	}

	if !strings.HasSuffix(strings.ToLower(name), ".pdf") {
		name += ".pdf"
	}

	// Truncate to at most maxRunes runes, keeping the ".pdf" suffix just
	// guaranteed above.
	if r := []rune(name); len(r) > maxRunes {
		name = string(r[:maxRunes-len(".pdf")]) + ".pdf"
	}
	if name == "" {
		return fallback
	}
	return name
}
