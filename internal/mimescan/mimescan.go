// Package mimescan extracts PDF attachments from the MIME message a scanner
// sends.
//
// This is the application's untrusted-input boundary: the message arrives on a
// LAN socket from a device nobody audits. The walk is therefore bounded in
// every direction (part count, nesting depth, PDFs per message), streams
// attachment bytes straight to disk instead of buffering them, and prefers
// skipping a part over failing the whole message wherever the rest of it is
// still usable.
package mimescan

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
)

// Structural limits. Deliberately constants and not configuration: no real
// scanner comes anywhere near them, and a message that does is hostile.
const (
	maxParts = 100 // MIME parts in the whole tree
	maxDepth = 10  // multipart nesting levels
	maxPDFs  = 16  // PDF attachments per message

	// headBytes is how much decoded data is buffered before a file is
	// created, so a part that only claims to be a PDF leaves nothing behind.
	headBytes = 1024
	// tailBytes is the window at the end of a document that must contain the
	// %%EOF marker. 4 KiB, because scanners pad an attachment out to a block
	// boundary and a kilobyte of that padding is not unusual.
	tailBytes = 4096
)

// Sentinel errors. Callers branch on these with errors.Is; the SMTP layer maps
// them to reply codes.
var (
	ErrTooComplex = errors.New("mimescan: message exceeds structural limits")
	ErrNoPDF      = errors.New("mimescan: no PDF attachment found")
	// ErrNoAttachments is a message that carried nothing and was structurally
	// sound while doing so - a connection test, in practice. A message whose
	// attachments were simply not PDFs gets ErrNoPDF, and so does one whose
	// containers were too broken to show what they held: the SMTP layer
	// answers the two differently, and a hidden scan must not be mistaken
	// for an empty message.
	ErrNoAttachments = errors.New("mimescan: message has no attachments")
	// ErrStorage wraps a failure to create or write an attachment file. It
	// is about this machine, not about the message, so the caller must fail
	// temporarily instead of rejecting the scan.
	ErrStorage = errors.New("mimescan: storing an attachment failed")
)

var (
	pdfMagic = []byte("%PDF-")
	pdfEOF   = []byte("%%EOF")
)

// Result is what one message yielded.
type Result struct {
	Subject string // decoded, "" when absent or undecodable
	PDFs    []PDF
}

// PDF is one extracted attachment.
type PDF struct {
	DisplayName string // filename as it appeared, decoded but NOT sanitized
	Path        string // the file newFile() produced
	Size        int64  // decoded bytes written
}

// Extract reads one RFC 5322 message from r, walks it (including nested
// multiparts) and writes every PDF attachment to a file obtained from
// newFile. The caller is expected to bound the size of r; Extract enforces the
// structural limits.
//
// A part is taken to be a PDF when its decoded bytes start with %PDF- and
// carry %%EOF in the last few kilobytes; everything else is skipped silently.
// What a part claims to be -- media type, filename -- is deliberately not
// consulted: the magic bytes already answer the question, while the claims
// are unreliable in both directions (scanners send PDFs as
// application/octet-stream without a filename, or with a filename and no
// Content-Type at all). newFile is called only once a part's decoded prefix
// has been seen to start with %PDF-, and a file that is created but then
// rejected is removed again, so a caller never sees a file it does not get a
// PDF for.
//
// On error nothing is left on disk and Result.PDFs is empty (Result.Subject is
// still filled in where the headers parsed). Returns ErrNoAttachments when the
// message carried no files and nothing about it was malformed, ErrNoPDF when
// it carried files -- or a container too broken to yield them -- but no usable
// PDF, and ErrStorage when writing an attachment failed for a local reason.
func Extract(r io.Reader, newFile func() (*os.File, error)) (Result, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return Result{}, fmt.Errorf("mimescan: parse message: %w", err)
	}
	e := extractor{newFile: newFile}
	e.words.CharsetReader = latin1Reader
	res := Result{Subject: e.decode(msg.Header.Get("Subject"))}
	if err := e.walk(textproto.MIMEHeader(msg.Header), msg.Body, 0); err != nil {
		for _, p := range e.pdfs {
			os.Remove(p.Path)
		}
		return res, err
	}
	if len(e.pdfs) == 0 {
		if e.attach == 0 {
			return res, ErrNoAttachments
		}
		return res, ErrNoPDF
	}
	res.PDFs = e.pdfs
	return res, nil
}

// extractor carries the state of one walk.
type extractor struct {
	newFile func() (*os.File, error)
	words   mime.WordDecoder
	parts   int
	attach  int // parts that carried a file, whatever its type
	pdfs    []PDF
}

// walk processes one node of the MIME tree: a multipart container, whose
// children are walked recursively, or a leaf that may be a PDF.
func (e *extractor) walk(h textproto.MIMEHeader, body io.Reader, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: MIME nesting too deep", ErrTooComplex)
	}
	// A Content-Type that does not parse (or is absent) leaves mt empty and
	// params nil, which is not a multipart, so the part is treated as a leaf.
	mt, params, _ := mime.ParseMediaType(h.Get("Content-Type"))
	if !strings.HasPrefix(mt, "multipart/") {
		return e.leaf(h, body, mt, params)
	}
	// A container that cannot be opened, or that yields nothing at all, is a
	// malformed message rather than an empty one - something was meant to be
	// in there. It counts as carrying a file, because the alternative is to
	// mistake it for the empty message a connection test sends and drop a
	// scan in silence.
	if params["boundary"] == "" {
		e.attach++
		return nil
	}
	mr := multipart.NewReader(body, params["boundary"])
	seen := 0
	for {
		p, err := mr.NextPart()
		if err != nil {
			// io.EOF at the closing boundary is the only clean end. Any other
			// error is a container that broke while we were reading it, and a
			// container that ended without ever yielding a part never worked
			// at all: both hide what the message was carrying, so both count
			// as carrying something. Otherwise a cover page followed by an
			// unparsable attachment would read as an empty message and take
			// the scan down with it, unannounced.
			if err != io.EOF || seen == 0 {
				e.attach++
			}
			return nil
		}
		seen++
		e.parts++
		if e.parts > maxParts {
			p.Close()
			return fmt.Errorf("%w: too many parts", ErrTooComplex)
		}
		err = e.walk(p.Header, p, depth+1)
		p.Close()
		if err != nil {
			return err
		}
	}
}

// leaf extracts one non-multipart part if its bytes are a PDF (see Extract
// on why only the bytes decide) and skips it otherwise.
func (e *extractor) leaf(h textproto.MIMEHeader, body io.Reader, mt string, params map[string]string) error {
	name := e.filename(h, params)
	// A part is a file if it names one, says it is one, or is simply not
	// text; counted before any check can reject it, since the caller needs
	// "carried files at all" separately from "carried a PDF".
	disp, _, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	if name != "" || disp == "attachment" || (mt != "" && !strings.HasPrefix(mt, "text/")) {
		e.attach++
	}
	src := decoded(h, body)

	// Buffer the prefix before creating anything: a part that merely claims
	// to be a PDF must not leave a file behind.
	head := make([]byte, headBytes)
	n, err := io.ReadFull(src, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil // unreadable part: broken base64, truncated message, ...
	}
	if !bytes.HasPrefix(head[:n], pdfMagic) {
		return nil
	}
	if len(e.pdfs) >= maxPDFs {
		return fmt.Errorf("%w: too many PDF attachments", ErrTooComplex)
	}

	f, err := e.newFile()
	if err != nil {
		return fmt.Errorf("%w: create file: %w", ErrStorage, err)
	}
	dst := &fileWriter{f: f}
	size, err := io.Copy(dst, io.MultiReader(bytes.NewReader(head[:n]), src))
	ok := false
	if err == nil {
		tail := make([]byte, min(int64(tailBytes), size))
		if _, terr := f.ReadAt(tail, max(0, size-tailBytes)); terr == nil {
			ok = bytes.Contains(tail, pdfEOF)
		}
	}
	cerr := f.Close()
	if serr := errors.Join(dst.err, cerr); serr != nil {
		os.Remove(f.Name())
		return fmt.Errorf("%w: %w", ErrStorage, serr)
	}
	if err != nil || !ok {
		os.Remove(f.Name())
		return nil
	}
	e.pdfs = append(e.pdfs, PDF{DisplayName: name, Path: f.Name(), Size: size})
	return nil
}

// fileWriter records the first write error, so a failure to *store* an
// attachment (a local problem: full disk, vanished directory) can be told
// apart from a failure to *read* one, which only costs that one part.
type fileWriter struct {
	f   *os.File
	err error
}

func (w *fileWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// filename returns the attachment name from Content-Disposition, falling back
// to the Content-Type name parameter. ParseMediaType already resolves RFC 2231
// (filename*=); some devices additionally use RFC 2047 encoded-words there.
// The result is deliberately not sanitized -- that is jobs.SanitizeDisplayName's
// job -- and is never used to build a path.
func (e *extractor) filename(h textproto.MIMEHeader, params map[string]string) string {
	_, disp, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	if f := disp["filename"]; f != "" {
		return e.decode(f)
	}
	return e.decode(params["name"])
}

// decode resolves RFC 2047 encoded-words. A value in a charset we cannot
// decode yields "" rather than bytes in an unknown encoding.
func (e *extractor) decode(s string) string {
	d, err := e.words.DecodeHeader(s)
	if err != nil {
		return ""
	}
	return d
}

// decoded applies a part's transfer encoding. mime/multipart already undoes
// quoted-printable for parts inside a multipart (and removes the header), but
// a non-multipart message body still carries it. Unknown encodings are treated
// as identity rather than failing the message.
func decoded(h textproto.MIMEHeader, body io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, spaceFilter{body})
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	}
	return body
}

// spaceFilter drops whitespace from a base64 stream. encoding/base64 skips
// only CR and LF, while RFC 2045 6.8 requires a decoder to ignore every
// character outside the alphabet -- and scanners really do pad their lines
// with trailing spaces or indent them with tabs.
type spaceFilter struct{ r io.Reader }

func (f spaceFilter) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	kept := p[:0] // compacting in place: bytes only ever move left
	for _, c := range p[:n] {
		switch c {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			continue
		}
		kept = append(kept, c)
	}
	return len(kept), err
}

// latin1Reader decodes an encoded-word whose charset the standard library
// does not handle itself (it covers utf-8, us-ascii and iso-8859-1) by
// treating the bytes as latin-1. The labels a scanner realistically emits
// beyond those three are windows-1252 and iso-8859-15, which agree with
// latin-1 on every accented letter a European subject or filename uses.
func latin1Reader(_ string, r io.Reader) (io.Reader, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return strings.NewReader(sb.String()), nil
}
