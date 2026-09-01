package mimescan

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errAny in a case's wantErr means "some error, no particular sentinel".
var errAny = errors.New("any error")

// samplePDF returns a small, structurally plausible PDF: the %PDF- magic, a
// tag so different attachments differ, and the %%EOF trailer. Everything is
// printable ASCII with LF line endings, so it can be embedded in a test
// message as-is (7bit) as well as base64- or quoted-printable-encoded.
func samplePDF(tag string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	b.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n")
	fmt.Fprintf(&b, "%% attachment %s\n", tag)
	for b.Len() < 400 {
		b.WriteString("% padding padding padding padding padding padding\n")
	}
	b.WriteString("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n")
	return b.Bytes()
}

// Test data. LF is the canonical form; crlf turns a whole message into the
// wire form, which also rewrites embedded 7bit/quoted-printable payloads, so
// crlfPDF is what those cases must end up with on disk. Base64 payloads are
// unaffected and decode back to the LF form.
var (
	pdfA    = samplePDF("A")
	pdfB    = samplePDF("B")
	crlfPDF = []byte(crlf(string(pdfA)))
	// Inside a multipart the CRLF in front of the boundary belongs to the
	// delimiter, so a part's body loses its final line ending.
	partPDF = crlfPDF[:len(crlfPDF)-2]
	notPDF  = []byte("This is not a PDF at all, it only claims to be one.\n%%EOF\n")
	noEOF   = []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n")
)

// crlf converts a message written with LF line endings to wire form. It is
// idempotent, so messages may mix in text that already uses CRLF.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// b64 encodes b the way a mailer would, wrapped at 76 characters.
func b64(b []byte) string {
	enc := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(enc) > 76 {
		out.WriteString(enc[:76] + "\n")
		enc = enc[76:]
	}
	out.WriteString(enc + "\n")
	return out.String()
}

// b64Padded encodes b like b64 but puts prefix in front of and suffix behind
// every line, for the whitespace real senders add around base64 lines.
func b64Padded(b []byte, prefix, suffix string) string {
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimRight(b64(b), "\n"), "\n") {
		out.WriteString(prefix + line + suffix + "\n")
	}
	return out.String()
}

// qp encodes b as quoted-printable.
func qp(b []byte) string {
	var out bytes.Buffer
	w := quotedprintable.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.String()
}

type wantPDF struct {
	name    string
	content []byte
}

type extractCase struct {
	name    string
	msg     string
	subject string
	want    []wantPDF
	wantErr error
}

func extractCases() []extractCase {
	return []extractCase{
		{
			name: "single base64 attachment",
			msg: "From: printer@scanner.local\n" +
				"To: bob@corp.example\n" +
				"Subject: Scan\n" +
				"MIME-Version: 1.0\n" +
				"Content-Type: multipart/mixed; boundary=\"outer\"\n" +
				"\n" +
				"--outer\n" +
				"Content-Type: text/plain; charset=us-ascii\n" +
				"\n" +
				"Scanned document attached.\n" +
				"--outer\n" +
				"Content-Type: application/pdf; name=\"scan.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"scan.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--outer--\n",
			subject: "Scan",
			want:    []wantPDF{{"scan.pdf", pdfA}},
		},
		{
			name: "several attachments",
			msg: "Subject: Two scans\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"one.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--b\n" +
				"Content-Type: application/x-pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"two.pdf\"\n" +
				"\n" + b64(pdfB) +
				"--b--\n",
			subject: "Two scans",
			want:    []wantPDF{{"one.pdf", pdfA}, {"two.pdf", pdfB}},
		},
		{
			name: "nested multiparts",
			msg: "Subject: Nested\n" +
				"Content-Type: multipart/alternative; boundary=\"alt\"\n" +
				"\n" +
				"--alt\n" +
				"Content-Type: text/plain\n" +
				"\n" +
				"plain body\n" +
				"--alt\n" +
				"Content-Type: multipart/related; boundary=\"rel\"\n" +
				"\n" +
				"--rel\n" +
				"Content-Type: text/html\n" +
				"\n" +
				"<html>body</html>\n" +
				"--rel\n" +
				"Content-Type: multipart/mixed; boundary=\"mix\"\n" +
				"\n" +
				"--mix\n" +
				"Content-Type: image/png\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: inline; filename=\"logo.png\"\n" +
				"\n" + b64([]byte("\x89PNG\r\n\x1a\n not really a png")) +
				"--mix\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"deep.pdf\"\n" +
				"\n" + b64(pdfB) +
				"--mix--\n" +
				"--rel--\n" +
				"--alt--\n",
			subject: "Nested",
			want:    []wantPDF{{"deep.pdf", pdfB}},
		},
		{
			name: "base64 lines with trailing spaces",
			msg: "Subject: Padded\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"padded.pdf\"\n" +
				"\n" + b64Padded(pdfA, "", " ") +
				"--b--\n",
			subject: "Padded",
			want:    []wantPDF{{"padded.pdf", pdfA}},
		},
		{
			name: "base64 lines indented with tabs",
			msg: "Subject: Indented\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"indented.pdf\"\n" +
				"\n" + b64Padded(pdfA, "\t", "") +
				"--b--\n",
			subject: "Indented",
			want:    []wantPDF{{"indented.pdf", pdfA}},
		},
		{
			name: "quoted-printable part",
			msg: "Subject: QP\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf; name=\"qp.pdf\"\n" +
				"Content-Transfer-Encoding: quoted-printable\n" +
				"\n" + qp(pdfA) +
				"--b--\n",
			subject: "QP",
			want:    []wantPDF{{"qp.pdf", partPDF}},
		},
		{
			name: "7bit part",
			msg: "Subject: 7bit\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: 7bit\n" +
				"Content-Disposition: attachment; filename=\"plain.pdf\"\n" +
				"\n" + string(pdfA) +
				"--b--\n",
			subject: "7bit",
			want:    []wantPDF{{"plain.pdf", partPDF}},
		},
		{
			name: "non-multipart base64 body",
			msg: "Subject: Direct\n" +
				"Content-Type: application/pdf; name=\"direct.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA),
			subject: "Direct",
			want:    []wantPDF{{"direct.pdf", pdfA}},
		},
		{
			name: "octet-stream with pdf filename",
			msg: "Subject: Octet\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/octet-stream\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"SCAN_0001.PDF\"\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Octet",
			want:    []wantPDF{{"SCAN_0001.PDF", pdfA}},
		},
		{
			// The magic bytes decide, not the extension: printers really do
			// send PDFs under names like this.
			name: "octet-stream without pdf filename",
			msg: "Subject: Octet\n" +
				"Content-Type: application/octet-stream\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"scan.dat\"\n" +
				"\n" + b64(pdfA),
			subject: "Octet",
			want:    []wantPDF{{"scan.dat", pdfA}},
		},
		{
			name: "octet-stream attachment without any filename",
			msg: "Subject: Nameless\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/octet-stream\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Nameless",
			want:    []wantPDF{{"", pdfA}},
		},
		{
			name: "no content-type at all, just a filename",
			msg: "Subject: Typeless\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"scan.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Typeless",
			want:    []wantPDF{{"scan.pdf", pdfA}},
		},
		{
			name: "text body only",
			msg: "Subject: Nothing here\n" +
				"Content-Type: text/plain; charset=utf-8\n" +
				"\n" +
				"Just a note from the printer.\n",
			subject: "Nothing here",
			wantErr: ErrNoAttachments,
		},
		{
			name: "non-pdf attachments skipped",
			msg: "Subject: Cover page\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: text/plain\n" +
				"\n" +
				"cover\n" +
				"--b\n" +
				"Content-Type: image/jpeg\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"logo.jpg\"\n" +
				"\n" + b64([]byte("\xff\xd8\xff\xe0 jpeg-ish")) +
				"--b--\n",
			subject: "Cover page",
			wantErr: ErrNoPDF,
		},
		{
			// Base64 that breaks inside the first kilobyte: the decoder
			// returns both the %PDF- it managed and an error, and the error
			// used to win before anything had counted the magic.
			name: "corrupt base64 pdf with no headers",
			msg: "Subject: Corrupt\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + "JVBERi0xLjQK!!!!\n" +
				"--b--\n",
			subject: "Corrupt",
			wantErr: ErrNoPDF,
		},
		{
			// A container whose declaration is missing its semicolon: the
			// media type does not parse, so the container is never opened
			// and the PDF inside it is never seen. The unreadable
			// declaration is what says something was there.
			name: "unparsable multipart declaration",
			msg: "Subject: Broken type\n" +
				"Content-Type: multipart/mixed boundary=b\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"\n" + string(pdfA) +
				"--b--\n",
			subject: "Broken type",
			wantErr: ErrNoPDF,
		},
		{
			// No filename, no Content-Type, no disposition - nothing but
			// bytes that begin a PDF and then stop before %%EOF. The headers
			// say nothing, so only the magic marks this as an attempted scan
			// rather than an empty message.
			name: "truncated pdf with no headers at all",
			msg: "Subject: Cut short\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"\n" + "%PDF-1.4\nbut the rest never arrived\n" +
				"--b--\n",
			subject: "Cut short",
			wantErr: ErrNoPDF,
		},
		{
			// A cover page, then a part whose headers do not parse: the walk
			// stops there with a part already behind it, so "did it yield
			// anything" is not enough to tell a broken message from an empty
			// one. The error itself is what says the message was carrying
			// something the walk could not reach.
			name: "malformed part after a valid one",
			msg: "Subject: Broken part\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: text/plain\n" +
				"\n" +
				"cover page\n" +
				"--b\n" +
				"this line is not a header\n" +
				"Content-Type: application/pdf\n" +
				"\n" + string(pdfA) +
				"--b--\n",
			subject: "Broken part",
			wantErr: ErrNoPDF,
		},
		{
			// A boundary that never appears in the body: the walk finds no
			// parts, but the PDF is in there somewhere. Refusing it tells the
			// sender; calling it a connection test would drop it silently.
			name: "declared boundary never appears",
			msg: "Subject: Mismatched\n" +
				"Content-Type: multipart/mixed; boundary=\"declared\"\n" +
				"\n" +
				"--actual\n" +
				"Content-Type: application/pdf\n" +
				"\n" + string(pdfA) +
				"--actual--\n",
			subject: "Mismatched",
			wantErr: ErrNoPDF,
		},
		{
			// The filename clause: a text part that names a file is a file.
			name: "text part with a filename counts as attached",
			msg: "Subject: Scan\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: text/plain; name=\"scan.txt\"\n" +
				"\n" + "not a pdf\n" +
				"--b--\n",
			subject: "Scan",
			wantErr: ErrNoPDF,
		},
		{
			// A scanner that attaches its image inline, with neither a
			// filename nor a disposition: still a file, so still a wrong
			// format rather than a connection test.
			name: "inline non-text part counts as attached",
			msg: "Subject: Scan\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: image/jpeg\n" +
				"\n" + "\xff\xd8\xff\xe0 not a pdf\n" +
				"--b--\n",
			subject: "Scan",
			wantErr: ErrNoPDF,
		},
		{
			// The distinction the SMTP layer acts on: something was
			// attached, so this is a printer sending the wrong format
			// rather than somebody pressing "test connection".
			name: "text attached by disposition alone counts as attached",
			msg: "Subject: Scan\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: text/plain\n" +
				"Content-Disposition: attachment\n" +
				"\n" + "not a pdf, but attached\n" +
				"--b--\n",
			subject: "Scan",
			wantErr: ErrNoPDF,
		},
		{
			name: "claims pdf but is not",
			msg: "Subject: Liar\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"fake.pdf\"\n" +
				"\n" + b64(notPDF) +
				"--b--\n",
			subject: "Liar",
			wantErr: ErrNoPDF,
		},
		{
			name: "pdf without eof marker",
			msg: "Subject: Truncated\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"half.pdf\"\n" +
				"\n" + b64(noEOF) +
				"--b--\n",
			subject: "Truncated",
			wantErr: ErrNoPDF,
		},
		{
			// Padded out to a block boundary after %%EOF, the way scanners
			// that write fixed-size blocks do.
			name: "eof marker followed by block padding",
			msg: "Subject: Padding\n" +
				"Content-Type: application/pdf; name=\"padded.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(append(append([]byte(nil), pdfA...), make([]byte, 2048)...)),
			subject: "Padding",
			want:    []wantPDF{{"padded.pdf", append(append([]byte(nil), pdfA...), make([]byte, 2048)...)}},
		},
		{
			name: "eof marker too far from the end",
			msg: "Subject: Trailing junk\n" +
				"Content-Type: application/pdf; name=\"junk.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(append(pdfA, bytes.Repeat([]byte("x"), 2*tailBytes)...)),
			subject: "Trailing junk",
			wantErr: ErrNoPDF,
		},
		{
			name: "good pdf next to a rejected one",
			msg: "Subject: Mixed bag\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"half.pdf\"\n" +
				"\n" + b64(noEOF) +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"good.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Mixed bag",
			want:    []wantPDF{{"good.pdf", pdfA}},
		},
		{
			name: "encoded-word subject utf-8 base64",
			msg: "Subject: =?utf-8?B?" + base64.StdEncoding.EncodeToString([]byte("Grüße vom Drucker")) + "?=\n" +
				"Content-Type: application/pdf; name=\"a.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA),
			subject: "Grüße vom Drucker",
			want:    []wantPDF{{"a.pdf", pdfA}},
		},
		{
			name: "encoded-word subject utf-8 quoted",
			msg: "Subject: =?UTF-8?Q?Scan_vom_B=C3=BCro?=\n" +
				"Content-Type: application/pdf; name=\"a.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA),
			subject: "Scan vom Büro",
			want:    []wantPDF{{"a.pdf", pdfA}},
		},
		{
			name: "encoded-word subject iso-8859-1",
			msg: "Subject: =?iso-8859-1?Q?Gr=FC=DFe?=\n" +
				"Content-Type: application/pdf; name=\"a.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA),
			subject: "Grüße",
			want:    []wantPDF{{"a.pdf", pdfA}},
		},
		{
			name: "encoded-word subject windows-1252",
			msg: "Subject: =?windows-1252?Q?Gr=FC=DFe?=\n" +
				"Content-Type: application/pdf; name=\"a.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA),
			subject: "Grüße",
			want:    []wantPDF{{"a.pdf", pdfA}},
		},
		{
			name: "no subject header",
			msg: "From: printer@scanner.local\n" +
				"Content-Type: application/pdf; name=\"a.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA),
			subject: "",
			want:    []wantPDF{{"a.pdf", pdfA}},
		},
		{
			name: "rfc 2231 filename",
			msg: "Subject: 2231\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename*=UTF-8''Rechnung%20M%C3%A4rz.pdf\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "2231",
			want:    []wantPDF{{"Rechnung März.pdf", pdfA}},
		},
		{
			name: "encoded-word filename",
			msg: "Subject: 2047 filename\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf; name=\"=?utf-8?Q?Sitzung=2Dm=C3=A4rz.pdf?=\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "2047 filename",
			want:    []wantPDF{{"Sitzung-märz.pdf", pdfA}},
		},
		{
			name: "content-type name fallback",
			msg: "Subject: Fallback\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/octet-stream; name=\"fallback.pdf\"\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Fallback",
			want:    []wantPDF{{"fallback.pdf", pdfA}},
		},
		{
			name: "traversal filename is returned verbatim",
			msg: "Subject: Traversal\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"../../etc/passwd.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Traversal",
			want:    []wantPDF{{"../../etc/passwd.pdf", pdfA}},
		},
		{
			name: "multipart without boundary",
			msg: "Subject: No boundary\n" +
				"Content-Type: multipart/mixed\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"\n" + string(pdfA) +
				"--b--\n",
			subject: "No boundary",
			wantErr: ErrNoPDF,
		},
		{
			// A Content-Type that does not parse is not a multipart, so the
			// part is magic-checked like any other leaf.
			name: "unparsable content type",
			msg: "Subject: Junk type\n" +
				"Content-Type: ;;;not a media type\n" +
				"\n" + string(pdfA),
			subject: "Junk type",
			want:    []wantPDF{{"", crlfPDF}},
		},
		{
			name: "part without headers",
			msg: "Subject: Headerless part\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"\n" +
				"body without any headers\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"ok.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--b--\n",
			subject: "Headerless part",
			want:    []wantPDF{{"ok.pdf", pdfA}},
		},
		{
			name: "truncated message keeps earlier attachment",
			msg: "Subject: Truncated\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"first.pdf\"\n" +
				"\n" + b64(pdfA) +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"cut.pdf\"\n" +
				"\n" + b64(pdfB)[:100],
			subject: "Truncated",
			want:    []wantPDF{{"first.pdf", pdfA}},
		},
		{
			name: "broken base64 part is skipped",
			msg: "Subject: Broken\n" +
				"Content-Type: multipart/mixed; boundary=\"b\"\n" +
				"\n" +
				"--b\n" +
				"Content-Type: application/pdf\n" +
				"Content-Transfer-Encoding: base64\n" +
				"Content-Disposition: attachment; filename=\"broken.pdf\"\n" +
				"\n" + b64(pdfA)[:200] + "!!!! not base64 !!!!\n" +
				"--b--\n",
			subject: "Broken",
			wantErr: ErrNoPDF,
		},
		{
			name:    "junk headers",
			msg:     "this is not a header at all\nneither is this\n\nbody\n",
			wantErr: errAny,
		},
		{
			name:    "empty message",
			msg:     "",
			wantErr: errAny,
		},
	}
}

func TestExtract(t *testing.T) {
	for _, tc := range extractCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			res, err := Extract(strings.NewReader(crlf(tc.msg)), fileFactory(t, dir))

			if tc.wantErr == errAny {
				if err == nil {
					t.Fatalf("Extract() error = nil, want some error")
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Extract() error = %v, want %v", err, tc.wantErr)
			}
			if res.Subject != tc.subject {
				t.Errorf("Subject = %q, want %q", res.Subject, tc.subject)
			}
			if len(res.PDFs) != len(tc.want) {
				t.Fatalf("got %d PDFs, want %d: %+v", len(res.PDFs), len(tc.want), res.PDFs)
			}
			for i, w := range tc.want {
				got := res.PDFs[i]
				if got.DisplayName != w.name {
					t.Errorf("PDFs[%d].DisplayName = %q, want %q", i, got.DisplayName, w.name)
				}
				if got.Size != int64(len(w.content)) {
					t.Errorf("PDFs[%d].Size = %d, want %d", i, got.Size, len(w.content))
				}
				b, err := os.ReadFile(got.Path)
				if err != nil {
					t.Fatalf("read %s: %v", got.Path, err)
				}
				if !bytes.Equal(b, w.content) {
					t.Errorf("PDFs[%d] content mismatch (%d bytes on disk, want %d)", i, len(b), len(w.content))
				}
			}
			// Nothing may be left behind for a part that was rejected, and
			// nothing at all when Extract failed.
			if files := filesIn(t, dir); len(files) != len(res.PDFs) {
				t.Errorf("%d files in staging dir, want %d: %v", len(files), len(res.PDFs), files)
			}
		})
	}
}

func TestExtractLimits(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		wantPDFs int
		wantErr  error
	}{
		{"parts at limit", manyParts(maxParts), 0, ErrNoAttachments},
		{"too many parts", manyParts(maxParts + 1), 0, ErrTooComplex},
		{"depth at limit", nested(maxDepth), 1, nil},
		{"too deep", nested(maxDepth + 1), 0, ErrTooComplex},
		{"pdfs at limit", manyPDFs(maxPDFs), maxPDFs, nil},
		{"too many pdfs", manyPDFs(maxPDFs + 1), 0, ErrTooComplex},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			res, err := Extract(strings.NewReader(crlf(tc.msg)), fileFactory(t, dir))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Extract() error = %v, want %v", err, tc.wantErr)
			}
			if len(res.PDFs) != tc.wantPDFs {
				t.Errorf("got %d PDFs, want %d", len(res.PDFs), tc.wantPDFs)
			}
			if files := filesIn(t, dir); len(files) != len(res.PDFs) {
				t.Errorf("%d files in staging dir, want %d", len(files), len(res.PDFs))
			}
		})
	}
}

// TestExtractNewFileError checks that a failing file factory fails the
// message with ErrStorage instead of being ignored: a scan that could not be
// stored for a local reason must not look like a message without a PDF.
func TestExtractNewFileError(t *testing.T) {
	msg := "Subject: x\nContent-Type: application/pdf; name=\"a.pdf\"\n\n" + string(pdfA)
	_, err := Extract(strings.NewReader(crlf(msg)), func() (*os.File, error) {
		return nil, errors.New("disk on fire")
	})
	if err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("Extract() error = %v, want the factory error", err)
	}
	if !errors.Is(err, ErrStorage) {
		t.Errorf("Extract() error = %v, want it to wrap ErrStorage", err)
	}
}

// TestExtractWriteError is the same for a file that cannot be written to.
func TestExtractWriteError(t *testing.T) {
	dir := t.TempDir()
	msg := "Subject: x\nContent-Type: application/pdf; name=\"a.pdf\"\n\n" + string(pdfA)
	_, err := Extract(strings.NewReader(crlf(msg)), func() (*os.File, error) {
		p := filepath.Join(dir, "read-only")
		if werr := os.WriteFile(p, nil, 0600); werr != nil {
			return nil, werr
		}
		return os.Open(p) // opened for reading: every Write fails
	})
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("Extract() error = %v, want ErrStorage", err)
	}
}

// manyParts builds a multipart message with n text parts.
func manyParts(n int) string {
	var b strings.Builder
	b.WriteString("Subject: Many\nContent-Type: multipart/mixed; boundary=\"b\"\n\n")
	for i := range n {
		fmt.Fprintf(&b, "--b\nContent-Type: text/plain\n\npart %d\n", i)
	}
	b.WriteString("--b--\n")
	return b.String()
}

// manyPDFs builds a multipart message with n PDF attachments.
func manyPDFs(n int) string {
	var b strings.Builder
	b.WriteString("Subject: Many PDFs\nContent-Type: multipart/mixed; boundary=\"b\"\n\n")
	for i := range n {
		fmt.Fprintf(&b, "--b\nContent-Type: application/pdf\nContent-Transfer-Encoding: base64\n"+
			"Content-Disposition: attachment; filename=\"scan-%d.pdf\"\n\n%s", i, b64(samplePDF(fmt.Sprint(i))))
	}
	b.WriteString("--b--\n")
	return b.String()
}

// nested builds a message with levels nested multiparts and one PDF in the
// innermost one, i.e. a PDF part at depth levels.
func nested(levels int) string {
	var b strings.Builder
	b.WriteString("Subject: Nested\n")
	for i := range levels {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"b%d\"\n\n--b%d\n", i, i)
	}
	b.WriteString("Content-Type: application/pdf\nContent-Transfer-Encoding: base64\n" +
		"Content-Disposition: attachment; filename=\"deep.pdf\"\n\n" + b64(pdfA))
	for i := levels - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%d--\n", i)
	}
	return b.String()
}

// fileFactory returns a newFile function that creates files in dir, the way
// jobs.Staging.CreateFile does.
func fileFactory(t *testing.T, dir string) func() (*os.File, error) {
	t.Helper()
	return func() (*os.File, error) { return os.CreateTemp(dir, "pdf-*") }
}

// filesIn lists the regular files below dir.
func filesIn(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// FuzzExtract asserts the properties that matter at the untrusted-input
// boundary: no panic, no hang, never more than maxPDFs results, every file
// inside the directory the factory hands out, and no file left behind that is
// not a returned PDF.
func FuzzExtract(f *testing.F) {
	for _, tc := range extractCases() {
		f.Add(crlf(tc.msg))
	}
	for _, m := range []string{manyParts(3), manyPDFs(2), nested(3), nested(maxDepth + 1)} {
		f.Add(crlf(m))
	}

	f.Fuzz(func(t *testing.T, msg string) {
		dir := t.TempDir()
		res, err := Extract(strings.NewReader(msg), func() (*os.File, error) {
			return os.CreateTemp(dir, "pdf-*")
		})
		if len(res.PDFs) > maxPDFs {
			t.Fatalf("got %d PDFs, more than maxPDFs=%d", len(res.PDFs), maxPDFs)
		}
		if err != nil && len(res.PDFs) != 0 {
			t.Fatalf("got %d PDFs alongside error %v", len(res.PDFs), err)
		}
		for _, p := range res.PDFs {
			fi, err := os.Stat(p.Path)
			if err != nil {
				t.Fatalf("stat %s: %v", p.Path, err)
			}
			if fi.Size() != p.Size {
				t.Fatalf("PDF %q: Size = %d, file is %d bytes", p.Path, p.Size, fi.Size())
			}
		}
		if files := filesIn(t, dir); len(files) != len(res.PDFs) {
			t.Fatalf("%d files left in %s, want %d", len(files), dir, len(res.PDFs))
		}
	})
}
