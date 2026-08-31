package smtpin_test

import (
	"errors"
	"strings"
	"testing"
)

func TestFullTransaction(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<Alice@Corp.Example>")
	if code, msg := c.data(singlePDFMessage("Test Scan")); code != 250 {
		t.Fatalf("DATA: got %d %q, want 250", code, msg)
	}

	got := h.enqueued()
	if len(got) != 1 {
		t.Fatalf("enqueued %d jobs, want 1", len(got))
	}
	job := got[0]
	if job.Profile != "printer@corp.example" {
		t.Errorf("Profile = %q, want printer@corp.example", job.Profile)
	}
	if !job.Caps.Email || !job.Caps.Web || job.Caps.OCR {
		t.Errorf("Caps = %+v, want email+web only", job.Caps)
	}
	if want := []string{"alice@corp.example"}; len(job.Recipients) != 1 || job.Recipients[0] != want[0] {
		t.Errorf("Recipients = %v, want %v (canonicalized/lowercased)", job.Recipients, want)
	}
	if job.Subject != "Test Scan" {
		t.Errorf("Subject = %q, want %q", job.Subject, "Test Scan")
	}
	if len(job.Documents) != 1 {
		t.Fatalf("Documents = %d, want 1", len(job.Documents))
	}
	if store.Len() != 1 {
		t.Errorf("store.Len() = %d, want 1 (the committed job)", store.Len())
	}
}

func TestAuthLoginSuccess(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := dialSMTP(t, addr)
	c.ehlo()
	if code, msg := c.authLogin(cfg.SMTPUsername, cfg.SMTPPassword); code != 235 {
		t.Fatalf("AUTH LOGIN: got %d %q, want 235", code, msg)
	}
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
}

func TestAuthFailure(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := dialSMTP(t, addr)
	c.ehlo()
	if code, msg := c.authPlain(cfg.SMTPUsername, "wrong-password"); code != 535 {
		t.Fatalf("AUTH PLAIN with wrong password: got %d %q, want 535", code, msg)
	}
}

func TestMailBeforeAuthRejected(t *testing.T) {
	h := &fakeHandler{}
	addr, _, _ := newHarness(t, nil, nil, h)

	c := dialSMTP(t, addr)
	c.ehlo()
	if code, msg := c.readCodeAfter(func() { c.send("MAIL FROM:<printer@corp.example>") }); code != 502 {
		t.Fatalf("MAIL FROM before AUTH: got %d %q, want 502", code, msg)
	}
}

func TestAnonymousMode(t *testing.T) {
	h := &fakeHandler{}
	addr, _, _ := newHarness(t, map[string]string{"S2G_SMTP_ALLOW_ANONYMOUS": "true"},
		[]string{"S2G_SMTP_USERNAME", "S2G_SMTP_PASSWORD"}, h)

	c := dialSMTP(t, addr)
	ehloMsg := c.ehlo()
	if strings.Contains(ehloMsg, "AUTH") {
		t.Errorf("EHLO response advertises AUTH in anonymous mode: %q", ehloMsg)
	}
	// Mail must be accepted without ever authenticating.
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(singlePDFMessage("Anon")); code != 250 {
		t.Fatalf("DATA: got %d %q, want 250", code, msg)
	}
	if len(h.enqueued()) != 1 {
		t.Fatalf("enqueued %d jobs, want 1", len(h.enqueued()))
	}
}

func TestUnknownSender(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	if code, msg := c.readCodeAfter(func() { c.send("MAIL FROM:<stranger@corp.example>") }); code != 550 {
		t.Fatalf("MAIL FROM unknown sender: got %d %q, want 550", code, msg)
	}
}

func TestDisallowedRecipientDomain(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	if code, msg := c.readCodeAfter(func() { c.send("RCPT TO:<eve@other.example>") }); code != 550 {
		t.Fatalf("RCPT TO disallowed domain: got %d %q, want 550", code, msg)
	}
}

func TestRecipientNotAnAddress(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	// Has an "@" so the SMTP grammar itself accepts it, but the domain has
	// no "." so it is not a plausible address by our own rules.
	if code, msg := c.readCodeAfter(func() { c.send("RCPT TO:<someone@nodot>") }); code != 550 {
		t.Fatalf("RCPT TO implausible address: got %d %q, want 550", code, msg)
	}
}

func TestDuplicateRecipientsCollapse(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	c.cmd(250, "RCPT TO:<Alice@Corp.Example>") // same identity, different case
	if code, msg := c.data(singlePDFMessage("Dup")); code != 250 {
		t.Fatalf("DATA: got %d %q, want 250", code, msg)
	}

	got := h.enqueued()
	if len(got) != 1 {
		t.Fatalf("enqueued %d jobs, want 1", len(got))
	}
	if r := got[0].Recipients; len(r) != 1 {
		t.Errorf("Recipients = %v, want exactly one deduplicated entry", r)
	}
}

func TestNoPDF(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(textMessage("No attachment")); code != 550 {
		t.Fatalf("DATA with no PDF: got %d %q, want 550", code, msg)
	}
}

func TestOversizedData(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, map[string]string{"S2G_MAX_MESSAGE_BYTES": "100"}, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	// The server's own SIZE= check (go-smtp) rejects this before our code
	// ever runs.
	if code, msg := c.readCodeAfter(func() { c.send("MAIL FROM:<printer@corp.example> SIZE=999999") }); code != 552 {
		t.Fatalf("MAIL FROM SIZE over cap: got %d %q, want 552", code, msg)
	}
}

// TestOversizedBodyRejected covers the size limit go-smtp enforces while the
// body streams, i.e. a printer that never announced SIZE=. The read error
// must reach the reply mapping (552) instead of being swallowed into a
// truncated message that is then accepted with 250.
func TestOversizedBodyRejected(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, map[string]string{"S2G_MAX_MESSAGE_BYTES": "8192"}, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	// Many short lines: a single long one would trip go-smtp's line limit
	// first, which is a different rejection.
	big := scanMessage("Huge", [][2]string{{"scan.pdf", pdfBody(strings.Repeat(strings.Repeat("x", 64)+"\r\n", 1024))}})
	if code, msg := c.data(big); code != 552 {
		t.Fatalf("DATA over MaxMessageBytes: got %d %q, want 552", code, msg)
	}
	waitStoreEmpty(t, store)
	if got := h.enqueued(); len(got) != 0 {
		t.Fatalf("enqueued %d jobs for an oversized message, want 0", len(got))
	}
}

func TestTooManyParts(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(manyPartsMessage(105)); code != 552 {
		t.Fatalf("DATA with too many parts: got %d %q, want 552", code, msg)
	}
}

func TestCapacityExhausted(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, map[string]string{"S2G_MAX_JOBS": "1"}, nil, h)

	// Occupy the only slot directly, without going through a transaction.
	held, err := store.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	defer held.Abort()

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(singlePDFMessage("Full")); code != 451 {
		t.Fatalf("DATA at capacity: got %d %q, want 451", code, msg)
	}
	if len(h.enqueued()) != 0 {
		t.Errorf("enqueued %d jobs, want 0", len(h.enqueued()))
	}
}

func TestHandlerBusy(t *testing.T) {
	h := &fakeHandler{err: errors.New("no room in the pipeline")}
	addr, store, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(singlePDFMessage("Busy")); code != 451 {
		t.Fatalf("DATA with busy handler: got %d %q, want 451", code, msg)
	}
	if store.Len() != 0 {
		t.Errorf("store.Len() = %d, want 0 (no job left after a busy handler)", store.Len())
	}
}

func TestResetReleasesCapacity(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<eve@corp.example>")
	c.cmd(250, "RSET")
	if store.Len() != 0 {
		t.Fatalf("store.Len() = %d, want 0 after RSET", store.Len())
	}

	// The reset session must behave like a fresh one: a new transaction
	// with different recipients must not carry the old ones over.
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(singlePDFMessage("After reset")); code != 250 {
		t.Fatalf("DATA after RSET: got %d %q, want 250", code, msg)
	}
	got := h.enqueued()
	if len(got) != 1 {
		t.Fatalf("enqueued %d jobs, want 1", len(got))
	}
	if r := got[0].Recipients; len(r) != 1 || r[0] != "alice@corp.example" {
		t.Errorf("Recipients = %v, want only alice@corp.example (eve@corp.example must not survive RSET)", r)
	}
}

// TestSecondMailFromStartsFreshTransaction: go-smtp lets a client send MAIL
// FROM again without RSET, and the session must then behave like a fresh
// one -- neither the recipients nor the profile of the earlier transaction
// may survive into the new one.
func TestSecondMailFromStartsFreshTransaction(t *testing.T) {
	h := &fakeHandler{}
	addr, _, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>") // email+web
	c.cmd(250, "RCPT TO:<eve@corp.example>")
	c.cmd(250, "MAIL FROM:<webonly@corp.example>") // web only
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.data(singlePDFMessage("Second")); code != 250 {
		t.Fatalf("DATA: got %d %q, want 250", code, msg)
	}

	got := h.enqueued()
	if len(got) != 1 {
		t.Fatalf("enqueued %d jobs, want 1", len(got))
	}
	job := got[0]
	if r := job.Recipients; len(r) != 1 || r[0] != "alice@corp.example" {
		t.Errorf("Recipients = %v, want only alice@corp.example", r)
	}
	if job.Profile != "webonly@corp.example" || job.Caps.Email {
		t.Errorf("Profile = %q, Caps = %+v, want the webonly profile (no email)", job.Profile, job.Caps)
	}
}

func TestDisconnectDuringDataLeavesNoStaging(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	c.send("DATA")
	if code, msg := c.readCode(); code != 354 {
		t.Fatalf("DATA: got %d %q, want 354", code, msg)
	}
	// Write a partial, never-terminated message, then vanish -- like a
	// printer whose network connection just drops mid-transfer.
	c.tp.W.WriteString("From: scanner@lan.local\r\n\r\nnever finishes")
	c.tp.W.Flush()
	c.conn.Close()

	waitStoreEmpty(t, store)
	if len(h.enqueued()) != 0 {
		t.Errorf("enqueued %d jobs, want 0", len(h.enqueued()))
	}
}

// TestBdatResetDoesNotCommit covers the CHUNKING path: go-smtp advertises
// CHUNKING unconditionally and runs Session.Data on a separate goroutine, so
// a complete message can arrive in a non-final BDAT chunk and then be
// abandoned with RSET. Nothing may be committed or enqueued for it -- the
// client was never told 250, so it will retry.
func TestBdatResetDoesNotCommit(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.bdat(singlePDFMessage("Chunked")); code != 250 {
		t.Fatalf("BDAT: got %d %q, want 250 (Continue)", code, msg)
	}
	c.cmd(250, "RSET")

	waitStoreEmpty(t, store)
	if got := h.enqueued(); len(got) != 0 {
		t.Fatalf("enqueued %d jobs after RSET, want 0: %+v", len(got), got)
	}
}

// TestBdatLastCommits is the other half of the CHUNKING path: a message the
// client does finish must be accepted exactly like one sent with DATA.
func TestBdatLastCommits(t *testing.T) {
	h := &fakeHandler{}
	addr, store, cfg := newHarness(t, nil, nil, h)

	c := mustAuth(t, addr, cfg.SMTPUsername, cfg.SMTPPassword)
	c.cmd(250, "MAIL FROM:<printer@corp.example>")
	c.cmd(250, "RCPT TO:<alice@corp.example>")
	if code, msg := c.bdat(singlePDFMessage("Chunked")); code != 250 {
		t.Fatalf("BDAT: got %d %q, want 250 (Continue)", code, msg)
	}
	c.cmd(250, "BDAT 0 LAST")

	got := h.enqueued()
	if len(got) != 1 {
		t.Fatalf("enqueued %d jobs, want 1", len(got))
	}
	if r := got[0].Recipients; len(r) != 1 || r[0] != "alice@corp.example" {
		t.Errorf("Recipients = %v, want [alice@corp.example]", r)
	}
	if store.Len() != 1 {
		t.Errorf("store.Len() = %d, want 1", store.Len())
	}
}
