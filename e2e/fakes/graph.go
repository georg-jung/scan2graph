package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
)

// graphMessage is one sendMail call as /inspect/graph reports it. A message
// that will not parse is recorded with Error set instead of being dropped: a
// malformed message the suite cannot see would be a green test proving
// nothing.
type graphMessage struct {
	Sender      string       `json:"sender"`
	To          []string     `json:"to"`
	Subject     string       `json:"subject"`
	Body        string       `json:"body"`
	Attachments []attachment `json:"attachments"`
	Error       string       `json:"error,omitempty"`
}

type attachment struct {
	Filename string `json:"filename"`
	Base64   string `json:"base64"`
}

// upload is one open attachment upload session: which draft it belongs to,
// the attachment's name, and the bytes assembled so far. data is allocated at
// its declared size, so a chunk that does not fit the attachment the session
// was opened for is a failure rather than a silent resize.
type upload struct {
	draft *graphMessage
	name  string
	data  []byte
	got   int64 // what has arrived, and the offset the next chunk must start at
}

// mailbox is the check every call on the sender's mailbox shares. The mailbox
// in the path is the one production URL built from operator configuration
// (S2G_GRAPH_SENDER). Real Graph refuses a mailbox the application may not
// write; a fake that ignored it would let the appliance address the wrong one
// and still look correct.
func mailbox(w http.ResponseWriter, r *http.Request) bool {
	if !authorized(w, r, graphScope) {
		return false
	}
	if sender := r.PathValue("sender"); sender != graphSender {
		writeAPIError(w, http.StatusForbidden, "not allowed to send as "+sender)
		return false
	}
	return true
}

func (f *fakes) sendMail(w http.ResponseWriter, r *http.Request) {
	if !mailbox(w, r) {
		return
	}
	rec := parseMessage(r.Body)
	f.mu.Lock()
	f.messages = append(f.messages, rec)
	f.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

// parseMessage decodes Graph's base64 sendMail body and pulls out of the
// RFC 5322 message inside exactly what the suite asserts on.
func parseMessage(body io.Reader) graphMessage {
	rec := graphMessage{To: []string{}, Attachments: []attachment{}}
	raw, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, body))
	if err != nil {
		rec.Error = "the request body is not base64: " + err.Error()
		return rec
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		rec.Error = "not an RFC 5322 message: " + err.Error()
		return rec
	}
	if from, err := mail.ParseAddress(msg.Header.Get("From")); err == nil {
		rec.Sender = from.Address
	}
	to, err := msg.Header.AddressList("To")
	if err != nil {
		rec.Error = "unreadable To header: " + err.Error()
		return rec
	}
	for _, a := range to {
		rec.To = append(rec.To, a.Address)
	}
	rec.Subject, err = new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		rec.Subject = msg.Header.Get("Subject")
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		rec.Error = "unreadable Content-Type: " + err.Error()
		return rec
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		text, err := io.ReadAll(msg.Body)
		if err != nil {
			rec.Error = "unreadable body: " + err.Error()
		}
		rec.Body = string(text)
		return rec
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return rec
		}
		if err != nil {
			rec.Error = "unreadable part: " + err.Error()
			return rec
		}
		if err := addPart(&rec, p); err != nil {
			rec.Error = "unreadable part: " + err.Error()
			return rec
		}
	}
}

// addPart records one MIME part: the text/plain one is the body, everything
// else is an attachment, digested and kept so the suite can compare it with
// what the printer sent and with what OCR returned.
func addPart(rec *graphMessage, p *multipart.Part) error {
	var r io.Reader = p // multipart decodes quoted-printable, but not base64
	if strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "base64") {
		r = base64.NewDecoder(base64.StdEncoding, p)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if p.FileName() == "" && strings.HasPrefix(p.Header.Get("Content-Type"), "text/plain") {
		rec.Body = string(data)
		return nil
	}
	rec.Attachments = append(rec.Attachments, attachment{
		Filename: p.FileName(),
		Base64:   base64.StdEncoding.EncodeToString(data),
	})
	return nil
}

// createDraft is the first of the four calls a scan too large for sendMail
// makes: the message the MIME path would have composed, as JSON and without
// its attachments, which arrive later through upload sessions of their own.
func (f *fakes) createDraft(w http.ResponseWriter, r *http.Request) {
	if !mailbox(w, r) {
		return
	}
	var body struct {
		Subject string `json:"subject"`
		Body    struct {
			Content string `json:"content"`
		} `json:"body"`
		ToRecipients []struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"toRecipients"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "the draft is not JSON: "+err.Error())
		return
	}
	msg := &graphMessage{
		Sender:      graphSender,
		Subject:     body.Subject,
		Body:        body.Body.Content,
		To:          []string{},
		Attachments: []attachment{},
	}
	for _, t := range body.ToRecipients {
		msg.To = append(msg.To, t.EmailAddress.Address)
	}
	id := rand.Text()
	f.mu.Lock()
	f.drafts[id] = msg
	f.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// createUploadSession opens a session for one attachment and answers with the
// URL its chunks go to - on this host but off the /graph prefix, the way real
// Graph hands out a pre-authorized URL somewhere else entirely.
func (f *fakes) createUploadSession(w http.ResponseWriter, r *http.Request) {
	if !mailbox(w, r) {
		return
	}
	var body struct {
		AttachmentItem struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"AttachmentItem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AttachmentItem.Size <= 0 {
		writeAPIError(w, http.StatusBadRequest, "an upload session needs an AttachmentItem with a size")
		return
	}
	id := rand.Text()
	f.mu.Lock()
	draft, known := f.drafts[r.PathValue("id")]
	if known {
		f.uploads[id] = &upload{draft: draft, name: body.AttachmentItem.Name, data: make([]byte, body.AttachmentItem.Size)}
	}
	f.mu.Unlock()
	if !known {
		writeAPIError(w, http.StatusNotFound, "no such draft message")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"uploadUrl": "http://" + r.Host + "/upload/" + id})
}

// uploadChunk places one chunk at the offset its Content-Range names, and
// refuses one that does not continue what has already arrived. Tolerating a
// wrong offset would let the fake assemble the right scan out of the wrong
// requests, which is a green test proving nothing. Every chunk but the last
// is answered 200 and the last one 201, as Graph does.
func (f *fakes) uploadChunk(w http.ResponseWriter, r *http.Request) {
	// No bearer token here, ever: an uploadUrl is pre-authorized and points at
	// a host Graph picks, so an appliance that sent its Graph token would hand
	// a credential for every mailbox in the tenant to somebody it never chose.
	// Refusing is how that regression gets caught.
	if r.Header.Get("Authorization") != "" {
		writeAPIError(w, http.StatusForbidden, "an upload session is pre-authorized; do not send a bearer token")
		return
	}
	chunk, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "could not read the chunk")
		return
	}
	var first, last, total int64
	if _, err := fmt.Sscanf(r.Header.Get("Content-Range"), "bytes %d-%d/%d", &first, &last, &total); err != nil {
		writeAPIError(w, http.StatusBadRequest, "Content-Range must read bytes first-last/total")
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	up, known := f.uploads[r.PathValue("id")]
	if !known {
		writeAPIError(w, http.StatusNotFound, "no such upload session")
		return
	}
	if total != int64(len(up.data)) || first != up.got || last != first+int64(len(chunk))-1 || last >= total {
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf(
			"chunk %d-%d/%d does not continue the %d bytes of %d already uploaded",
			first, last, total, up.got, len(up.data)))
		return
	}
	copy(up.data[first:], chunk)
	up.got = last + 1
	if up.got < total {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Complete: the attachment joins the draft, in the shape /inspect/graph
	// reports for a message that went out through sendMail, so the suite
	// asserts the same way whichever path carried the scan.
	up.draft.Attachments = append(up.draft.Attachments, attachment{
		Filename: up.name,
		Base64:   base64.StdEncoding.EncodeToString(up.data),
	})
	delete(f.uploads, r.PathValue("id"))
	w.WriteHeader(http.StatusCreated)
}

// sendDraft sends the draft, which is the moment it becomes a message the
// suite can see: everything before this is a mailbox no recipient hears about.
func (f *fakes) sendDraft(w http.ResponseWriter, r *http.Request) {
	if !mailbox(w, r) {
		return
	}
	f.mu.Lock()
	msg, known := f.drafts[r.PathValue("id")]
	if known {
		delete(f.drafts, r.PathValue("id"))
		f.messages = append(f.messages, *msg)
	}
	f.mu.Unlock()
	if !known {
		writeAPIError(w, http.StatusNotFound, "no such draft message")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
