package main

import (
	"bytes"
	"encoding/base64"
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

func (f *fakes) sendMail(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, graphScope) {
		return
	}
	// The mailbox in the path is the one production URL built from operator
	// configuration (S2G_GRAPH_SENDER). Real Graph refuses a mailbox the
	// application may not send as; a fake that ignored it would let the
	// appliance address the wrong one and still look correct.
	if sender := r.PathValue("sender"); sender != graphSender {
		writeAPIError(w, http.StatusForbidden, "not allowed to send as "+sender)
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
