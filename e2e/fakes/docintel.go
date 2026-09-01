package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
)

// analyze takes the submitted PDF, records exactly the bytes that arrived
// and hands back an operation to poll - or, in fail mode, the 500 the suite
// uses to prove that a failed OCR never falls back to the original scan.
func (f *fakes) analyze(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, diScope) {
		return
	}
	if r.URL.Query().Get("output") != "pdf" {
		writeAPIError(w, http.StatusBadRequest, "output=pdf is required to get a searchable PDF back")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "could not read the document")
		return
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	id := rand.Text()

	f.mu.Lock()
	f.subs = append(f.subs, submission{SHA256: sha, Size: len(body)})
	fail := f.diFail
	if !fail {
		f.analyses[id] = &analysis{sha: sha}
	}
	f.mu.Unlock()

	if fail {
		writeAPIError(w, http.StatusInternalServerError, "the fake is in fail mode")
		return
	}
	// Same origin as the configured endpoint: the client refuses to carry
	// its bearer token anywhere else.
	w.Header().Set("Operation-Location", f.diOrigin+"/documentintelligence/documentModels/prebuilt-read/analyzeResults/"+
		id+"?api-version="+url.QueryEscape(r.URL.Query().Get("api-version")))
	w.WriteHeader(http.StatusAccepted)
}

// analyzeResult answers the first poll of an operation with "running" and
// every later one with "succeeded", so the poll loop and its Retry-After are
// genuinely exercised without costing the suite more than a second.
func (f *fakes) analyzeResult(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, diScope) {
		return
	}
	f.mu.Lock()
	a, known := f.analyses[r.PathValue("id")]
	if known {
		a.polls++
	}
	first := known && a.polls == 1
	f.mu.Unlock()

	switch {
	case !known:
		writeAPIError(w, http.StatusNotFound, "no such analyze operation")
	case first:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusOK, map[string]string{"status": "running"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "succeeded"})
	}
}

// analyzePDF is the "searchable" result: recognisably not the input, and
// carrying the digest of the document it was made from, so the suite can
// prove that what a user downloads came out of OCR and out of *their* scan.
func (f *fakes) analyzePDF(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, diScope) {
		return
	}
	f.mu.Lock()
	a, known := f.analyses[r.PathValue("id")]
	f.mu.Unlock()
	if !known {
		writeAPIError(w, http.StatusNotFound, "no such analyze operation")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	_, _ = io.WriteString(w, "%PDF-1.7\n% OCRED-BY-FAKE "+a.sha+
		"\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
}

// documentModels is the one call the setup wizard's check makes: it proves
// the endpoint, the TLS chain, the token and the scope together, for free.
func (f *fakes) documentModels(w http.ResponseWriter, r *http.Request) {
	if !authorized(w, r, diScope) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": []map[string]string{{"modelId": "prebuilt-read"}}})
}
