package docintel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRetryWithFileBody covers the retry with the reader the pipeline
// actually passes: an *os.File. net/http closes a request body that is an
// io.ReadCloser, so without care the seek before the second attempt fails
// with "file already closed" and a single 429 from Azure fails the job.
func TestRetryWithFileBody(t *testing.T) {
	pdf := "%PDF-1.4\nbody\n%%EOF\n"
	path := filepath.Join(t.TempDir(), "scan.pdf")
	if err := os.WriteFile(path, []byte(pdf), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var attempts int
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ":analyze"):
			attempts++
			if attempts == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			body, _ := os.ReadFile(path)
			got := make([]byte, len(body))
			n, _ := r.Body.Read(got)
			if string(got[:n]) != pdf {
				t.Errorf("retry body = %q, want the whole PDF", got[:n])
			}
			w.Header().Set("Operation-Location", base+"/documentintelligence/documentModels/prebuilt-read/analyzeResults/abc?api-version=2024-11-30")
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/pdf"):
			_, _ = w.Write([]byte(pdf))
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "succeeded"})
		}
	}))
	defer srv.Close()
	base = srv.URL

	c := &Client{HTTP: srv.Client(), Endpoint: srv.URL, APIVersion: "2024-11-30", sleep: func(context.Context, time.Duration) {}}
	var out bytes.Buffer
	if err := c.SearchablePDF(context.Background(), f, &out); err != nil {
		t.Fatalf("SearchablePDF with an *os.File over a retry: %v", err)
	}
}
