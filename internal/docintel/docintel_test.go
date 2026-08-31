package docintel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	analyzePath = "POST /documentintelligence/documentModels/prebuilt-read:analyze"
	pollPath    = "GET /documentintelligence/documentModels/prebuilt-read/analyzeResults/{id}"
	fetchPath   = "GET /documentintelligence/documentModels/prebuilt-read/analyzeResults/{id}/pdf"
)

// testClient builds a Client against srv with an instant, non-blocking
// sleep: every duration the client would have waited on is recorded instead
// of actually waited out, which is what keeps this whole suite fast. The
// context-cancellation test needs real waiting, so it builds a Client
// directly instead of using this helper.
func testClient(srv *httptest.Server) (*Client, *[]time.Duration) {
	waits := new([]time.Duration)
	c := &Client{
		HTTP:       srv.Client(),
		Endpoint:   srv.URL,
		APIVersion: "2024-11-30",
		sleep: func(_ context.Context, d time.Duration) {
			*waits = append(*waits, d)
		},
	}
	return c, waits
}

// succeedAnalyze replies 202 with an Operation-Location pointing at
// resultID on the same server.
func succeedAnalyze(resultID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Operation-Location", "http://"+r.Host+
			"/documentintelligence/documentModels/prebuilt-read/analyzeResults/"+resultID+"?api-version=2024-11-30")
		w.WriteHeader(http.StatusAccepted)
	}
}

// succeedFetch writes data as the "searchable pdf" body.
func succeedFetch(data string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, data) }
}

// succeedPoll always reports the operation as succeeded.
func succeedPoll(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "succeeded"})
}

func TestSearchablePDF_HappyPath(t *testing.T) {
	const (
		pdfIn    = "fake pdf bytes for the happy path"
		pdfOut   = "fake searchable pdf bytes, distinct from the input"
		resultID = "result-abc-123"
	)

	var gotMethod, gotPath, gotContentType string
	var gotBody []byte

	mux := http.NewServeMux()
	mux.HandleFunc(analyzePath, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		if got := r.URL.Query().Get("api-version"); got != "2024-11-30" {
			t.Errorf("api-version = %q", got)
		}
		if got := r.URL.Query().Get("output"); got != "pdf" {
			t.Errorf("output = %q", got)
		}
		succeedAnalyze(resultID)(w, r)
	})
	mux.HandleFunc(pollPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("id"); got != resultID {
			t.Errorf("poll id = %q, want %q", got, resultID)
		}
		succeedPoll(w, r)
	})
	mux.HandleFunc(fetchPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("id"); got != resultID {
			t.Errorf("fetch id = %q, want %q", got, resultID)
		}
		if got := r.URL.Query().Get("api-version"); got != "2024-11-30" {
			t.Errorf("fetch api-version = %q", got)
		}
		succeedFetch(pdfOut)(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := testClient(srv)
	var out bytes.Buffer
	if err := c.SearchablePDF(context.Background(), strings.NewReader(pdfIn), &out); err != nil {
		t.Fatalf("SearchablePDF: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("analyze method = %q, want POST", gotMethod)
	}
	if gotPath != "/documentintelligence/documentModels/prebuilt-read:analyze" {
		t.Errorf("analyze path = %q", gotPath)
	}
	if gotContentType != "application/pdf" {
		t.Errorf("Content-Type = %q, want application/pdf", gotContentType)
	}
	if string(gotBody) != pdfIn {
		t.Errorf("analyze body = %q, want %q", gotBody, pdfIn)
	}
	if out.String() != pdfOut {
		t.Errorf("out = %q, want %q", out.String(), pdfOut)
	}
}

func TestSearchablePDF_PollsUntilSucceeded(t *testing.T) {
	const runningSteps = 3 // "running" responses before "succeeded"
	var pollN int32

	mux := http.NewServeMux()
	mux.HandleFunc(analyzePath, succeedAnalyze("r1"))
	mux.HandleFunc(pollPath, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&pollN, 1)
		status := "running"
		if n > runningSteps {
			status = "succeeded"
		}
		json.NewEncoder(w).Encode(map[string]string{"status": status})
	})
	mux.HandleFunc(fetchPath, succeedFetch("done"))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := testClient(srv)
	var out bytes.Buffer
	if err := c.SearchablePDF(context.Background(), strings.NewReader("in"), &out); err != nil {
		t.Fatalf("SearchablePDF: %v", err)
	}
	if want := int32(runningSteps + 1); pollN != want {
		t.Errorf("poll calls = %d, want %d", pollN, want)
	}
	if out.String() != "done" {
		t.Errorf("out = %q, want %q", out.String(), "done")
	}
}

// TestSearchablePDF_RetryAfterHonoured drives the poll's Retry-After
// handling end to end; the format parsing itself (seconds vs. HTTP date)
// is covered by msapi's own unit table.
func TestSearchablePDF_RetryAfterHonoured(t *testing.T) {
	var pollN int32
	mux := http.NewServeMux()
	mux.HandleFunc(analyzePath, succeedAnalyze("r1"))
	mux.HandleFunc(pollPath, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&pollN, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			json.NewEncoder(w).Encode(map[string]string{"status": "running"})
			return
		}
		succeedPoll(w, r)
	})
	mux.HandleFunc(fetchPath, succeedFetch("done"))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, waits := testClient(srv)
	var out bytes.Buffer
	if err := c.SearchablePDF(context.Background(), strings.NewReader("in"), &out); err != nil {
		t.Fatalf("SearchablePDF: %v", err)
	}
	if pollN != 2 {
		t.Errorf("poll calls = %d, want 2", pollN)
	}
	if len(*waits) != 1 {
		t.Fatalf("recorded waits = %v, want exactly one", *waits)
	}
	if got := (*waits)[0]; got <= 0 || got > 1500*time.Millisecond {
		t.Errorf("wait honouring Retry-After = %v, want roughly 1s", got)
	}
}

func TestSearchablePDF_AnalysisFailedOrCanceled(t *testing.T) {
	tests := []struct {
		name, status, msg string
	}{
		{"failed", "failed", "the document could not be read"},
		{"canceled", "canceled", "operation canceled by the caller"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(analyzePath, succeedAnalyze("r1"))
			mux.HandleFunc(pollPath, func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"status": tt.status,
					"error":  map[string]string{"message": tt.msg},
				})
			})
			mux.HandleFunc(fetchPath, succeedFetch("unused"))

			srv := httptest.NewServer(mux)
			defer srv.Close()

			c, _ := testClient(srv)
			err := c.SearchablePDF(context.Background(), strings.NewReader("in"), io.Discard)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("error %q does not contain API message %q", err.Error(), tt.msg)
			}
		})
	}
}

// TestSearchablePDF_Retries drives the retry loop shared by all three
// requests through the analyze call, which is enough to cover it: poll and
// fetch use the exact same do() helper.
func TestSearchablePDF_Retries(t *testing.T) {
	errBody := func(msg string) string {
		b, _ := json.Marshal(map[string]any{"error": map[string]string{"message": msg}})
		return string(b)
	}

	type step struct {
		status int
		body   string
		opLoc  bool // set Operation-Location on this response
	}
	tests := []struct {
		name         string
		steps        []step
		wantAnalyzeN int
		wantErr      bool
		wantMsg      string
	}{
		{
			name:         "429 then success",
			steps:        []step{{status: 429}, {status: 202, opLoc: true}},
			wantAnalyzeN: 2,
		},
		{
			name:         "500 then success",
			steps:        []step{{status: 500}, {status: 202, opLoc: true}},
			wantAnalyzeN: 2,
		},
		{
			name: "exhausts retry budget",
			steps: []step{
				{status: 503}, {status: 503}, {status: 503}, {status: 503},
			},
			wantAnalyzeN: 4,
			wantErr:      true,
		},
		{
			name:         "401 is permanent immediately",
			steps:        []step{{status: 401, body: errBody("invalid subscription key")}},
			wantAnalyzeN: 1,
			wantErr:      true,
			wantMsg:      "invalid subscription key",
		},
		{
			name:         "404 is permanent immediately",
			steps:        []step{{status: 404, body: errBody("resource not found")}},
			wantAnalyzeN: 1,
			wantErr:      true,
			wantMsg:      "resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var analyzeN int32
			mux := http.NewServeMux()
			mux.HandleFunc(analyzePath, func(w http.ResponseWriter, r *http.Request) {
				i := int(atomic.AddInt32(&analyzeN, 1)) - 1
				if i >= len(tt.steps) {
					i = len(tt.steps) - 1
				}
				s := tt.steps[i]
				if s.opLoc {
					w.Header().Set("Operation-Location", "http://"+r.Host+
						"/documentintelligence/documentModels/prebuilt-read/analyzeResults/r1")
				}
				w.WriteHeader(s.status)
				io.WriteString(w, s.body)
			})
			mux.HandleFunc(pollPath, succeedPoll)
			mux.HandleFunc(fetchPath, succeedFetch("done"))

			srv := httptest.NewServer(mux)
			defer srv.Close()

			c, _ := testClient(srv)
			err := c.SearchablePDF(context.Background(), strings.NewReader("in"), io.Discard)

			if int(analyzeN) != tt.wantAnalyzeN {
				t.Errorf("analyze calls = %d, want %d", analyzeN, tt.wantAnalyzeN)
			}
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				return
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestSearchablePDF_MissingOperationLocation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(analyzePath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted) // no Operation-Location header
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := testClient(srv)
	err := c.SearchablePDF(context.Background(), strings.NewReader("in"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Operation-Location") {
		t.Fatalf("err = %v, want a mention of the missing Operation-Location header", err)
	}
}

func TestSearchablePDF_MalformedOperationBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(analyzePath, succeedAnalyze("r1"))
	mux.HandleFunc(pollPath, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "{not valid json")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := testClient(srv)
	err := c.SearchablePDF(context.Background(), strings.NewReader("in"), io.Discard)
	if err == nil {
		t.Fatal("want error for a malformed operation-status body")
	}
}

func TestSearchablePDF_ContextCancelledMidPoll(t *testing.T) {
	polled := make(chan struct{}, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(analyzePath, succeedAnalyze("r1"))
	mux.HandleFunc(pollPath, func(w http.ResponseWriter, _ *http.Request) {
		select {
		case polled <- struct{}{}:
		default:
		}
		// A Retry-After far larger than any sane test timeout: if
		// cancellation is not honoured promptly, this test hangs.
		w.Header().Set("Retry-After", "30")
		json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Real waiting here, deliberately: this is what proves cancellation
	// during the wait itself is honoured, not just plumbed through.
	c := &Client{HTTP: srv.Client(), Endpoint: srv.URL, APIVersion: "2024-11-30"}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-polled
		cancel()
	}()

	start := time.Now()
	err := c.SearchablePDF(ctx, strings.NewReader("in"), io.Discard)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("took %v to notice cancellation, want well under the 30s Retry-After", elapsed)
	}
}
