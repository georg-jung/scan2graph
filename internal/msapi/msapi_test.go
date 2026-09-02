package msapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRetryAfter(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		fallback time.Duration
		want     time.Duration
	}{
		{"absent falls back", "", 5 * time.Second, 5 * time.Second},
		{"seconds", "2", time.Second, 2 * time.Second},
		{"zero seconds is floored", "0", time.Second, baseBackoff},
		{"negative seconds falls back", "-1", 5 * time.Second, 5 * time.Second},
		{"clamped to maxWait", "9999", time.Second, maxWait},
		{"garbage falls back", "soon please", 5 * time.Second, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.value != "" {
				h.Set("Retry-After", tt.value)
			}
			if got := RetryAfter(h, tt.fallback); got != tt.want {
				t.Errorf("RetryAfter(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}

	t.Run("http-date in the future", func(t *testing.T) {
		h := http.Header{"Retry-After": {time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)}}
		got := RetryAfter(h, time.Minute)
		if got <= 0 || got > 2*time.Second+500*time.Millisecond {
			t.Errorf("RetryAfter(future date) = %v, want roughly 2s", got)
		}
	})

	// A wait of zero would spin: the poll loop calls this on every response
	// and the retry loop would exhaust its attempts in microseconds.
	t.Run("http-date in the past is floored", func(t *testing.T) {
		h := http.Header{"Retry-After": {time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)}}
		if got := RetryAfter(h, time.Minute); got != baseBackoff {
			t.Errorf("RetryAfter(past date) = %v, want %v", got, baseBackoff)
		}
	})
}

// fakeSignature, from roles_test.go, doubles as the stand-in credential here:
// one obviously synthetic literal per package, so a scanner has one thing to
// look at rather than several.
//
// Graph hands out upload session URLs that carry their own authorization in
// the query string. Go's client puts the whole URL, query included, into the
// *url.Error it returns for a transport failure - so a dropped connection
// mid-upload would put a credential straight into the log the moment the
// caller reports the error. Do must not let it.
func TestDoTransportErrorKeepsTheURLOutOfTheMessage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing is listening now, so the request fails to dial

	c := &Client{HTTP: &http.Client{Timeout: time.Second}, Sleep: func(context.Context, time.Duration) {}}
	_, err = c.Do(context.Background(), func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut,
			"http://"+addr+"/uploadsession/fake?authtoken="+fakeSignature, strings.NewReader("chunk"))
	})
	if err == nil {
		t.Fatal("Do: want an error, nothing is listening")
	}
	if strings.Contains(err.Error(), fakeSignature) || strings.Contains(err.Error(), "authtoken") {
		t.Errorf("err = %v, want the query string left out of it", err)
	}
	// The path still has to be there, or a failure names no request at all.
	if !strings.Contains(err.Error(), "/uploadsession/fake") {
		t.Errorf("err = %v, want it to name the request's path", err)
	}
}
