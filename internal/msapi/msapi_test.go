package msapi

import (
	"net/http"
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
		{"zero seconds", "0", time.Second, 0},
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

	t.Run("http-date in the past clamps to zero", func(t *testing.T) {
		h := http.Header{"Retry-After": {time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)}}
		if got := RetryAfter(h, time.Minute); got != 0 {
			t.Errorf("RetryAfter(past date) = %v, want 0", got)
		}
	})
}
