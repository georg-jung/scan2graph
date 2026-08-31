package smtpin

import (
	"errors"
	"fmt"
	"testing"

	"github.com/emersion/go-smtp"

	"github.com/georg-jung/scan2graph/internal/mimescan"
)

// TestExtractErrorMapping pins the reply each extraction failure earns:
// over limits 552, nothing usable in the message 550, and anything that is
// this machine's problem 451, so a printer retries instead of discarding a
// scan it did deliver.
func TestExtractErrorMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"too complex", fmt.Errorf("walk: %w", mimescan.ErrTooComplex), 552},
		{"no pdf", mimescan.ErrNoPDF, 550},
		{"unparsable headers", errors.New("mimescan: parse message: malformed MIME header"), 550},
		{"storage failure", fmt.Errorf("%w: no space left on device", mimescan.ErrStorage), 451},
		{"server size limit passed through", smtp.ErrDataTooLarge, 552},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractError(tt.err).Code; got != tt.want {
				t.Errorf("extractError(%v).Code = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
