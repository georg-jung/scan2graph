package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkerRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan2graph.env.setup")

	token, err := createMarker(path)
	if err != nil {
		t.Fatalf("createMarker: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("marker mode = %o, want 0600", perm)
	}

	want := sha256.Sum256([]byte(token))
	hash, err := consumeMarker(path)
	if err != nil {
		t.Fatalf("consumeMarker: %v", err)
	}
	if hex.EncodeToString(hash) != hex.EncodeToString(want[:]) {
		t.Errorf("consumeMarker hash = %x, want %x", hash, want)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("marker file still exists after consume (stat err = %v)", err)
	}

	// A second consume, with the file already gone, is a no-op rather than
	// an error - this is what lets a crash loop not re-open the wizard.
	hash, err = consumeMarker(path)
	if err != nil || hash != nil {
		t.Errorf("second consumeMarker = (%x, %v), want (nil, nil)", hash, err)
	}
}

// TestConsumeMarkerTorn covers what a corrupt or interrupted write can leave
// behind. Any of these shapes must fail loudly rather than silently: an empty
// file decodes to an empty hash with no error at all, and the appliance would
// then open a wizard whose token can never match while answering 404 to
// everything else.
func TestConsumeMarkerTorn(t *testing.T) {
	full := hex.EncodeToString(make([]byte, sha256.Size))
	for name, content := range map[string]string{
		"zero-byte":  "",
		"odd length": full[:31],
		"truncated":  full[:30],
		"too long":   full + "00",
		"not hex":    "not hex\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "scan2graph.env.setup")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := consumeMarker(path)
			if err == nil {
				t.Fatal("consumeMarker succeeded, want an error")
			}
			// The operator has to be told the way out: this file is not one
			// they would think to look for.
			if !strings.Contains(err.Error(), "delete it to start normally") ||
				!strings.Contains(err.Error(), path) {
				t.Errorf("error %q names neither the file nor the recovery", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("a corrupt marker should be left in place: stat: %v", err)
			}
		})
	}
}
