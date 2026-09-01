package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// markerPath is the one-shot setup marker for a configuration file path: it
// exists only between "scan2graph setup-next-start" minting a token and the
// next unauthenticated-by-default "scan2graph" start consuming it. It holds
// a hash, never the token itself, so nothing usable is ever at rest.
func markerPath(configPath string) string {
	return configPath + ".setup"
}

// mintToken returns a fresh one-shot setup token together with the SHA-256
// that is all anything else ever stores or compares. Handing out the token is
// the only moment it exists in the clear, so it goes straight to the operator
// - stderr of the command they ran, which no redirect of stdout and no log
// level can lose - and never through a log.
func mintToken() (token string, hash []byte) {
	token = rand.Text()
	sum := sha256.Sum256([]byte(token))
	return token, sum[:]
}

// createMarker mints a fresh token and writes hex(sha256(token)) plus a
// trailing newline to path, 0600 (a secret's mode). It returns the token -
// the only moment it is ever available, since only its hash is stored. A
// write that fails - a full disk - takes the marker with it, because
// os.WriteFile creates and truncates before it writes and would otherwise
// leave an empty one behind. A power cut in the microsecond the write itself
// takes is consumeMarker's problem, not this function's: its length check is
// what turns a torn marker into a loud, actionable error instead of a silent
// lockout.
func createMarker(path string) (token string, err error) {
	token, hash := mintToken()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(hash)+"\n"), 0o600); err != nil {
		os.Remove(path) // a half-written marker would stop the next start
		return "", err
	}
	return token, nil
}

// consumeMarker reads the marker at path, decodes its hash and removes the
// file. A missing file is not an error: it means "setup-next-start" was
// never run, so (nil, nil) tells the caller to proceed as normal. A marker
// that fails to decode is left in place rather than removed, so it surfaces
// as a startup error instead of silently vanishing.
func consumeMarker(path string) (hash []byte, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	hash, err = hex.DecodeString(strings.TrimSpace(string(data)))
	// The length matters as much as the decoding: hex.DecodeString takes an
	// empty file for an empty hash and reports no error at all, and that hash
	// can never match a token - so the appliance would refuse to serve, open
	// a wizard nobody can get into, and answer 404 to everything while
	// /healthz still says 200. Both shapes get the message that names the way
	// out, because the file is not one an operator would think to look for.
	if err != nil || len(hash) != sha256.Size {
		return nil, fmt.Errorf("corrupt setup marker %s: delete it to start normally", path)
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return hash, nil
}
