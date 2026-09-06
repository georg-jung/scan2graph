// Package version reports which build of the appliance is running, for the
// startup banner, "scan2graph --version" and the setup wizard's footer.
package version

import "runtime/debug"

// Stamp is baked in at link time by container builds
// (-ldflags "-X github.com/georg-jung/scan2graph/internal/version.Stamp=v1.2.3").
// The image needs it because .dockerignore keeps .git out of the build
// context, so the toolchain has no tags to derive anything from. Every other
// build leaves this empty and derives instead.
var Stamp string

// String is the version to show a human.
func String() string {
	var derived string
	if bi, ok := debug.ReadBuildInfo(); ok {
		derived = bi.Main.Version
	}
	return resolve(Stamp, derived)
}

// resolve is String's decision, kept separate so it can be tested: what the
// toolchain hands a test binary is not what it hands a real build.
//
// Without a stamp the answer is whatever Go derived from the nearest tag -
// "v0.2.0" when the build sat exactly on one, "v0.2.1-0.20260906093111-3faaf5b"
// a few commits later, "+dirty" appended when the tree had uncommitted
// changes. A build with no repository to read - a source archive rather than
// a clone, or "go test" - derives "(devel)", which tells an operator nothing,
// so it is not dressed up as a version.
func resolve(stamp, derived string) string {
	if stamp != "" {
		return stamp
	}
	if derived != "" && derived != "(devel)" {
		return derived
	}
	return "unknown"
}
