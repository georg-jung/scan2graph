package version

import "testing"

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		name           string
		stamp, derived string
		want           string
	}{
		{"container build", "v1.2.3", "(devel)", "v1.2.3"},
		{"stamp beats a derived version too", "v1.2.3", "v9.9.9", "v1.2.3"},
		{"released binary", "", "v0.2.0", "v0.2.0"},
		{"commits past a tag", "", "v0.2.1-0.20260906093111-3faaf5bdda41", "v0.2.1-0.20260906093111-3faaf5bdda41"},
		{"uncommitted tree", "", "v0.2.0+dirty", "v0.2.0+dirty"},
		{"source archive, no repository", "", "(devel)", "unknown"},
		{"no build info at all", "", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolve(tc.stamp, tc.derived); got != tc.want {
				t.Errorf("resolve(%q, %q) = %q, want %q", tc.stamp, tc.derived, got, tc.want)
			}
		})
	}
}

// TestStringNeverEmpty pins the one thing every caller relies on: the banner,
// the wizard footer and --version always have something to print.
func TestStringNeverEmpty(t *testing.T) {
	if String() == "" {
		t.Error("String() is empty")
	}
}
