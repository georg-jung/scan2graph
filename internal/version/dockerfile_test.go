package version

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDockerfileStampsThisPackage guards the one mistake in the v2 checklist
// that fails silently: the Dockerfile names this variable by its full module
// path, so a module path that grows a "/v2" while the -X flag does not leaves
// the image reporting "unknown" - a working build, a working container, and a
// version that is simply gone. Comparing against go.mod catches it here
// instead of in a published image.
func TestDockerfileStampsThisPackage(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("no module line in go.mod")
	}
	want := "-X " + string(m[1]) + "/internal/version.Stamp="

	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), want) {
		t.Errorf("Dockerfile does not stamp this package; expected to find %q.\n"+
			"See the v2 checklist in docs/versioning.md.", want)
	}
}
