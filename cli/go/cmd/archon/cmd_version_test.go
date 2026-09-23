package main

import "testing"

// What `archon version` reports for each shape of main-module version the Go toolchain
// records. Only a clean release version is believed; everything a working-tree build can
// carry falls back to the guard-held constant.
func TestReportedVersion(t *testing.T) {
	for _, c := range []struct{ mainVersion, want string }{
		{"v0.8.1", "0.8.1"}, // go install …/cli/go/cmd/archon@v0.8.1
		{"v1.12.30", "1.12.30"},
		{"(devel)", version}, // a build with no VCS information
		{"", version},        // no build info at all
		{"v0.8.1-0.20260923150000-121655b5ef66", version}, // a checkout past a tag
		{"v0.8.1+dirty", version},                         // a tagged checkout with edits
		{"v0.8.1-0.20260923150000-121655b5ef66+dirty", version},
		{"v0.9.0-rc.1", version}, // a pre-release is not a release
		{"0.8.1", version},       // not a module version at all
	} {
		if got := reportedVersion(c.mainVersion); got != c.want {
			t.Errorf("reportedVersion(%q) = %q, want %q", c.mainVersion, got, c.want)
		}
	}
}
