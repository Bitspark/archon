package main

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
)

// version is a version site: held to the tag by release.yml's manifest guard, and to the
// other two lanes by cli/smoke.mjs, which pins `archon version` to cli/ts's package version
// in all three. It said "0.5.0" from 0.5.0 to 0.8.0 because nothing held it — Go has no
// release build to stamp it, and the smoke case checked only the line's shape. A build can
// still override it with `-ldflags "-X main.version=<v>"`.
//
// It is the FALLBACK. A binary installed with `go install …/cli/go/cmd/archon@vX.Y.Z`
// carries the module version the Go toolchain resolved, and that is what it reports (see
// reportedVersion); the constant answers only for builds from a working tree.
var version = "0.8.1"

// releaseVersion matches what the toolchain records for a RELEASE — `vX.Y.Z` and nothing
// more. Go 1.24+ also stamps builds from a git checkout: a pseudo-version past the last tag
// (`v0.8.1-0.20260923150000-121655b5ef66`), `+dirty` for an unclean tree, `(devel)` with no
// VCS at all. None of those names a release, so none of them is reported.
var releaseVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// reportedVersion is the semver `archon version` prints, given the main module's version
// from the binary's build info: the toolchain's word for a release, else the constant.
func reportedVersion(mainVersion string) string {
	if releaseVersion.MatchString(mainVersion) {
		return strings.TrimPrefix(mainVersion, "v")
	}
	return version
}

const versionUsage = "usage: archon version  (prints version + build info)"

// versionLine is the single line both `archon version` and the top-level --version print:
// `archon <semver> (<commit>)`. The commit is the VCS revision when built from a repo,
// else "unknown" — pinned only by SHAPE, never byte-for-byte.
func versionLine() string {
	commit, mainVersion := "unknown", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		mainVersion = bi.Main.Version
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				commit = s.Value
			}
		}
	}
	return fmt.Sprintf("archon %s (%s)", reportedVersion(mainVersion), commit)
}

func runVersion(args []string) error {
	if wantsHelp(args) {
		fmt.Println(versionUsage)
		return nil
	}
	fmt.Println(versionLine())
	return nil
}
