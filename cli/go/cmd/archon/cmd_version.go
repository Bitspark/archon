package main

import (
	"fmt"
	"runtime/debug"
)

// version is a version site: held to the tag by release.yml's manifest guard, and to the
// other two lanes by cli/smoke.mjs, which pins `archon version` to cli/ts's package version
// in all three. It said "0.5.0" from 0.5.0 to 0.8.0 because nothing held it — Go has no
// release build to stamp it, and the smoke case checked only the line's shape. A build can
// still override it with `-ldflags "-X main.version=<v>"`.
var version = "0.8.1"

const versionUsage = "usage: archon version  (prints version + build info)"

// versionLine is the single line both `archon version` and the top-level --version print:
// `archon <semver> (<commit>)`. The commit is the VCS revision when built from a repo,
// else "unknown" — pinned only by SHAPE, never byte-for-byte.
func versionLine() string {
	commit := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				commit = s.Value
			}
		}
	}
	return fmt.Sprintf("archon %s (%s)", version, commit)
}

func runVersion(args []string) error {
	if wantsHelp(args) {
		fmt.Println(versionUsage)
		return nil
	}
	fmt.Println(versionLine())
	return nil
}
