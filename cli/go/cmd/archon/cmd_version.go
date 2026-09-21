package main

import (
	"fmt"
	"runtime/debug"
)

// version defaults to a semver so `archon version` has a valid shape even under `go run`;
// a release build can override it with `-ldflags "-X main.version=<v>"`.
var version = "0.5.0"

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
