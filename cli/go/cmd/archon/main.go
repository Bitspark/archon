// archon — the human-facing CLI for the Go lane.
//
// A thin presentation + I/O layer over the public archon core API. The shape is fixed:
// `archon <subcommand> [args]`. Each subcommand lives in its own cmd_*.go file behind a
// single run(args) handler registered in dispatch; main only routes the name to its
// handler. Results go to stdout; diagnostics, usage, and the keygen secret warning go to
// stderr; any error exits non-zero. Three native binaries (cli/rs, cli/go, cli/ts) build
// the SAME `archon` command with byte-identical stdout, pinned by cli/smoke.mjs.
//
// `key` and `keygen` were carved out of thesmos's CLI on 2026-09-09 (docs/growth-plan.md
// §8.2): they contained no thesmos term and archon shipped no CLI at all. `sign` and
// `verify` are new: raw bytes, domain-aware.
package main

import (
	"fmt"
	"os"
)

// usage is the one-line subcommand summary, printed to stderr on an unknown or missing
// subcommand (exit 2) and to stdout on --help/-h (exit 0).
const usage = "usage: archon <keygen|key|login|sign|verify|version> [args]"

// dispatch maps a subcommand name to its handler.
var dispatch = map[string]func(args []string) error{
	"keygen":  runKeygen,
	"key":     runKey,
	"login":   runLogin,
	"sign":    runSign,
	"verify":  runVerify,
	"version": runVersion,
}

// wantsHelp reports whether args request this command's help — `<cmd> --help` / `-h`,
// with the flag as the first token. Help is success (usage to STDOUT, exit 0), distinct
// from the error path (usage to stderr, exit non-zero).
func wantsHelp(args []string) bool {
	return len(args) > 0 && (args[0] == "--help" || args[0] == "-h")
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	command, rest := args[0], args[1:]
	if command == "--help" || command == "-h" {
		fmt.Println(usage)
		os.Exit(0)
	}
	if command == "--version" {
		fmt.Println(versionLine())
		os.Exit(0)
	}
	handler, ok := dispatch[command]
	if !ok {
		fmt.Fprintf(os.Stderr, "archon: unknown subcommand %q\n%s\n", command, usage)
		os.Exit(2)
	}
	if err := handler(rest); err != nil {
		var v verdict
		if asVerdict(err, &v) {
			// A verdict (`invalid`), not a usage error: already on stdout, exit 1, no
			// "archon verify:" line on stderr.
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "archon %s: %v\n", command, err)
		os.Exit(1)
	}
}
