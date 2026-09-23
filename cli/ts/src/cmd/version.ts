// archon version — one line `archon <semver> (<commit>)`. The commit is ARCHON_GIT_COMMIT
// when the environment stamps it, else "unknown" — pinned only by SHAPE. The semver is
// pinned exactly: cli/smoke.mjs holds all three lanes to this package's version.
import { readFileSync } from "node:fs";
import { wantsHelp } from "../io.js";

// The package's own version, read from its package.json — which npm always publishes, and
// which sits three levels above this file once compiled (dist/src/cmd/version.js). The
// Rust lane does the same with CARGO_PKG_VERSION. A literal here said "0.5.0" from 0.5.0
// to 0.8.0, because a release bump updates the manifest and nothing held the copy.
const VERSION: string = (
  JSON.parse(readFileSync(new URL("../../../package.json", import.meta.url), "utf8")) as { version: string }
).version;
const USAGE = "usage: archon version  (prints version + build info)";

export function versionLine(): string {
  return `archon ${VERSION} (${process.env["ARCHON_GIT_COMMIT"] ?? "unknown"})`;
}

export function run(args: string[]): void {
  if (wantsHelp(args)) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  process.stdout.write(`${versionLine()}\n`);
}
