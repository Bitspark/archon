// archon version — one line `archon <semver> (<commit>)`. The commit is ARCHON_GIT_COMMIT
// when the environment stamps it, else "unknown" — pinned only by SHAPE, never byte-for-byte.
import { wantsHelp } from "../io.js";

const VERSION = "0.5.0";
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
