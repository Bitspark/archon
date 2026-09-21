// The differential run over the three cores check.mjs already built (ADR 0008 §Consequences):
// fresh members of every verification-profile class through Go, Rust and TypeScript, with no
// oracle — any case two cores answer differently, or any non-genuine case all three accept,
// fails. Three fixed seeds, so a finding is reproducible by number and the run is the same on
// a laptop and in CI. Run AFTER check.mjs: it reuses the binaries and installs nothing.
//
//   node conformance/check-differential.mjs            the three cores, seeds 1 2 3
//   node conformance/check-differential.mjs "<cli>"…   these CLIs instead (at least two)
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const exe = isWindows ? ".exe" : "";
const root = dirname(dirname(fileURLToPath(import.meta.url)));

let clis = process.argv.slice(2);
if (clis.length === 0) {
  clis = [
    join(root, "bin", `conformance-go${exe}`),
    join(root, "core", "rs", "target", "debug", `conformance${exe}`),
    `node ${join(root, "core", "ts", "dist", "conformance", "cli.js")}`,
  ];
  for (const c of clis) {
    const p = c.replace(/^node /, "");
    if (!existsSync(p)) {
      console.error(`missing build output: ${p} — run node conformance/check.mjs first`);
      process.exit(1);
    }
  }
}

const generator = join(root, "conformance", "profile-cases.mjs");
for (const seed of [1, 2, 3]) {
  const r = spawnSync(process.execPath,
    [generator, "differential", "--seed", String(seed), "--per-class", "24", ...clis],
    { stdio: "inherit" });
  if ((r.status ?? 1) !== 0) process.exit(r.status ?? 1);
}
