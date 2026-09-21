// Drives the Python core through the shared harness against vectors/identity.json.
//
// Separate from check.mjs on purpose. That script is the tri-core check and needs Go, Rust
// and Node; making every further language a prerequisite would mean a contributor with no
// Python toolchain can no longer run the one command the README advertises. Bitwire splits
// the same way: a cheap cross-language job, then one job per additional binding.
//
// Splitting costs nothing, because agreement here is transitive THROUGH THE ORACLE rather
// than pairwise. Every core recomputes each case from its inputs and is asserted against the
// same fixed vectors, so "the Python core agrees with the oracle" and "the Go core agrees
// with the oracle" together mean the two agree with each other. That property is what lets
// this scale past three implementations.
//
// The venv is built once under core/py/.venv and reused. It installs the package itself, so
// a broken pyproject.toml fails here rather than at publish time.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pyDir = join(root, "core", "py");
const venv = join(pyDir, ".venv");
const venvPython = join(venv, isWindows ? "Scripts" : "bin", isWindows ? "python.exe" : "python");

function run(label, program, args, cwd) {
  process.stdout.write(`${label} … `);
  const r = spawnSync(program, args, { cwd, encoding: "utf8", shell: false });
  if (r.error || r.status !== 0) {
    console.log("FAILED");
    if (r.stdout) console.error(r.stdout.trim());
    if (r.stderr) console.error(r.stderr.trim());
    if (r.error) console.error(r.error.message);
    process.exit(1);
  }
  console.log("ok");
}

// `python3` first: on most Linux images `python` is absent or is Python 2.
const systemPython = ["python3", "python"].find((candidate) => {
  const probe = spawnSync(candidate, ["--version"], { encoding: "utf8", shell: false });
  return !probe.error && probe.status === 0;
});
if (!systemPython) {
  console.error("conformance: no python3 on PATH — the Python core cannot be checked");
  process.exit(1);
}

if (!existsSync(venvPython)) {
  run("create venv", systemPython, ["-m", "venv", venv], pyDir);
}
// Installing the package (not just its dependency) means a pyproject.toml that cannot build
// fails in CI on every push, rather than on release day.
run("install core/py", venvPython, ["-m", "pip", "install", "--quiet", "--upgrade", "pip"], pyDir);
run("install core/py deps", venvPython, ["-m", "pip", "install", "--quiet", "-e", "."], pyDir);

const harness = join(root, "conformance", "harness.mjs");
const result = spawnSync(
  process.execPath,
  [harness, join(root, "vectors", "identity.json"), `${venvPython} -m archon_core._conformance`],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
