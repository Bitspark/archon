// Drives the Python sdk through the shared harness against vectors/sdk.json.
//
// The sdk's sibling of check-py.mjs, and separate from it for the same reason that script is
// separate from check.mjs: each check needs only its own toolchain. Agreement is transitive
// through the oracle, so "the Python sdk agrees with sdk.json" and "the Go sdk agrees with
// sdk.json" together mean the two agree with each other.
//
// The venv installs the IN-TREE floor alongside the sdk, in one pip invocation, so the sdk is
// tested against the core in this checkout — not whatever `bitspark-archon-core` PyPI serves.
// An sdk change that needs a core change would otherwise pass here against the old floor and
// fail after release.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sdkDir = join(root, "sdk", "py");
const coreDir = join(root, "core", "py");
const venv = join(sdkDir, ".venv");
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
  return r;
}

// `python3` first: on most Linux images `python` is absent or is Python 2.
const systemPython = ["python3", "python"].find((candidate) => {
  const probe = spawnSync(candidate, ["--version"], { encoding: "utf8", shell: false });
  return !probe.error && probe.status === 0;
});
if (!systemPython) {
  console.error("conformance: no python3 on PATH — the Python sdk cannot be checked");
  process.exit(1);
}

if (!existsSync(venvPython)) {
  run("create venv", systemPython, ["-m", "venv", venv], sdkDir);
}
run("upgrade pip", venvPython, ["-m", "pip", "install", "--quiet", "--upgrade", "pip"], sdkDir);
run("install core/py + sdk/py", venvPython, ["-m", "pip", "install", "--quiet", "-e", coreDir, "-e", sdkDir], sdkDir);

// Assert the floor the sdk imports IS this checkout's, rather than trusting the install
// order: a green run against PyPI's core would say nothing about the tree under review.
const where = run(
  "the floor is this checkout's",
  venvPython,
  ["-c", "import archon_core, pathlib; print(pathlib.Path(archon_core.__file__).resolve())"],
  sdkDir,
);
const floorFile = where.stdout.trim();
if (!floorFile.toLowerCase().startsWith(join(coreDir, "src").toLowerCase())) {
  console.error(`archon_core resolved to ${floorFile}, not ${join(coreDir, "src")}`);
  process.exit(1);
}

const harness = join(root, "conformance", "harness.mjs");
const result = spawnSync(
  process.execPath,
  [harness, join(root, "vectors", "sdk.json"), `${venvPython} -m archon_sdk._conformance`],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
