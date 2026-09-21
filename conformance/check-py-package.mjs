// Builds core/py into an sdist and a wheel, then consumes the WHEEL from a clean venv with
// no source directory on the path — the nearest thing to what a stranger gets from PyPI.
//
// The distinction this exists to enforce: passing the oracle proves the *code* is right;
// it says nothing about whether the *package* is. A pyproject.toml that only resolves in-tree,
// a `src` layout that forgets to ship a module, or a missing runtime dependency all pass
// conformance and fail the first `pip install`. This runs the conformance protocol again,
// against the installed wheel, so both claims are made separately.
//
// PYTHONPATH is stripped deliberately: if it leaked through, the consumer could import the
// working tree and the check would pass without the wheel containing anything at all.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pyDir = join(root, "core", "py");

const env = { ...process.env };
delete env.PYTHONPATH;

function run(label, program, args, cwd) {
  process.stdout.write(`${label} … `);
  const r = spawnSync(program, args, { cwd, encoding: "utf8", shell: false, env });
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

const systemPython = ["python3", "python"].find((c) => {
  const probe = spawnSync(c, ["--version"], { encoding: "utf8", shell: false });
  return !probe.error && probe.status === 0;
});
if (!systemPython) {
  console.error("no python3 on PATH");
  process.exit(1);
}

const work = mkdtempSync(join(tmpdir(), "archon-py-pkg-"));
try {
  const dist = join(work, "dist");
  run("build sdist + wheel", systemPython, ["-m", "build", pyDir, "--outdir", dist], work);

  const built = readdirSync(dist);
  const wheel = built.find((f) => f.endsWith(".whl"));
  const sdist = built.find((f) => f.endsWith(".tar.gz"));
  if (!wheel || !sdist) {
    console.error(`expected a wheel and an sdist, got: ${built.join(", ")}`);
    process.exit(1);
  }
  console.log(`     ${wheel}`);
  console.log(`     ${sdist}`);

  const venv = join(work, "venv");
  const py = join(venv, isWindows ? "Scripts" : "bin", isWindows ? "python.exe" : "python");
  run("clean venv", systemPython, ["-m", "venv", venv], work);
  // The wheel by path, not the project directory: this installs what would be uploaded.
  run("install the wheel", py, ["-m", "pip", "install", "--quiet", join(dist, wheel)], work);

  // Import from a directory that contains no archon source at all.
  const probe = spawnSync(
    py,
    ["-c", [
      "import archon_core as a",
      "seed = bytes(range(32))",
      "pub = a.public_key_from_seed(seed)",
      "text = a.encode_key(pub)",
      "assert a.decode_key(text) == pub",
      "sig = a.sign_in_domain(seed, 'example.v1', b'hello')",
      "assert a.verify_in_domain(pub, 'example.v1', b'hello', sig)",
      "assert not a.verify_in_domain(pub, 'other.v1', b'hello', sig)",
      "assert not a.verify(pub, b'hello', sig)",
      "print(f'installed {a.__version__}: {text}')",
    ].join("; ")],
    { cwd: work, encoding: "utf8", shell: false, env },
  );
  if (probe.status !== 0) {
    console.error("the installed wheel failed its consumer check");
    if (probe.stdout) console.error(probe.stdout.trim());
    if (probe.stderr) console.error(probe.stderr.trim());
    process.exit(1);
  }
  process.stdout.write(`consumer  … ok\n     ${probe.stdout.trim()}\n`);

  // And the conformance protocol again, this time against the INSTALLED package.
  const harness = join(root, "conformance", "harness.mjs");
  const result = spawnSync(
    process.execPath,
    [harness, join(root, "vectors", "identity.json"), `${py} -m archon_core._conformance`],
    { stdio: "inherit", env },
  );
  if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);
} finally {
  rmSync(work, { recursive: true, force: true });
}
