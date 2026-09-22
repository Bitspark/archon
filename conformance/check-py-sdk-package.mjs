// Builds sdk/py (and core/py beneath it) into wheels, then consumes the SDK WHEEL from a clean
// venv with no source directory on the path — the nearest thing to what a stranger gets from
// PyPI. The sdk's sibling of check-py-package.mjs.
//
// Passing the oracle proves the code; this proves the package. Three things only an install
// can show, each asserted rather than inferred from the install having worked:
//
//   1. The sdk names the floor by a REGISTRY range (`bitspark-archon-core~=<version>`), not a
//      path — what a consumer's pip resolves on PyPI. The range must equal the version this
//      tree is at: an sdk naming an older floor than the one it was tested against is how a
//      lockstep release quietly stops being one.
//   2. Both packages import from site-packages, not from this checkout.
//   3. The conformance protocol passes again against the INSTALLED sdk.
//
// The floor's wheel is built from this tree and passed to pip explicitly, so the sdk is
// consumed against the core under review — never against whatever PyPI happens to serve.
// PYTHONPATH is stripped for the same reason check-py-package.mjs strips it.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sdkDir = join(root, "sdk", "py");
const coreDir = join(root, "core", "py");

const env = { ...process.env };
delete env.PYTHONPATH;

// Read, never repeat: the version comes from the manifest, so this check cannot go red for a
// reason of its own the day the version moves.
function versionOf(dir) {
  const m = readFileSync(join(dir, "pyproject.toml"), "utf8").match(/^version = "([^"]+)"/m);
  if (!m) throw new Error(`no version in ${join(dir, "pyproject.toml")}`);
  return m[1];
}
const sdkVersion = versionOf(sdkDir);
const coreVersion = versionOf(coreDir);
if (sdkVersion !== coreVersion) {
  console.error(`lockstep broken: sdk/py is ${sdkVersion}, core/py is ${coreVersion}`);
  process.exit(1);
}

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

const work = mkdtempSync(join(tmpdir(), "archon-py-sdk-pkg-"));
try {
  const dist = join(work, "dist");
  run("build core/py", systemPython, ["-m", "build", coreDir, "--outdir", dist], work);
  run("build sdk/py sdist + wheel", systemPython, ["-m", "build", sdkDir, "--outdir", dist], work);

  const built = readdirSync(dist);
  const sdkWheel = built.find((f) => f.startsWith("bitspark_archon_sdk-") && f.endsWith(".whl"));
  const sdkSdist = built.find((f) => f.startsWith("bitspark_archon_sdk-") && f.endsWith(".tar.gz"));
  const coreWheel = built.find((f) => f.startsWith("bitspark_archon_core-") && f.endsWith(".whl"));
  if (!sdkWheel || !sdkSdist || !coreWheel) {
    console.error(`expected an sdk wheel + sdist and a core wheel, got: ${built.join(", ")}`);
    process.exit(1);
  }
  console.log(`     ${sdkWheel}\n     ${sdkSdist}\n     ${coreWheel} (the floor under review)`);

  const venv = join(work, "venv");
  const py = join(venv, isWindows ? "Scripts" : "bin", isWindows ? "python.exe" : "python");
  run("clean venv", systemPython, ["-m", "venv", venv], work);
  // Both wheels by path: this installs what would be uploaded, and satisfies the sdk's floor
  // requirement with the floor built above rather than one fetched from PyPI.
  run("install the wheels", py, ["-m", "pip", "install", "--quiet", join(dist, coreWheel), join(dist, sdkWheel)], work);

  // Run from a directory that contains no archon source at all.
  const probe = spawnSync(
    py,
    ["-c", [
      "import importlib.metadata as md, pathlib, sys",
      "import archon_core, archon_sdk",
      "from archon_sdk import envelope, possession",
      `want = ${JSON.stringify(sdkVersion)}`,
      "reqs = [r for r in (md.requires('bitspark-archon-sdk') or []) if r.split(';')[0].strip().startswith('bitspark-archon-core')]",
      "assert reqs == ['bitspark-archon-core~=' + want], f'the sdk names the floor as {reqs}, want bitspark-archon-core~={want}'",
      "assert archon_sdk.__version__ == want == md.version('bitspark-archon-sdk'), 'sdk metadata and self-report disagree'",
      "assert md.version('bitspark-archon-core') == want, 'the installed floor is not the one under review'",
      "for m in (archon_core, archon_sdk): assert 'site-packages' in pathlib.Path(m.__file__).parts, f'{m.__name__} imported from {m.__file__}'",
      "seed = bytes(range(32)); pub = archon_core.public_key_from_seed(seed)",
      "nonce, binding = bytes(range(16)), b'channel'",
      "proof = possession.prove(seed, 'example/pop/v1', nonce, binding)",
      "assert possession.verify(pub, 'example/pop/v1', nonce, binding, proof)",
      "assert not possession.verify(pub, 'example/pop/v1', nonce, b'other', proof)",
      "sealed = envelope.seal(seed, 'example/env/v1', b'payload')",
      "assert envelope.open(sealed, 'example/env/v1').payload == b'payload'",
      // The sdk-only refusal: a GENUINE envelope in another domain. An opener that trusted the
      // envelope's own domain field would return its payload.
      "other = envelope.seal(seed, 'example/env/other', b'payload')",
      "try:\n    envelope.open(other, 'example/env/v1')\nexcept ValueError:\n    pass\nelse:\n    sys.exit('an envelope sealed in another domain was opened')",
      "print(f'installed sdk {archon_sdk.__version__} on core {archon_core.__version__}; names the floor as {reqs[0]}')",
    ].join("\n")],
    { cwd: work, encoding: "utf8", shell: false, env },
  );
  if (probe.status !== 0) {
    console.error("the installed sdk wheel failed its consumer check");
    if (probe.stdout) console.error(probe.stdout.trim());
    if (probe.stderr) console.error(probe.stderr.trim());
    process.exit(1);
  }
  process.stdout.write(`consumer  … ok\n     ${probe.stdout.trim()}\n`);

  const harness = join(root, "conformance", "harness.mjs");
  const result = spawnSync(
    process.execPath,
    [harness, join(root, "vectors", "sdk.json"), `${py} -m archon_sdk._conformance`],
    { stdio: "inherit", env, cwd: work },
  );
  if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);
} finally {
  rmSync(work, { recursive: true, force: true });
}
