// Builds all three conformance CLIs, then drives them through the harness.
//
// One command — `node conformance/check.mjs` — is the whole tri-core check. It exists so
// the check is the same on a laptop and in CI, and so nobody has to remember three build
// invocations and three binary paths.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const exe = isWindows ? ".exe" : "";
// Derived from this file's location, never from cwd: `node conformance/check.mjs` must
// mean the same thing from the repo root, from a subdirectory, and from a CI step whose
// working-directory someone changed later.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const bin = join(root, "bin");
mkdirSync(bin, { recursive: true });

function run(label, program, args, cwd) {
  process.stdout.write(`build ${label} … `);
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

const tsDir = join(root, "core", "ts");
const tsc = join(tsDir, "node_modules", "typescript", "bin", "tsc");
const sdkTsDir = join(root, "sdk", "ts");
const sdkTsc = join(sdkTsDir, "node_modules", "typescript", "bin", "tsc");

// Bootstrap the TS toolchain if it is absent. Without this, a fresh clone running the
// one command the README advertises died on a raw MODULE_NOT_FOUND stack trace for
// typescript/bin/tsc — technically correct, useless as an error. `ci`, not `install`:
// the committed lockfile is the reproducibility floor. Two packages: the floor, then the
// sdk (which consumes the floor through a file: dependency).
for (const [dir, tscPath] of [[tsDir, tsc], [sdkTsDir, sdkTsc]]) {
  if (existsSync(tscPath)) continue;
  process.stdout.write(`install ts deps (${dir.slice(root.length + 1)}) … `);
  // Same shell-free discipline as tsc below: npm ships as a .cmd shim on Windows, so we
  // run its JS entry with the node we are already running rather than asking a shell to
  // resolve it. Both layouts exist in the wild (Windows keeps npm beside node.exe, POSIX
  // installs put it under ../lib); the shim is the last resort, not the first choice.
  const npmCli = [
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
    join(dirname(process.execPath), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ].find(existsSync);
  const npm = npmCli
    ? spawnSync(process.execPath, [npmCli, "ci"], { cwd: dir, encoding: "utf8" })
    : spawnSync(isWindows ? "npm.cmd" : "npm", ["ci"],
        { cwd: dir, encoding: "utf8", shell: isWindows });
  if (npm.error || npm.status !== 0) {
    console.log("FAILED");
    if (npm.stderr) console.error(npm.stderr.trim());
    if (npm.error) console.error(npm.error.message);
    console.error(`run \`npm ci\` in ${dir} and try again`);
    process.exit(1);
  }
  console.log("ok");
}

const goBin = join(bin, `conformance-go${exe}`);
const rsBin = join(root, "core", "rs", "target", "debug", `conformance${exe}`);
const tsEntry = join(root, "core", "ts", "dist", "conformance", "cli.js");

run("go", isWindows ? "go.exe" : "go", ["build", "-o", goBin, "./cmd/conformance"], join(root, "core", "go"));
run("rs", isWindows ? "cargo.exe" : "cargo",
    ["build", "-q", "--features", "conformance-cli", "--bin", "conformance"], join(root, "core", "rs"));
// tsc is invoked through its JS entry rather than the `npx`/`tsc` shim: Node refuses to
// spawn a Windows .cmd file without a shell, and going through a shell is exactly the
// cross-platform hazard spawn.mjs exists to avoid.
run("ts", process.execPath, [tsc, "-p", "tsconfig.json"], tsDir);

// The layer above the floor: its own three CLIs over its own oracle (vectors/sdk.json).
// sdk/ts consumes core/ts through a file: dependency, so the core build above must come
// first; sdk/go resolves core/go through the repository's go.work.
const sdkGoBin = join(bin, `conformance-sdk-go${exe}`);
const sdkRsBin = join(root, "sdk", "rs", "target", "debug", `conformance${exe}`);
const sdkTsEntry = join(root, "sdk", "ts", "dist", "conformance", "cli.js");
run("sdk go", isWindows ? "go.exe" : "go", ["build", "-o", sdkGoBin, "./cmd/conformance"], join(root, "sdk", "go"));
run("sdk rs", isWindows ? "cargo.exe" : "cargo",
    ["build", "-q", "--features", "conformance-cli", "--bin", "conformance"], join(root, "sdk", "rs"));
run("sdk ts", process.execPath, [sdkTsc, "-p", "tsconfig.json"], sdkTsDir);

// The command's own layer: the key store (vectors/keystore.json, ADR 0007 §A).
// Custody is the CLI tier's, so this oracle is driven by the cli/* lanes. cli/ts consumes
// core/ts through a file: dependency, so the core build above must come first.
const cliTsDir = join(root, "cli", "ts");
const cliTsc = join(cliTsDir, "node_modules", "typescript", "bin", "tsc");
const cliGoBin = join(bin, `conformance-cli-go${exe}`);
const cliRsBin = join(root, "cli", "rs", "target", "debug", `conformance${exe}`);
const cliTsEntry = join(cliTsDir, "dist", "conformance", "cli.js");
if (!existsSync(cliTsc)) {
  process.stdout.write(`install ts deps (cli/ts) … `);
  const npmCli = [
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
    join(dirname(process.execPath), "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ].find(existsSync);
  const npm = npmCli
    ? spawnSync(process.execPath, [npmCli, "install"], { cwd: cliTsDir, encoding: "utf8" })
    : spawnSync(isWindows ? "npm.cmd" : "npm", ["install"],
        { cwd: cliTsDir, encoding: "utf8", shell: isWindows });
  if (npm.error || npm.status !== 0) {
    console.log("FAILED");
    if (npm.stderr) console.error(npm.stderr.trim());
    process.exit(1);
  }
  console.log("ok");
}
run("cli go", isWindows ? "go.exe" : "go", ["build", "-o", cliGoBin, "./cmd/conformance"], join(root, "cli", "go"));
run("cli rs", isWindows ? "cargo.exe" : "cargo",
    ["build", "-q", "--features", "conformance-cli", "--bin", "conformance"], join(root, "cli", "rs"));
run("cli ts", process.execPath, [cliTsc, "-p", "tsconfig.json"], cliTsDir);

for (const p of [goBin, rsBin, tsEntry, sdkGoBin, sdkRsBin, sdkTsEntry, cliGoBin, cliRsBin, cliTsEntry]) {
  if (!existsSync(p)) {
    console.error(`missing build output: ${p}`);
    process.exit(1);
  }
}

console.log();
const harness = join(root, "conformance", "harness.mjs");
const floor = spawnSync(process.execPath,
  [harness, join(root, "vectors", "identity.json"), goBin, rsBin, `node ${tsEntry}`],
  { stdio: "inherit" });
if ((floor.status ?? 1) !== 0) process.exit(floor.status ?? 1);
console.log();
const sdk = spawnSync(process.execPath,
  [harness, join(root, "vectors", "sdk.json"), sdkGoBin, sdkRsBin, `node ${sdkTsEntry}`],
  { stdio: "inherit" });
if ((sdk.status ?? 1) !== 0) process.exit(sdk.status ?? 1);
console.log();
// The login scheme (docs/login.md): the same three sdk CLIs over vectors/login.json.
const login = spawnSync(process.execPath,
  [harness, join(root, "vectors", "login.json"), sdkGoBin, sdkRsBin, `node ${sdkTsEntry}`],
  { stdio: "inherit" });
if ((login.status ?? 1) !== 0) process.exit(login.status ?? 1);
console.log();
// The command's own layer: the key store (vectors/keystore.json, ADR 0007 §A),
// driven by the cli/* lanes because custody is the CLI tier's.
const keystore = spawnSync(process.execPath,
  [harness, join(root, "vectors", "keystore.json"), cliGoBin, cliRsBin, `node ${cliTsEntry}`],
  { stdio: "inherit" });
process.exit(keystore.status ?? 1);
