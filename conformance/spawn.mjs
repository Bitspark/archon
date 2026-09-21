// Cross-platform process invocation for the conformance harness.
//
// Copied verbatim from thesmos conformance/spawn.mjs @ d878832 (with the example
// command strings updated for archon's layout). It is pure process plumbing: no
// authority vocabulary, no archon vocabulary, nothing to re-derive.
//
// The driver receives each core's CLI as a single shell-prefix STRING (e.g.
// "cargo run -q --manifest-path core/rs/Cargo.toml --features conformance-cli --bin conformance --" or "node core/ts/dist/conformance/cli.js") and append
// per-call arguments (a family name). The original code ran
// `<cmd> <args>` through `spawnSync(..., { shell: true })`, which on POSIX is a POSIX
// shell but on Windows is `cmd.exe` — and cmd.exe mis-handles the forward-slash,
// `./`-prefixed bin paths these command strings use (`'.' is not recognized …`) and the
// POSIX quoting the driver would otherwise need. The repo's primary dev platform is
// Windows, so that friction recurs locally; issue #68 adds a windows-latest CI leg.
//
// The fix is to drop `shell: true` and spawn the program + an explicit argv array. The
// command strings carry no quoted arguments with embedded spaces (verified against every caller), so a plain whitespace split is a faithful,
// shell-free tokenizer that behaves identically on every platform. The leading program
// token is normalized so a path-like bin (`./bin`, `core/go/...`) resolves on Windows:
// forward slashes → the platform separator, and a `.exe` suffix is added when a
// path-like token names a file that exists only as `<token>.exe` (Windows release bins).
// Bare commands (`cargo`, `go`, `node`) are left untouched so the OS PATH + PATHEXT
// lookup finds them (Node resolves `.exe` via PATHEXT for argv[0] without a shell).

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { sep } from "node:path";

const isWindows = process.platform === "win32";

// Split a shell-prefix string into argv tokens. The conformance command strings are
// whitespace-separated with no quoting (see header), so this is exact for our inputs and
// — crucially — identical across platforms, unlike a real shell.
function tokenize(s) {
  return s.split(/\s+/).filter(Boolean);
}

// Make a program token runnable without a shell on the current platform. A path-like
// token (one containing a separator or a leading `.`) gets its slashes normalized to the
// platform separator and, on Windows, a `.exe` suffix when only the `.exe` form exists on
// disk. A bare command name is returned unchanged for PATH resolution.
function resolveProgram(token) {
  const pathLike = token.includes("/") || token.includes("\\") || token.startsWith(".");
  if (!pathLike) return token;
  let p = isWindows ? token.replace(/\//g, sep) : token;
  if (isWindows && !p.toLowerCase().endsWith(".exe") && !existsSync(p) && existsSync(`${p}.exe`)) {
    p = `${p}.exe`;
  }
  return p;
}

// Run `<cmd-string> <args-string>` and return { status, stdout, stderr, error } exactly
// as the spawnSync result shape the driver consumes. `args` is the suffix the
// driver appends (a family name); it is tokenized the same
// way. No shell is involved, so the call is byte-for-byte portable across POSIX/Windows.
export function runCli(cmd, args = "", input = "") {
  const argv = [...tokenize(cmd), ...tokenize(args)];
  const [program, ...rest] = argv;
  const prog = resolveProgram(program);
  return spawnSync(prog, rest, { input, encoding: "utf8" });
}
