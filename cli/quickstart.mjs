// The README's quickstart, executed as written.
//
// The quickstart is the first thing an adopter copies, and for three releases it did not
// work: it wrote `keygen --out seed.hex` — a PKCS#8 PEM — and then fed that file to
// `sign --seed`, which wants 64 hex characters (issue #49). Nothing ran it, so nothing
// noticed. This runs it.
//
// It reads the ```console block that follows the `<!-- quickstart` marker in README.md and
// runs every `$ ` line, verbatim, with bash, in an empty directory, with `archon` on PATH
// resolving to the command under test. The lines under a command are what it must print on
// stdout, compared exactly, with two rules a transcript cannot avoid:
//
//   - a line `ed25519:<64 hex>` matches any key text, because keygen is random;
//   - a command whose output is `invalid` must exit 1 (that is verify's documented verdict);
//     every other command must exit 0.
//
// Used two ways:
//   import { runQuickstart } from "./quickstart.mjs"   — cli/smoke.mjs, once per lane
//   node cli/quickstart.mjs [--readme <file>] -- <archon command…>
//                                                       — against an installed CLI, e.g.
//                                                         `node cli/quickstart.mjs -- archon`
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const KEY_TEXT = /^ed25519:[0-9a-f]{64}$/;

// The commands and their expected stdout, from the marked block.
export function readQuickstart(readmePath) {
  const lines = readFileSync(readmePath, "utf8").replace(/\r\n/g, "\n").split("\n");
  const marker = lines.findIndex((l) => l.startsWith("<!-- quickstart"));
  if (marker < 0) throw new Error(`${readmePath}: no <!-- quickstart … --> marker`);
  const open = lines.findIndex((l, i) => i > marker && l.startsWith("```"));
  if (open !== marker + 1 || lines[open].trim() !== "```console") {
    throw new Error(`${readmePath}: the quickstart marker must be followed directly by a \`\`\`console block`);
  }
  const close = lines.findIndex((l, i) => i > open && l.startsWith("```"));
  const steps = [];
  for (const line of lines.slice(open + 1, close)) {
    if (line.startsWith("$ ")) steps.push({ command: line.slice(2), stdout: [] });
    else if (line.trim() !== "" && steps.length) steps[steps.length - 1].stdout.push(line);
  }
  if (!steps.length) throw new Error(`${readmePath}: the quickstart block has no $ commands`);
  return steps;
}

// Git Bash on Windows, wherever bash is on POSIX.
function bashPath() {
  if (process.platform !== "win32") return "bash";
  const git = "C:\\Program Files\\Git\\bin\\bash.exe";
  return existsSync(git) ? git : "bash";
}

const shq = (s) => `'${String(s).replace(/\\/g, "/").replace(/'/g, `'\\''`)}'`;

// Run the quickstart with `archon` = archonArgv. Returns one result per step:
// { command, ok, detail }. Never throws for a failing step — the caller reports.
export function runQuickstart(readmePath, archonArgv) {
  const steps = readQuickstart(readmePath);
  const work = mkdtempSync(join(tmpdir(), "archon-quickstart-"));
  const bin = join(work, ".bin");
  const cwd = join(work, "run");
  for (const d of [bin, cwd]) mkdirSync(d, { recursive: true });
  // A shim named `archon`, so the README's own word resolves to the command under test.
  const shim = join(bin, "archon");
  writeFileSync(shim, `#!/usr/bin/env bash\nexec ${archonArgv.map(shq).join(" ")} "$@"\n`);
  chmodSync(shim, 0o755);

  const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH ?? ""}` };
  const results = [];
  for (const step of steps) {
    const r = spawnSync(bashPath(), ["-c", `set -o pipefail\n${step.command}`], { cwd, env, encoding: "utf8" });
    const got = (r.stdout ?? "").replace(/\r\n/g, "\n").replace(/\n$/, "");
    const gotLines = got === "" ? [] : got.split("\n");
    const wantCode = step.stdout.length === 1 && step.stdout[0] === "invalid" ? 1 : 0;
    const linesOk = gotLines.length === step.stdout.length &&
      step.stdout.every((want, i) => (KEY_TEXT.test(want) ? KEY_TEXT.test(gotLines[i]) : gotLines[i] === want));
    const ok = linesOk && r.status === wantCode;
    results.push({
      command: step.command,
      ok,
      detail: ok ? "" :
        `exit ${r.status} (want ${wantCode})\n       stdout ${JSON.stringify(got)}\n       want   ${JSON.stringify(step.stdout.join("\n"))}` +
        (r.stderr ? `\n       stderr ${r.stderr.trim().split("\n").slice(0, 3).join(" | ")}` : ""),
    });
  }
  rmSync(work, { recursive: true, force: true });
  return results;
}

// Standalone: node cli/quickstart.mjs [--readme <file>] -- <archon command…>
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  let readme = join(dirname(dirname(fileURLToPath(import.meta.url))), "README.md");
  if (args[0] === "--readme") { readme = resolve(args[1]); args.splice(0, 2); }
  if (args[0] === "--") args.shift();
  if (!args.length) {
    console.error("usage: node cli/quickstart.mjs [--readme <file>] -- <archon command…>");
    process.exit(2);
  }
  let bad = 0;
  for (const r of runQuickstart(readme, args)) {
    if (r.ok) console.log(`ok   $ ${r.command}`);
    else { bad++; console.error(`FAIL $ ${r.command}\n       ${r.detail}`); }
  }
  process.exit(bad ? 1 : 0);
}
