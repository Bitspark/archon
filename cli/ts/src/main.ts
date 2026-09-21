#!/usr/bin/env node
// archon — the human-facing CLI for the TS lane. A thin presentation + I/O layer over the
// public @bitspark/archon API. The shape is fixed: `archon <subcommand> [args]`. Each
// subcommand lives in its own cmd/*.ts behind a single run(args); this dispatch only
// routes the name. Results go to stdout; diagnostics, usage, and the keygen secret
// warning go to stderr; any error exits non-zero. Three native binaries (cli/rs, cli/go,
// cli/ts) build the SAME `archon` command with byte-identical stdout (cli/smoke.mjs).
//
// `key` and `keygen` were carved out of thesmos's CLI on 2026-09-09 (docs/growth-plan.md
// §8.2). `sign` and `verify` are new: raw bytes, domain-aware.
import { run as key } from "./cmd/key.js";
import { run as login } from "./cmd/login.js";
import { run as keygen } from "./cmd/keygen.js";
import { run as sign } from "./cmd/sign.js";
import { run as verify } from "./cmd/verify.js";
import { run as version, versionLine } from "./cmd/version.js";
import { Verdict } from "./io.js";

const USAGE = "usage: archon <keygen|key|login|sign|verify|version> [args]";

// login is async (it makes HTTP requests), so a handler may return a promise and this
// dispatch awaits it. Without the await, a rejected promise would escape the try/catch
// below and Node would report an unhandled rejection instead of `archon login: <reason>`.
const dispatch: Record<string, (args: string[]) => void | Promise<void>> = { keygen, key, login, sign, verify, version };

const [command, ...rest] = process.argv.slice(2);
if (command === undefined) {
  process.stderr.write(`${USAGE}\n`);
  process.exit(2);
}
if (command === "--help" || command === "-h") {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}
if (command === "--version") {
  process.stdout.write(`${versionLine()}\n`);
  process.exit(0);
}
const handler = dispatch[command];
if (handler === undefined) {
  process.stderr.write(`archon: unknown subcommand ${JSON.stringify(command)}\n${USAGE}\n`);
  process.exit(2);
}
try {
  await handler(rest);
} catch (err) {
  // A verdict (`invalid`) is already on stdout: exit 1 with nothing on stderr.
  if (!(err instanceof Verdict)) {
    process.stderr.write(`archon ${command}: ${err instanceof Error ? err.message : String(err)}\n`);
  }
  process.exit(1);
}
