// archon key add|list|rm|default|export — the password-protected seed store of
// ADR 0007 §A. The format lives in ../keystore.js; this file is the command: flags,
// prompts, paths, and the lines we print about what we did.
//
// Every operation that destroys, reveals or creates key material says so IN SCOPE
// (docs/keystore.md §6): archon speaks for its own store and never for anyone else's, so
// an empty result means "nothing visible here", never "nothing exists". The wording is
// pinned in cli/smoke.mjs.
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  fstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

import { encodeKey, getPublicKey, pkcs8PemToSeed, pubkeyFromHex, seedFromHex, seedToPkcs8Pem }
  from "@bitspark/archon";

import * as keystore from "../keystore.js";

export const USAGE =
  "usage: archon key <add <name> [--seed <hex>|--seed-file <file>|--pkcs8 <file>]|" +
  "list [--json]|rm <name> [--force]|default [<name>]|export <name> --reveal --out <file>>\n  " +
  "the password-protected seed store; keys live in $ARCHON_HOME/keys (default ~/.archon). " +
  "Password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv.";

// ---------------------------------------------------------------------------
// Where the store lives — docs/keystore.md §1.
// ---------------------------------------------------------------------------

const archonHome = (): string => {
  const env = process.env["ARCHON_HOME"];
  return env !== undefined && env !== "" ? env : join(homedir(), ".archon");
};

const storeDir = (): string => join(archonHome(), "keys");

function keyPath(name: string): string {
  keystore.validateName(name);
  return join(storeDir(), name);
}

/**
 * Writes atomically: a temp file in the SAME directory, then a rename, so a crash
 * mid-write can never leave a half key where a whole one was.
 */
function writeKeyFile(path: string, blob: Uint8Array): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.tmp-${process.pid}`);
  writeFileSync(tmp, blob, { mode: 0o600 });
  try {
    chmodSync(tmp, 0o600);
  } catch {
    // Windows has no mode bits; the file inherits the ACL of the user's own profile
    // directory. Failing here would be pretending 0600 was ever possible.
  }
  renameSync(tmp, path);
}

function listKeyNames(): string[] {
  try {
    return readdirSync(storeDir())
      .filter((n) => !n.startsWith(".tmp-"))
      .filter((n) => {
        try {
          return statSync(join(storeDir(), n)).isFile();
        } catch {
          return false;
        }
      })
      .sort();
  } catch {
    // A missing store directory is an empty store, not an error: nothing added yet.
    return [];
  }
}

// ---------------------------------------------------------------------------
// Passwords — docs/keystore.md §4. Never argv.
// ---------------------------------------------------------------------------

/**
 * Scans for `--password-fd <n>` and removes it. The password never travels in argv, so
 * this carries a descriptor number rather than the secret.
 */
export function takePasswordFd(args: string[]): { rest: string[]; fd: number | undefined } {
  const rest: string[] = [];
  let fd: number | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--password-fd") {
      const v = args[i + 1];
      if (v === undefined) throw new Error('flag "--password-fd" needs a value');
      const n = Number.parseInt(v, 10);
      if (!Number.isInteger(n) || n < 0) {
        throw new Error(`--password-fd: ${JSON.stringify(v)} is not a file descriptor`);
      }
      fd = n;
      i++;
      continue;
    }
    rest.push(args[i] as string);
  }
  return { rest, fd };
}

const trimNewline = (s: string): string => s.replace(/[\r\n]+$/u, "");

/**
 * What a hidden prompt needs from the terminal. Injectable so the prompt PATH can be
 * exercised by a test with no TTY — which is how the bare `require("node:fs")` this
 * function used to reach for, inside an ESM package, would have been caught: the first
 * interactive password prompt threw ReferenceError before reading a byte, and nothing ran
 * the path to notice (lane A's, found while wiring `login --key`).
 */
export interface HiddenPromptIo {
  setRawMode(raw: boolean): void;
  /** One byte, or -1 at end of input. */
  readByte(): number;
  write(text: string): void;
}

/** The real terminal. The fd read is injectable too, so the byte-reading closure — the one
 *  place this file touches fd 0 — can be exercised by a test without a TTY. */
export const terminalIo = (
  readOne: (into: Buffer) => number = (into) => readSync(0, into, 0, 1, null),
): HiddenPromptIo => {
  const chunk = Buffer.alloc(1);
  return {
    setRawMode: (raw) => {
      process.stdin.setRawMode(raw);
    },
    readByte: () => {
      let n = 0;
      try {
        n = readOne(chunk);
      } catch {
        return -1;
      }
      return n === 0 ? -1 : (chunk[0] as number);
    },
    write: (text) => {
      process.stderr.write(text);
    },
  };
};

/** A prompt that does not echo. Node has no rpassword, so raw mode is done by hand. */
export function promptHidden(label: string, io: HiddenPromptIo = terminalIo()): string {
  io.write(label);
  const wasRaw = process.stdin.isRaw === true;
  io.setRawMode(true);
  const buf: string[] = [];
  for (;;) {
    const c = io.readByte();
    if (c < 0 || c === 0x0d || c === 0x0a) break;
    if (c === 0x03) {
      io.setRawMode(wasRaw);
      io.write("\n");
      throw new Error("interrupted");
    }
    if (c === 0x7f || c === 0x08) {
      buf.pop();
      continue;
    }
    buf.push(String.fromCharCode(c));
  }
  io.setRawMode(wasRaw);
  io.write("\n");
  return buf.join("");
}

/**
 * Sources the password: --password-fd, then ARCHON_KEY_PASSWORD, then an interactive
 * prompt. `confirm` asks twice when a key is being created, where a typo would otherwise
 * be discovered only at the next unlock.
 */
export function readPassword(fd: number | undefined, confirm: boolean): string {
  if (fd !== undefined) {
    refuseLoosePasswordFile(fd);
    return trimNewline(readFileSync(fd, "utf8"));
  }
  const env = process.env["ARCHON_KEY_PASSWORD"];
  if (env !== undefined) return env;
  if (process.stdin.isTTY !== true) {
    throw new Error(
      "no password: stdin is not a terminal — set ARCHON_KEY_PASSWORD or pass --password-fd <n>",
    );
  }
  const first = promptHidden("password: ");
  if (confirm) {
    const second = promptHidden("password (again): ");
    if (first !== second) throw new Error("the two passwords differ");
  }
  return first;
}

// ---------------------------------------------------------------------------
// What the store lets another command ask of it — `login --key`'s seams.
// ---------------------------------------------------------------------------

/**
 * The store's own "is there a key called that": a validated name, then a stat — opening
 * nothing, asking for no password. Shared by `key default <name>` and by `login`'s
 * pre-network check, so both refuse a missing key with one wording.
 */
export function requireNamedKey(name: string): void {
  if (!existsSync(keyPath(name))) {
    throw new Error(`no key named ${JSON.stringify(name)} in archon's store`);
  }
}

/**
 * The ONE reader of the default pointer ($ARCHON_HOME/default), shared by `key default`
 * and by `login`'s fallback so the two can never disagree about what "the default" is.
 * Absent, unreadable, or present-but-empty all read as undefined — there is no default —
 * and the caller says what that means for it.
 */
export function readDefaultKeyName(): string | undefined {
  let raw: string;
  try {
    raw = readFileSync(join(archonHome(), "default"), "utf8");
  } catch {
    return undefined;
  }
  const name = raw.trim();
  return name === "" ? undefined : name;
}

/**
 * Opens the key called `name`: the path, the file, the password — sourced the store's one
 * way (--password-fd, then ARCHON_KEY_PASSWORD, then a prompt) — and the seal. It is the
 * ONE unlock path, shared by `key export` and `login --key`, so no two commands can ask
 * for a password differently.
 */
export function unlockNamedKey(name: string, fd: number | undefined): Uint8Array {
  const path = keyPath(name);
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(readFileSync(path));
  } catch {
    throw new Error(`no key named ${JSON.stringify(name)} in archon's store`);
  }
  return keystore.open(raw, readPassword(fd, false));
}

// ---------------------------------------------------------------------------
// The commands.
// ---------------------------------------------------------------------------

/**
 * The one place a key is written, shared by `key add` and `keygen --store` so the two
 * cannot drift apart. Salt and nonce are drawn HERE, in the command: the format takes them
 * as arguments and never sources randomness, which is what makes it pinnable.
 */
export function sealAndWrite(path: string, seed: Uint8Array, password: string): string {
  const salt = new Uint8Array(randomBytes(keystore.SALT_SIZE));
  const nonce = new Uint8Array(randomBytes(keystore.NONCE_SIZE));
  const blob = keystore.seal(seed, password, salt, nonce, keystore.defaultParams());
  writeKeyFile(path, blob);
  return encodeKey(getPublicKey(seed));
}

/** `keygen --store <name>`: the same seal path as `key add`. */
export function storeGenerated(name: string, seed: Uint8Array, fd: number | undefined): void {
  keystore.validateName(name);
  const path = keyPath(name);
  if (existsSync(path)) {
    throw new Error(
      `a key named ${JSON.stringify(name)} already exists; remove it first (archon key rm ${name})`,
    );
  }
  const password = readPassword(fd, true);
  const principal = sealAndWrite(path, seed, password);
  process.stdout.write(`generated and stored ${name} (${principal}).\n`);
}

/**
 * Accepts the two shapes ADR 0007 §A names: a 32-byte seed as 64 hex, and the first consumer's
 * ed25519.PrivateKey shape as 128 hex (seed ‖ public key). The public half is CHECKED
 * against the seed rather than trusted — a mismatch means the file is not what its owner
 * thinks it is, and storing it would carry the confusion forward.
 */
function seedFromHexish(s: string): Uint8Array {
  const t = s.trim();
  if (t.length === 64) return seedFromHex(t);
  if (t.length === 128) {
    const seed = seedFromHex(t.slice(0, 64));
    const claimed = pubkeyFromHex(t.slice(64));
    const derived = getPublicKey(seed);
    if (claimed.length !== derived.length || claimed.some((b, i) => b !== derived[i])) {
      throw new Error(
        "the public half does not match the seed: this is not a consistent private key",
      );
    }
    return seed;
  }
  throw new Error(
    `expected 64 hex characters (a seed) or 128 (seed then public key), got ${t.length}`,
  );
}

export function runAdd(args: string[]): void {
  const name = args[0];
  if (name === undefined) throw new Error(USAGE);
  keystore.validateName(name);
  const { rest, fd } = takePasswordFd(args.slice(1));

  let seedHex: string | undefined;
  let seedFile: string | undefined;
  let pkcs8File: string | undefined;
  for (let i = 0; i < rest.length; i += 2) {
    const value = rest[i + 1];
    if (value === undefined) throw new Error(`flag ${JSON.stringify(rest[i])} needs a value\n${USAGE}`);
    switch (rest[i]) {
      case "--seed": seedHex = value; break;
      case "--seed-file": seedFile = value; break;
      case "--pkcs8": pkcs8File = value; break;
      default: throw new Error(`unknown flag ${JSON.stringify(rest[i])}\n${USAGE}`);
    }
  }
  if ([seedHex, seedFile, pkcs8File].filter((v) => v !== undefined).length > 1) {
    throw new Error(`--seed, --seed-file and --pkcs8 are mutually exclusive\n${USAGE}`);
  }

  const path = keyPath(name);
  // Refused BEFORE a password is asked for: a key is never silently replaced, and there is
  // no reason to make someone type a password to find that out.
  if (existsSync(path)) {
    throw new Error(
      `a key named ${JSON.stringify(name)} already exists; remove it first (archon key rm ${name})`,
    );
  }

  let seed: Uint8Array;
  let from: string | undefined;
  if (seedHex !== undefined) {
    seed = seedFromHexish(seedHex);
    from = "--seed";
  } else if (seedFile !== undefined) {
    seed = seedFromHexish(readFileSync(seedFile, "utf8"));
    from = seedFile;
  } else if (pkcs8File !== undefined) {
    seed = pkcs8PemToSeed(readFileSync(pkcs8File, "utf8"));
    from = pkcs8File;
  } else {
    seed = new Uint8Array(randomBytes(keystore.SEED_SIZE));
  }

  const password = readPassword(fd, true);
  const principal = sealAndWrite(path, seed, password);
  if (from === undefined) {
    process.stdout.write(`generated and stored ${name} (${principal}).\n`);
  } else {
    process.stdout.write(
      `stored ${name} (${principal}) from ${from}; the source file is untouched.\n`,
    );
  }
}

/**
 * Prints what each header CLAIMS. The claim is only proven at unlock, which is why this
 * never opens a key and never asks for a password.
 */
export function runList(args: string[]): void {
  let asJson = false;
  for (const a of args) {
    if (a !== "--json") throw new Error(`unknown flag ${JSON.stringify(a)}\n${USAGE}`);
    asJson = true;
  }
  const rows: { name: string; principal: string }[] = [];
  for (const name of listKeyNames()) {
    try {
      const raw = new Uint8Array(readFileSync(keyPath(name)));
      // The magic is what keeps a stray file out of this list.
      const h = keystore.parseHeader(raw);
      rows.push({ name, principal: encodeKey(h.publicKey) });
    } catch {
      continue;
    }
  }
  if (asJson) {
    process.stdout.write(`${JSON.stringify(rows)}\n`);
    return;
  }
  for (const r of rows) process.stdout.write(`${r.name}\t${r.principal}\n`);
}

/**
 * Removes a key and says exactly what it removed, from where, and what it does NOT speak
 * for. An unparsable file is refused unless --force: deleting an unrecognised file inside
 * the store silently is what this rule exists to prevent.
 */
export function runRm(args: string[]): void {
  const name = args[0];
  if (name === undefined) throw new Error(USAGE);
  let force = false;
  for (const a of args.slice(1)) {
    if (a !== "--force") throw new Error(`unknown flag ${JSON.stringify(a)}\n${USAGE}`);
    force = true;
  }
  const path = keyPath(name);
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(readFileSync(path));
  } catch {
    throw new Error(`no key named ${JSON.stringify(name)} in archon's store`);
  }
  let header: keystore.KeyHeader | undefined;
  let why = "";
  try {
    header = keystore.parseHeader(raw);
  } catch (e) {
    why = e instanceof Error ? e.message : String(e);
    if (!force) throw new Error(`not an archon key file: ${path}: ${why}`);
  }
  unlinkSync(path);
  const what = header === undefined ? `unreadable header: ${why}` : encodeKey(header.publicKey);
  process.stdout.write(
    `removed ${name} (${what}) from archon's store at ${path}; ` +
      "any copy of this key outside it is untouched.\n",
  );
}

/**
 * Sets or shows the default key. Selection is by NAME, never by principal text
 * (ADR 0007 §A). The pointer lives beside keys/, not in it, so it can never collide with
 * a key name.
 */
export function runDefault(args: string[]): void {
  const pointer = join(archonHome(), "default");
  if (args.length === 0) {
    const name = readDefaultKeyName();
    if (name === undefined) throw new Error("no default key is set");
    process.stdout.write(`${name}\n`);
    return;
  }
  if (args.length !== 1) throw new Error(USAGE);
  const name = args[0] as string;
  requireNamedKey(name);
  mkdirSync(dirname(pointer), { recursive: true, mode: 0o700 });
  writeFileSync(pointer, `${name}\n`, { mode: 0o600 });
  process.stdout.write(`default key is now ${name}.\n`);
}

/**
 * Writes the seed out. Refuses without --reveal, and refuses stdout unless `--out -` says
 * so: a seed should never land in a pipe by accident.
 */
export function runExport(args: string[]): void {
  const name = args[0];
  if (name === undefined) throw new Error(USAGE);
  const { rest, fd } = takePasswordFd(args.slice(1));
  let reveal = false;
  let out = "";
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--reveal") {
      reveal = true;
      continue;
    }
    if (rest[i] === "--out") {
      const v = rest[i + 1];
      if (v === undefined) throw new Error(`flag "--out" needs a value\n${USAGE}`);
      out = v;
      i++;
      continue;
    }
    throw new Error(`unknown flag ${JSON.stringify(rest[i])}\n${USAGE}`);
  }
  if (!reveal) throw new Error("refusing to export a seed without --reveal");
  if (out === "") {
    throw new Error("refusing to write a seed to stdout: pass --out <file>, or --out - to mean it");
  }
  const seed = unlockNamedKey(name, fd);
  const pem = seedToPkcs8Pem(seed);
  if (out === "-") {
    process.stdout.write(pem);
    process.stderr.write(`wrote the seed of ${name} to stdout; the store's copy remains.\n`);
    return;
  }
  writeFileSync(out, pem, { mode: 0o600 });
  process.stdout.write(`wrote the seed of ${name} to ${out}; the store's copy remains.\n`);
}

/**
 * Refuses a password file that anyone but its owner can read (ADR 0007 §A). Only a REGULAR
 * file is checked: a pipe, a terminal or a process substitution has no meaningful mode, and
 * `--password-fd 0` fed by a heredoc is a pipe, so checking those would refuse the ordinary
 * non-interactive case for nothing.
 *
 * Windows has no mode bits and Node reports a synthetic 0666, so there is nothing to check
 * and nothing is claimed — the same honesty the store keeps about 0600 elsewhere.
 */
function refuseLoosePasswordFile(fd: number): void {
  if (process.platform === "win32") return;
  let st;
  try {
    st = fstatSync(fd);
  } catch {
    // Undecidable, so this refuses nothing rather than guessing; the read below will
    // produce the real error if the descriptor is unusable.
    return;
  }
  if (!st.isFile()) return;
  const perm = st.mode & 0o777;
  if ((perm & 0o077) !== 0) {
    throw new Error(
      `--password-fd: the password file is readable by others (mode ${perm.toString(8).padStart(4, "0")}); chmod 600 it`,
    );
  }
}
