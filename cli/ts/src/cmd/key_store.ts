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
  closeSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { ReadStream } from "node:tty";

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

/** A terminal's prompt operations over injectable primitives, so the byte-reading closure can
 *  be exercised by a test without a TTY. */
export const terminalIo = (
  readOne: (into: Buffer) => number,
  setRaw: (raw: boolean) => void = () => {},
  writeOut: (text: string) => void = () => {},
): HiddenPromptIo => {
  const chunk = Buffer.alloc(1);
  return {
    setRawMode: setRaw,
    readByte: () => {
      let n = 0;
      try {
        n = readOne(chunk);
      } catch {
        return -1;
      }
      return n === 0 ? -1 : (chunk[0] as number);
    },
    write: writeOut,
  };
};

export const NO_TERMINAL =
  "no password: there is no terminal to prompt on — set ARCHON_KEY_PASSWORD or pass --password-fd <n>";

/** The controlling terminal, opened for one prompt and closed after it. */
export interface ControllingTerminal {
  io: HiddenPromptIo;
  close(): void;
}

/**
 * Opens the CONTROLLING TERMINAL — `/dev/tty`, or the Windows console — rather than reading
 * the prompt from fd 0 (ADR 0009 §5). stdin may be carrying the very message being signed,
 * and a password read from it would take that message's bytes for a password; a tool that
 * runs `archon` with a pipe on stdin still leaves the person's terminal reachable here. The
 * Windows devices are spelled in the `\\.\` namespace: Node prefixes plain paths with `\\?\`,
 * which turns `CONIN$` into a file name.
 */
export function openControllingTerminal(): ControllingTerminal {
  const windows = process.platform === "win32";
  const input = windows ? "\\\\.\\CONIN$" : "/dev/tty";
  const opened: number[] = [];
  const open = (path: string, flags: string): number => {
    const fd = openSync(path, flags);
    opened.push(fd);
    return fd;
  };
  let readFd: number;
  let modeFd: number;
  let outFd: number;
  try {
    // TWO descriptors on the same terminal. Node's ReadStream exists here only to switch raw
    // mode, and building one puts ITS descriptor in non-blocking mode (libuv's tty init), where
    // a synchronous read gets EAGAIN at once and the prompt would read an empty password. The
    // mode belongs to the terminal, not the descriptor, so it is set through one and the bytes
    // are read, blocking, through the other.
    readFd = open(input, "r+");
    modeFd = open(input, "r+");
    outFd = windows ? open("\\\\.\\CONOUT$", "w") : readFd;
  } catch {
    for (const fd of opened) closeSync(fd);
    throw new Error(NO_TERMINAL);
  }
  // The stream never runs on the event loop: every byte is read synchronously from readFd.
  // Destroying it closes modeFd.
  const stream = new ReadStream(modeFd);
  return {
    io: terminalIo(
      (into) => readSync(readFd, into, 0, 1, null),
      (raw) => {
        stream.setRawMode(raw);
      },
      (text) => {
        writeSync(outFd, text);
      },
    ),
    close: () => {
      stream.destroy();
      closeSync(readFd);
      if (outFd !== readFd) closeSync(outFd);
    },
  };
}

const utf8Strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** A prompt that does not echo. Node has no rpassword, so raw mode is done by hand. The
 *  terminal is the prompt's own, opened in cooked mode, so cooked is what it is left in.
 *
 *  It collects BYTES and decodes them as UTF-8 once, at the end: a terminal sends a
 *  non-ASCII character as several bytes, and the password is the characters (docs/keystore.md
 *  §3: UTF-8, then NFC), which is what the Go and Rust prompts read. Before 0.11.0 this
 *  prompt turned each byte into its own character, so a non-ASCII password derived a key no
 *  other lane derives; `openEntered` still opens keys sealed that way, and re-seals them. */
export function promptHidden(label: string, io: HiddenPromptIo): string {
  io.write(label);
  const wasRaw = false;
  io.setRawMode(true);
  const bytes: number[] = [];
  for (;;) {
    const c = io.readByte();
    if (c < 0 || c === 0x0d || c === 0x0a) break;
    if (c === 0x03) {
      io.setRawMode(wasRaw);
      io.write("\n");
      throw new Error("interrupted");
    }
    if (c === 0x7f || c === 0x08) {
      // Backspace erases one CHARACTER: its UTF-8 continuation bytes, then its first byte.
      for (;;) {
        const last = bytes[bytes.length - 1];
        if (last === undefined || (last & 0xc0) !== 0x80) break;
        bytes.pop();
      }
      bytes.pop();
      continue;
    }
    bytes.push(c);
  }
  io.setRawMode(wasRaw);
  io.write("\n");
  try {
    return utf8Strict.decode(new Uint8Array(bytes));
  } catch {
    throw new Error("the password is not valid UTF-8; set the terminal's encoding to UTF-8");
  }
}

/** One visible line from the controlling terminal, in cooked mode: `key policy`'s and `enroll`'s y/N. */
export function readTerminalLine(terminal: ControllingTerminal): string {
  const bytes: number[] = [];
  for (;;) {
    const c = terminal.io.readByte();
    if (c < 0 || c === 0x0a) break;
    if (c !== 0x0d) bytes.push(c);
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/** What the prompt before 0.11.0 made of the same keystrokes: each UTF-8 byte of `password`
 *  as a character of its own. undefined for an ASCII password, where both readings agree. */
export function legacyPromptDecoding(password: string): string | undefined {
  const bytes = new TextEncoder().encode(password);
  if (bytes.every((b) => b < 0x80)) return undefined;
  return String.fromCharCode(...bytes);
}

/**
 * Sources the password: --password-fd, then ARCHON_KEY_PASSWORD, then an interactive
 * prompt on the controlling terminal — never fd 0. `confirm` asks twice when a key is being
 * created, where a typo would otherwise be discovered only at the next unlock. `preamble` is
 * shown on that terminal before the prompt, and only when there is a prompt.
 */
export function readPassword(fd: number | undefined, confirm: boolean, preamble = ""): string {
  return readPasswordEntry(fd, confirm, preamble).password;
}

/** A password, and whether it was typed at the prompt: only the prompt ever misread one. */
export interface PasswordEntry {
  password: string;
  prompted: boolean;
}

/** `readPassword`, also saying where the password came from, for `openEntered`. */
export function readPasswordEntry(fd: number | undefined, confirm: boolean, preamble = ""): PasswordEntry {
  if (fd !== undefined) {
    refuseLoosePasswordFile(fd);
    return { password: trimNewline(readFileSync(fd, "utf8")), prompted: false };
  }
  const env = process.env["ARCHON_KEY_PASSWORD"];
  if (env !== undefined) return { password: env, prompted: false };
  const terminal = openControllingTerminal();
  try {
    if (preamble !== "") terminal.io.write(preamble);
    const first = promptHidden("password: ", terminal.io);
    if (confirm) {
      const second = promptHidden("password (again): ", terminal.io);
      if (first !== second) throw new Error("the two passwords differ");
    }
    return { password: first, prompted: true };
  } finally {
    terminal.close();
  }
}

/**
 * Opens the sealed key `name` with an entered password. A key sealed through the prompt
 * before 0.11.0 under a non-ASCII password opens only under that prompt's byte-by-byte
 * reading (`legacyPromptDecoding`), and in no other lane. So when a PROMPTED password fails
 * and its old reading opens the key, the key is re-sealed under the password as typed —
 * once, and saying so — after which every lane opens it. Any other failure is the first one.
 */
export function openEntered(name: string, file: Uint8Array, entry: PasswordEntry): Uint8Array {
  try {
    return keystore.open(file, entry.password);
  } catch (first) {
    const legacy = entry.prompted ? legacyPromptDecoding(entry.password) : undefined;
    if (legacy === undefined) throw first;
    // The re-seal keeps the entry's own policy (docs/keystore.md §8.3: nothing else changes a
    // policy). A version-1 file has none and is never converted as a side effect: that is
    // `key policy`'s, explicitly.
    const policy = keystore.parseHeader(file).policy;
    if (policy === null) throw first;
    let seed: Uint8Array;
    try {
      seed = keystore.open(file, legacy);
    } catch {
      throw first;
    }
    sealAndWrite(keyPath(name), seed, entry.password, policy);
    process.stderr.write(
      `re-sealed key ${name}: archon's TS prompt before 0.11.0 misread its non-ASCII password; ` +
        "it is now sealed under the password as typed, which every lane reads the same way\n",
    );
    return seed;
  }
}

// ---------------------------------------------------------------------------
// What the store lets another command ask of it — `login --key`'s seams.
// ---------------------------------------------------------------------------

/**
 * The store's own "is there a key called that, and can it be used": a validated name and a
 * header read — opening nothing, asking for no password. Shared by `key default <name>` and by
 * `login`'s pre-network check, so both refuse a missing, unreadable or version-1 key with one
 * wording (docs/keystore.md §8.2).
 */
export function requireNamedKey(name: string): keystore.KeyHeader {
  return usableKey(name).header;
}

/** A refusal of a named entry with its machine-mode category (§8.2). */
export class StoreRefusal extends Error {
  constructor(readonly category: string, message: string) {
    super(message);
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
  const { file } = usableKey(name);
  return openEntered(name, file, readPasswordEntry(fd, false));
}

/**
 * A stored key's file and its header as the header CLAIMS it — public key, version, policy —
 * opening nothing and asking for no password. The claim is what `sign --key --expect` checks
 * before the prompt; it is proven only when the seal opens, because `keystore.open` verifies the
 * tag over the header and refuses a seed that does not derive the public key.
 *
 * Every refusal is a StoreRefusal: no-key when no file has that name, else the header's kind.
 */
export function readNamedKey(name: string): { file: Uint8Array; header: keystore.KeyHeader } {
  let path: string;
  try {
    path = keyPath(name);
  } catch (e) {
    throw new StoreRefusal("no-key", e instanceof Error ? e.message : String(e));
  }
  let file: Uint8Array;
  try {
    file = new Uint8Array(readFileSync(path));
  } catch {
    throw new StoreRefusal("no-key", `no key named ${JSON.stringify(name)} in archon's store`);
  }
  try {
    return { file, header: keystore.parseHeader(file) };
  } catch (e) {
    const kind = e instanceof keystore.FormatError ? e.kind : "malformed";
    throw new StoreRefusal(kind, `${name}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * readNamedKey for a command that will sign, log in, export or make a key the default: only a
 * version-2 entry may (§8.2). A version-1 entry is refused with the command that converts it,
 * named in full, so a person can act on the line they read.
 */
export function usableKey(name: string): { file: Uint8Array; header: keystore.KeyHeader } {
  const read = readNamedKey(name);
  if (read.header.version !== keystore.VERSION_2) {
    throw new StoreRefusal(
      "migration-required",
      `${name} is a version-1 key file, which this archon no longer uses: convert it once with ` +
        `\`archon key policy ${name} --allow <context>\` (repeatable), or \`--unrestricted\``,
    );
  }
  return read;
}

/**
 * Removes --allow <context> (repeatable) and --unrestricted from args and returns the policy
 * they name (docs/keystore.md §8.3). There is no default: undefined when neither appears, and
 * the caller decides whether that is allowed.
 */
export function takePolicyFlags(args: string[]): { rest: string[]; policy: keystore.Policy | undefined } {
  const rest: string[] = [];
  const allow: string[] = [];
  let unrestricted = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a === "--allow") {
      const c = args[i + 1];
      if (c === undefined) throw new Error("--allow needs a context");
      allow.push(c);
      i++;
    } else if (a === "--unrestricted") {
      unrestricted = true;
    } else {
      rest.push(a);
    }
  }
  if (unrestricted && allow.length > 0) throw new Error("--allow and --unrestricted are mutually exclusive");
  if (unrestricted) return { rest, policy: keystore.unrestricted() };
  if (allow.length === 0) return { rest, policy: undefined };
  try {
    return { rest, policy: keystore.allowlist(allow) };
  } catch (e) {
    throw new Error(`--allow: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** The refusal for a new key that names no policy: there is no default. */
export const policyNeeded = (name: string): Error =>
  new Error(`say which contexts ${name} may sign in: --allow <context> (repeatable), or --unrestricted`);

// ---------------------------------------------------------------------------
// The commands.
// ---------------------------------------------------------------------------

/**
 * The one place a key is written, shared by `key add` and `keygen --store` so the two
 * cannot drift apart. Salt and nonce are drawn HERE, in the command: the format takes them
 * as arguments and never sources randomness, which is what makes it pinnable.
 */
export function sealAndWrite(path: string, seed: Uint8Array, password: string, policy: keystore.Policy): string {
  const salt = new Uint8Array(randomBytes(keystore.SALT_SIZE));
  const nonce = new Uint8Array(randomBytes(keystore.NONCE_SIZE));
  const blob = keystore.seal(seed, password, salt, nonce, keystore.defaultParams(), policy);
  writeKeyFile(path, blob);
  return encodeKey(getPublicKey(seed));
}

/** `keygen --store <name>`: the same seal path as `key add`. */
export function storeGenerated(name: string, seed: Uint8Array, fd: number | undefined, policy: keystore.Policy): void {
  keystore.validateName(name);
  const path = keyPath(name);
  if (existsSync(path)) {
    throw new Error(
      `a key named ${JSON.stringify(name)} already exists; remove it first (archon key rm ${name})`,
    );
  }
  const password = readPassword(fd, true);
  const principal = sealAndWrite(path, seed, password, policy);
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
  const { rest: afterFd, fd } = takePasswordFd(args.slice(1));
  const { rest, policy } = takePolicyFlags(afterFd);
  if (policy === undefined) throw policyNeeded(name);

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
  const principal = sealAndWrite(path, seed, password, policy);
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
  // A row for every entry whose principal can be read (docs/keystore.md §8.4), so an entry
  // awaiting conversion is reported as that and not as absent. The policy is the header's
  // CLAIM, read without the password, and named as such. An entry whose principal cannot be
  // read is named on stderr, one line each, so a key never vanishes without a word.
  const rows: { name: string; principal: string; status: string; claimed_policy: unknown; text: string }[] = [];
  for (const name of listKeyNames()) {
    let h: keystore.KeyHeader;
    try {
      // The magic is what keeps a stray file out of this list.
      h = readNamedKey(name).header;
    } catch (e) {
      process.stderr.write(`archon key list: skipped ${name}: ${e instanceof Error ? e.message : String(e)}\n`);
      continue;
    }
    const principal = encodeKey(h.publicKey);
    if (h.version === keystore.VERSION_2 && h.policy !== null) {
      const claimed = h.policy.unrestricted
        ? { mode: "unrestricted" }
        : h.policy.contexts.length === 0
          ? { mode: "allowlist" }
          : { mode: "allowlist", contexts: h.policy.contexts };
      rows.push({ name, principal, status: "usable", claimed_policy: claimed, text: keystore.describePolicy(h.policy) });
    } else {
      rows.push({
        name,
        principal,
        status: "migration-required",
        claimed_policy: null,
        text: `version 1: convert with \`archon key policy ${name}\``,
      });
    }
  }
  if (asJson) {
    const out = rows.map(({ name, principal, status, claimed_policy }) => ({ name, principal, status, claimed_policy }));
    process.stdout.write(`${JSON.stringify(out)}\n`);
    return;
  }
  for (const r of rows) process.stdout.write(`${r.name}\t${r.principal}\t${r.text}\n`);
}

/**
 * Shows an entry's policy, or converts a version-1 entry or changes a version-2 one
 * (docs/keystore.md §8.3). The change form is ALWAYS interactive: it shows the old and the new
 * policy before asking for anything, asks y/N at the controlling terminal, and takes the
 * password from that terminal only — no --yes, no ARCHON_KEY_PASSWORD, no --password-fd. That
 * is a safeguard against a password a program inherited, not an authorization claim (ADR 0012
 * §6): whoever can type the password can also decrypt the file.
 */
export function runPolicy(args: string[]): void {
  const name = args[0];
  if (name === undefined) throw new Error(USAGE);
  const { rest, policy } = takePolicyFlags(args.slice(1));
  if (rest.length > 0) throw new Error(`unknown flag ${JSON.stringify(rest[0])}\n${USAGE}`);
  const path = keyPath(name);
  // One read: the bytes shown are the bytes unlocked and replaced (ADR 0012 §4).
  const { file, header } = readNamedKey(name);
  const principal = encodeKey(header.publicKey);
  const current =
    header.version === keystore.VERSION_2 && header.policy !== null
      ? keystore.describePolicy(header.policy)
      : "version 1, no policy";
  if (policy === undefined) {
    process.stdout.write(`${name} (${principal}): ${current} (claimed by the header; proven only at unlock)\n`);
    return;
  }
  let terminal: ControllingTerminal;
  try {
    terminal = openControllingTerminal();
  } catch {
    throw new Error(
      "changing a key's policy needs a person at the controlling terminal: there is none, and " +
        "ARCHON_KEY_PASSWORD and --password-fd are not accepted here",
    );
  }
  let blob: Uint8Array;
  try {
    terminal.io.write(
      `${name} (${principal})\n  policy:  ${current}\n  becomes: ${keystore.describePolicy(policy)}\nchange it? [y/N] `,
    );
    const answer = readTerminalLine(terminal).trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") throw new Error("not changed");
    const password = promptHidden("password: ", terminal.io);
    // A key sealed through this lane's prompt before 0.11.0 opens only under the old reading
    // of its password; it is re-sealed under the password as typed (openEntered's rule).
    let seed: Uint8Array;
    try {
      seed = keystore.open(file, password);
    } catch (first) {
      const legacy = legacyPromptDecoding(password);
      if (legacy === undefined) throw first;
      try {
        seed = keystore.open(file, legacy);
      } catch {
        throw first;
      }
    }
    try {
      blob = keystore.seal(
        seed,
        password,
        header.salt,
        new Uint8Array(randomBytes(keystore.NONCE_SIZE)),
        header.params,
        policy,
      );
    } finally {
      seed.fill(0);
    }
  } finally {
    terminal.close();
  }
  writeKeyFile(path, blob);
  process.stdout.write(
    `changed the policy of ${name} (${principal}) to ${keystore.describePolicy(policy)}; ` +
      "any copy of this key outside archon's store is untouched.\n",
  );
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
  // An allowlisted entry's seed is not written out (§8.2): its policy would not travel with it.
  // A backup is the encrypted file itself. Refused from the header, before the password.
  const policy = usableKey(name).header.policy;
  if (policy === null || !policy.unrestricted) {
    throw new Error(
      `refusing to export ${name}: its policy allows only listed contexts (${keystore.describePolicy(policy)}), ` +
        "and a plaintext seed would carry none of it; back up the encrypted file instead",
    );
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
