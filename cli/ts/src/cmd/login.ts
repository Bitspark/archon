// archon login — prove possession of your key to a service, so a browser key it names may
// act for you within a scope you are shown BEFORE signing.
//
//   archon login <url> [--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>]
//                      [--authority-file <file>] [--yes]
//   archon login --audience <base> [--scope <entry>]... --valid-for <seconds> [custody] [--authority-file <file>]
//
// This module owns the TRANSPORT (HTTP/JSON), the DISPLAY (the statement the person
// confirms), and the FLOW. It owns NO scheme: the binding layout and the proof are
// sdk/ts/login's (archon#16, seat:cca authorship comment 2026-09-10T13:01Z), reached
// through the single seam proveLogin below. Nothing here computes signed bytes — a binding
// written twice is a binding that drifts.
//
// TWO FORMS, one command. With a URL (docs/login.md §4) the page started and the person
// finishes here: the audience is DERIVED FROM THE INVOCATION URL, never read from the wire
// (archon#16 Finding 1: a server that may name its own audience can name someone else's),
// the statement is shown, and nothing is signed until the person says yes. With no URL
// (§4.1, the offers form) the CLI starts and the page finishes: the audience is the CLI's
// OWN configuration, the CLI offers exactly what was typed, answers only the request that
// took its offer, asks no confirmation, and prints the ledger of that decision afterwards.
//
// HTTP is the platform's `fetch` (Node 18+), so this lane adds no dependency at all.
import { createInterface } from "node:readline";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import { encodeKey, decodeKey, getPublicKey } from "@bitspark/archon";
// Aliased on import: the scheme exports its own `LoginRequest` (bytes, camelCase) and its
// own `proveLogin`. Those are the SCHEME's types; the ones in this file are the WIRE's
// (strings, snake_case, straight off the JSON). Keeping both names visible and distinct is
// the point — converting between them is this seam's entire job.
import {
  MIN_NONCE_SIZE as SCHEME_MIN_NONCE_SIZE,
  deriveAudience,
  proveLogin as schemeProveLogin,
  type LoginRequest as SchemeRequest,
} from "@bitspark/archon-sdk";

import { resolveSeed, wantsHelp } from "../io.js";
import * as store from "./key_store.js";

const USAGE =
  "usage: archon login <url> [--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] " +
  "[--authority-file <file>] [--yes]\n" +
  "       archon login --audience <base> [--scope <entry>]... --valid-for <seconds> " +
  "[--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] [--authority-file <file>]\n  " +
  "proves possession of your key to the service at <url> so the browser key it names may act for you. " +
  "<url> is the invocation URL <audience>/login/<id>; the audience is derived from it, never taken from the server. " +
  "--key names a key in the store and is the default (archon key default); --key-file is a PKCS#8 file. " +
  "Store password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv.\n  " +
  "with no URL, the CLI OFFERS what you typed and the page finishes: the audience is --audience or ARCHON_AUDIENCE, " +
  "never a page's word; the code and the page address go to stderr, the ledger to stdout after the service answers; " +
  "no confirmation is asked — what you typed is what you sign.";

/** Where the offers form writes its interactive lines and how it waits, injected so a test can
 *  pin the code and the page mark on stderr, the pacing, and the ledger's wall-clock end —
 *  without sleeping through the pacing or patching process streams. `run` hands the real ones. */
export interface LoginIo {
  writeErr: (text: string) => void;
  sleep: (seconds: number) => Promise<void>;
  /** Seconds since the Unix epoch. */
  now: () => number;
}

const realIo: LoginIo = {
  writeErr: (text) => {
    process.stderr.write(text);
  },
  sleep: (seconds) => new Promise((resolve) => setTimeout(resolve, seconds * 1000)),
  now: () => Math.floor(Date.now() / 1000),
};

// The signing domain (archon-login/1) is deliberately NOT declared here. It is the
// scheme's, applied inside sdk/ts/login, and a copy in the CLI would be a second place it
// could drift from.

/** The SCHEME's floor, cited rather than restated: the sdk's MIN_NONCE_SIZE is where it is
 *  decided, and a local 16 would be a second place it could move from. It is checked HERE,
 *  and not only at signing time, because a short nonce must be refused before the person is
 *  asked to confirm — the check's POSITION is this lane's, its VALUE is not. */
const MIN_NONCE_SIZE = SCHEME_MIN_NONCE_SIZE;

/** Stands in the scope position when the request delegates nothing. */
const NO_SCOPE_LINE = "(no scope entries — the service asks only for proof of your key)";

/** What the service answers on GET <audience>/login/<id>.
 *
 *  NOTE the absent field: there is no `audience` here, by design (Finding 1). */
export interface LoginRequest {
  id: string;
  /** hex */
  nonce: string;
  /** canonical key text, ed25519:<hex> */
  browser: string;
  /** ordered, verbatim, displayed to the person */
  scope: string[];
  /** seconds */
  valid_for: number;
  /** RFC 3339; when the REQUEST dies, not the delegation */
  expires?: string;
}

/** What we POST to <audience>/login/<id>/answer. */
export interface LoginAnswer {
  principal: string;
  possession: string;
  authority: string;
}

/** The fields this lane understands. A service sending anything else — an `audience` above
 *  all — is speaking a protocol we do not, and is refused rather than half-read. */
const KNOWN_REQUEST_FIELDS = new Set(["id", "nonce", "browser", "scope", "valid_for", "expires"]);

/** WHICH custody will sign. Decided at flag-parse time — before the audience is derived —
 *  so the statement can name it and a bad choice is refused before anything is fetched or
 *  shown. */
export interface LoginSource {
  seedHex?: string;
  keyFile?: string;
  seedFile?: string;
  /** A NAME in the store, never a principal (ADR 0007 §A). Set by --key, or by the store's
   *  default pointer when no source flag was given. */
  storeKey?: string;
}

/** Settles the source: exactly one flag, or none and the store's default. It never guesses
 *  a seed file — the only fallback is the pointer the person set with `archon key default`.
 *  A named store key is checked to EXIST here (a stat, opening nothing), so a typo is
 *  refused before a pointless fetch; the password and the unlock still wait for consent. */
export function decideLoginSource(src: LoginSource): void {
  const given = [src.seedHex, src.keyFile, src.seedFile, src.storeKey].filter((v) => v !== undefined).length;
  if (given > 1) throw new Error(`--key, --seed, --key-file and --seed-file are mutually exclusive\n${USAGE}`);
  if (given === 0) {
    const name = store.readDefaultKeyName();
    if (name === undefined) {
      throw new Error(
        "no default key is set\n  pass --key <name>, --seed <hex>, --key-file <file> or --seed-file <file>, " +
          "or choose one with: archon key default <name>",
      );
    }
    src.storeKey = name;
  }
  if (src.storeKey !== undefined) store.requireNamedKey(src.storeKey);
}

/** Entry point. The order is the security order and is not an accident: derive the
 *  audience, fetch, validate, SHOW, confirm, only then unlock and sign.
 *
 *  Everything decidable WITHOUT the network — which custody signs, whether the flags agree,
 *  whether a named store key exists, whether the authority file is readable — is decided
 *  first, so those refusals land before a request is made and before the person reads a
 *  statement they could not have signed.
 *
 *  `write` is where the statement and the outcome go — stdout by default, and injectable so
 *  a test can pin what a person would have seen WITHOUT patching process.stdout.write. Under
 *  `node --test` the test file is a child that reports to the runner over its own stdout, so
 *  a patch there swallows the report and silently drops tests from the run. */
export async function run(
  args: string[],
  write: (text: string) => void = (text) => {
    process.stdout.write(text);
  },
  io: LoginIo = realIo,
): Promise<void> {
  if (wantsHelp(args)) {
    write(`${USAGE}\n`);
    return;
  }
  const rawUrl = args[0];
  if (rawUrl === undefined) throw new Error(USAGE);
  // No URL: the offers form (docs/login.md §4.1). The CLI starts, the page finishes.
  if (rawUrl.startsWith("--")) return runOffer(args, write, io);

  // The password descriptor is the STORE's flag, taken out first exactly as `key add` does,
  // so login sources a password the one way the store does.
  const { rest, fd } = store.takePasswordFd(args.slice(1));
  const src: LoginSource = {};
  let authorityFile: string | undefined;
  let assumeYes = false;
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i]!;
    if (flag === "--yes") {
      assumeYes = true;
      continue;
    }
    const value = rest[i + 1];
    if (value === undefined || value === "") throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    i++;
    switch (flag) {
      case "--key": src.storeKey = value; break;
      case "--seed": src.seedHex = value; break;
      case "--key-file": src.keyFile = value; break;
      case "--seed-file": src.seedFile = value; break;
      case "--authority-file": authorityFile = value; break;
      default: throw new Error(`unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
    }
  }
  decideLoginSource(src);
  // --password-fd belongs to the store. Beside a seed file it would be silently ignored, and
  // a flag that does nothing is a flag someone will come to rely on.
  if (fd !== undefined && src.storeKey === undefined) {
    throw new Error(`--password-fd applies only to a store key (--key, or the default)\n${USAGE}`);
  }
  // `confirm` reads stdin, so a password on fd 0 would be read by the prompt first. The
  // store's own commands never confirm; this is the one place the two meet.
  if (fd === 0 && !assumeYes) {
    throw new Error("--password-fd 0 puts the password on stdin, which the sign? prompt reads first; pass --yes with it");
  }
  // Read here, not after consent: a missing authority file is refused before the person has
  // read a statement and said yes to it. The payload stays opaque (see readAuthority).
  const authority = readAuthority(authorityFile);

  // THE DERIVATION IS THE SCHEME'S (docs/login.md §2.1, sdk/ts/login). It used to live in
  // this file, in three lanes, and the three disagreed: net/url decoded the path and kept a
  // default port, this lane's WHATWG URL dropped the port, a hand-rolled split kept
  // userinfo. The audience is the FIRST FIELD OF THE BINDING, so one URL must yield one
  // audience everywhere — which makes it the scheme's job and not a CLI's. The WHATWG URL is
  // gone from this file with it.
  const { audience, id: idBytes } = deriveAudience(rawUrl);
  // The id crosses the wire as hex (§4) and is bound as bytes. Re-encoding what the scheme
  // handed back is exact rather than convenient: the grammar admits only lowercase hex, so
  // this round-trips the URL's own segment and is the value the service will echo.
  const id = toHex(idBytes);
  const request = await fetchLoginRequest(audience, id);
  validateLoginRequest(request, id);

  // SHOW BEFORE SIGN. The person confirms the statement, not the URL.
  const keySource = describeKeySource(src);
  write(renderStatement(audience, request, io.now(), keySource));
  if (!assumeYes && !(await confirm())) {
    write("refused. nothing was signed.\n");
    return;
  }

  // ONLY NOW is the key touched. For a store key this is where the password is asked for.
  const seed = resolveLoginSeed(src, fd);
  const { proof, principal } = proveLogin(seed, audience, request);
  await postLoginAnswer(audience, id, {
    principal,
    possession: toHex(proof),
    authority: toHex(authority),
  });
  write(`signed as ${principal}. the browser is in.\n`);
}

/** Refuse a malformed request BEFORE anything is displayed, so the person is never shown a
 *  statement built from junk. Every refusal names the field. */
export function validateLoginRequest(r: LoginRequest, wantId: string): void {
  if (r.id !== wantId) throw new Error(`login: the service answered for request ${JSON.stringify(r.id)}, not ${JSON.stringify(wantId)}`);
  if (!/^[0-9a-fA-F]*$/.test(r.nonce) || r.nonce.length % 2 !== 0) throw new Error("login: nonce is not hex");
  if (r.nonce.length / 2 < MIN_NONCE_SIZE) {
    throw new Error(`login: nonce is ${r.nonce.length / 2} bytes, min ${MIN_NONCE_SIZE} — refusing a guessable challenge`);
  }
  try {
    decodeKey(r.browser);
  } catch (err) {
    throw new Error(`login: browser key ${JSON.stringify(r.browser)} is not canonical key text: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!Array.isArray(r.scope)) throw new Error("login: scope is not a list");
  r.scope.forEach((entry, i) => {
    if (typeof entry !== "string" || entry === "") throw new Error(`login: scope entry ${i} is empty`);
    refuseUndisplayable(`scope entry ${i}`, entry);
  });
  if (!Number.isInteger(r.valid_for) || r.valid_for <= 0) {
    throw new Error("login: valid_for is 0 — a delegation dead on arrival");
  }
}

/** Reject C0/DEL control characters in anything the person will be shown. A scope entry
 *  carrying an escape sequence can repaint the terminal and hide what is really being
 *  signed, so display safety is a validation concern, not a cosmetic one. */
function refuseUndisplayable(field: string, s: string): void {
  // Lone surrogates survive JSON.parse and are NOT valid UTF-8; the scheme's check_text
  // refuses them at binding time, which is after the person has already agreed. Refusing
  // here means a request that could lie on screen never reaches the confirm prompt.
  if (/\p{Surrogate}/u.test(s)) {
    throw new Error(`login: ${field} is not valid UTF-8 — refusing`);
  }
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (code < 0x20 || code === 0x7f) {
      throw new Error(`login: ${field} contains a control character — refusing`);
    }
  }
}

/** EXACTLY what the person is asked to approve, and the text all three lanes must print
 *  byte-identically. nowSeconds is a parameter so the wall-clock end is testable. */
export function renderStatement(
  audience: string,
  r: LoginRequest,
  nowSeconds: number,
  keySource: string,
): string {
  const lines = [`${audience} asks you to let browser key ${r.browser} act as you:`, ...scopeAndValidityLines(r, nowSeconds)];
  lines.push(`signing with ${keySource}`);
  return `${lines.join("\n")}\n`;
}

/** The offers form's counterpart (docs/login.md §4.1 rule 4): the same fields as the
 *  statement, printed AFTER answering rather than before signing, because in that form nobody
 *  confirmed — the person typed the scope and the audience is the CLI's own. It names K as the
 *  request delivered it, the source that signed, and the service's verdict (`undefined` for an
 *  accepted answer, else the code). Never the code: the ledger goes to stdout, and stdout may
 *  be a log. */
export function renderLedger(
  audience: string,
  r: LoginRequest,
  nowSeconds: number,
  keySource: string,
  refused: string | undefined,
): string {
  const lines = [`you offered ${audience} to let browser key ${r.browser} act as you:`, ...scopeAndValidityLines(r, nowSeconds)];
  lines.push(`signed with ${keySource}`);
  lines.push(
    refused === undefined
      ? "the service accepted the login. the browser is in."
      : `the service refused the login (${refused}). the browser is not in.`,
  );
  return `${lines.join("\n")}\n`;
}

/** The middle of both renderings — every scope entry verbatim, in order, then the validity as
 *  a duration and as a wall-clock end — written once so the two forms cannot drift from each
 *  other in the lines they share. */
function scopeAndValidityLines(r: LoginRequest, nowSeconds: number): string[] {
  const end = Math.floor(nowSeconds) + r.valid_for;
  const lines: string[] = [];
  // An EMPTY scope is valid (docs/login.md §3.1: 0..=65535 entries) — a proof-only service
  // asks for possession and delegates nothing. It still gets a line, because a statement
  // that silently showed nothing where the scope goes would read as a rendering bug at
  // exactly the moment the person is deciding what to sign.
  if (r.scope.length === 0) lines.push(`  ${NO_SCOPE_LINE}`);
  for (const entry of r.scope) lines.push(`  ${entry}`);
  lines.push(`for ${formatDuration(r.valid_for)}, until ${formatRfc3339Utc(end)}`);
  return lines;
}

/** Name the custody the signature will come from, for the last line of the statement
 *  (seat:cca ruling, 2026-09-10).
 *
 *  It is the SOURCE and not the principal, on purpose: naming the principal would mean
 *  unlocking the key before the person has agreed to sign — which, for a password-protected
 *  store, means demanding a password in order to show someone what they are being asked to
 *  approve. The source is known without touching the key at all.
 *
 *  A store key is named by its NAME, whether --key chose it or the default pointer did: the
 *  statement says what will sign, and how the name was chosen is not part of what is being
 *  approved. The pinned wording is cca's (2026-09-10 20:47Z). */
export function describeKeySource(src: LoginSource): string {
  if (src.storeKey !== undefined) return `the store key ${src.storeKey}`;
  if (src.seedFile !== undefined) return `the seed file ${src.seedFile}`;
  if (src.keyFile !== undefined) return `the key file ${src.keyFile}`;
  if (src.seedHex !== undefined) return "the seed given on the command line";
  return "an unspecified key";
}

/** Render seconds the same way in every lane. Written out explicitly so Go and Rust
 *  reproduce it exactly — a shared format nobody has to reverse-engineer. */
export function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h${m}m${s}s`;
  if (m > 0) return `${m}m${s}s`;
  return `${s}s`;
}

/** Format a Unix timestamp as YYYY-MM-DDTHH:MM:SSZ, matching the other two lanes. */
export function formatRfc3339Utc(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Read a y/N answer. Default is NO: anything that is not an explicit yes refuses,
 *  including EOF, so a login cannot be completed by a closed stdin. */
export async function confirm(): Promise<boolean> {
  process.stdout.write("sign? [y/N] ");
  const rl = createInterface({ input: process.stdin });
  const line = await new Promise<string>((resolve) => {
    rl.once("line", (value) => resolve(value));
    rl.once("close", () => resolve(""));
  });
  rl.close();
  const answer = line.trim().toLowerCase();
  return answer === "y" || answer === "yes";
}

/** Obtains the seed for the source decided at flag-parse time. Runs ONLY after the person
 *  has confirmed the statement: for a store key that is the moment the password is asked
 *  for, and never before. Seed files stay beside the store permanently, so an agent's
 *  non-interactive run and a person's login are the same code with two custody sources
 *  (ADR 0007 §A; archon#16, answer 2). */
function resolveLoginSeed(src: LoginSource, fd: number | undefined): Uint8Array {
  if (src.storeKey !== undefined) return store.unlockNamedKey(src.storeKey, fd);
  if (src.seedFile !== undefined) return seedFromHexFile(readFileSync(src.seedFile, "utf8"));
  return resolveSeed(src.seedHex, src.keyFile, USAGE);
}

/** Accept the two hex seed-file shapes in use: 64 hex characters (a raw 32-byte seed) and
 *  128 (seed followed by public key), the shape the first consumer's `key` files carry (answer 4). */
export function seedFromHexFile(text: string): Uint8Array {
  const trimmed = text.trim();
  if (!/^[0-9a-fA-F]*$/.test(trimmed) || trimmed.length % 2 !== 0) throw new Error("seed file is not hex");
  const raw = fromHex(trimmed);
  if (raw.length !== 32 && raw.length !== 64) {
    throw new Error(`seed file holds ${raw.length} bytes; want 32 (seed) or 64 (seed and public key)`);
  }
  return raw.slice(0, 32);
}

/** Read the authority payload. It is OPAQUE to archon — the delegation's meaning is the
 *  law's (thesmos), and this command must never parse it. Absent is empty. */
function readAuthority(path?: string): Uint8Array {
  if (path === undefined) return new Uint8Array();
  return new Uint8Array(readFileSync(path));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** GET the request. The CLI owns HTTP; the SDK never opens a socket (archon#16). */
export async function fetchLoginRequest(audience: string, id: string): Promise<LoginRequest> {
  const endpoint = `${audience}/login/${encodeURIComponent(id)}`;
  let response: Response;
  try {
    response = await fetch(endpoint);
  } catch (err) {
    throw new Error(`login: could not reach ${endpoint}: ${err instanceof Error ? err.message : String(err)}`);
  }
  const body = await response.text();
  if (!response.ok) throw new Error(loginHttpError(response.status, body));
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(`login: the service's request is not the expected JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (parsed === null || typeof parsed !== "object") throw new Error("login: the service's request is not a JSON object");
  for (const field of Object.keys(parsed)) {
    if (!KNOWN_REQUEST_FIELDS.has(field)) {
      throw new Error(`login: the service's request carries an unknown field ${JSON.stringify(field)} — refusing`);
    }
  }
  return parsed as LoginRequest;
}

/** Deliver the answer and report the service's verdict as an error, which is what the
 *  confirmed form wants: a refusal ends the command. */
export async function postLoginAnswer(audience: string, id: string, answer: LoginAnswer): Promise<void> {
  const { status, body } = await postAnswer(audience, id, answer);
  if (status !== 204 && status !== 200) throw new Error(loginHttpError(status, body));
}

/** The POST itself, returning the service's status and body so the offers form can record a
 *  refusal in its ledger rather than stop on it (§4.1 rule 4: the ledger is printed whether the
 *  service accepted or refused). Only a failure to reach the service throws — then nothing was
 *  answered, and there is nothing to record. */
async function postAnswer(audience: string, id: string, answer: LoginAnswer): Promise<{ status: number; body: string }> {
  const endpoint = `${audience}/login/${encodeURIComponent(id)}/answer`;
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(answer),
    });
  } catch (err) {
    throw new Error(`login: could not reach ${endpoint}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return { status: response.status, body: await response.text() };
}

// ---------------------------------------------------------------------------
// THE OFFERS FORM (docs/login.md §4.1)
// ---------------------------------------------------------------------------
//
// `archon login` with no URL. The prover starts: it mints a code from its own entropy,
// registers what it is willing to delegate, prints the code where only the person can see it,
// waits for the page to take the offer, and answers ONLY the request that took it — after
// checking for itself that the request is what was offered. No confirmation is asked: the
// person typed the scope, the audience is the CLI's own, and the only request it will answer
// carries the code it minted a moment ago. Afterwards it prints the ledger of that decision,
// whether the service accepted or refused.

/** How much of the CLI's own entropy a code carries: 16 bytes, spelled as 32 lowercase hex
 *  characters, the floor §4.1 sets. The code is confidential until the offer is taken. */
const CODE_BYTES = 16;

/** The service's answer to an offer. `page`, when the service has one, is the address the
 *  person opens, carrying the code in its fragment. No audience here either — in this form the
 *  audience is the prover's own configuration — and a response carrying one is refused. */
export interface OfferResponse {
  code: string;
  scope: string[];
  valid_for: number;
  expires_in: number;
  interval: number;
  page?: string;
}
const KNOWN_OFFER_FIELDS = new Set(["code", "scope", "valid_for", "expires_in", "interval", "page"]);

/** GET <audience>/login/offers/<code>: `request` is null until the page has taken the offer,
 *  then the id of the request that did. */
interface OfferRead {
  code: string;
  scope: string[];
  valid_for: number;
  request: string | null;
  expires?: string;
}
const KNOWN_OFFER_READ_FIELDS = new Set(["code", "scope", "valid_for", "request", "expires"]);

/** The offers form. The order is §4.1's, rule by rule, and the same before-any-network
 *  discipline as the confirmed form: everything decidable without the service — the custody,
 *  the authority file, the scope, the validity, the audience — is decided first, so those
 *  refusals land before an offer exists. */
export async function runOffer(args: string[], write: (text: string) => void, io: LoginIo): Promise<void> {
  // The password descriptor is the STORE's flag, taken out first exactly as `key add` does.
  // `--password-fd 0` needs no `--yes` here: nothing in this form reads stdin.
  const { rest, fd } = store.takePasswordFd(args);
  const src: LoginSource = {};
  let authorityFile: string | undefined;
  let audienceFlag: string | undefined;
  let validForText: string | undefined;
  const scope: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i]!;
    if (flag === "--yes") {
      // A flag that does nothing is a flag someone will come to rely on — and this one would
      // suggest a confirmation exists to skip.
      throw new Error(`no confirmation is asked in this form — what you typed is what you sign; drop --yes\n${USAGE}`);
    }
    const value = rest[i + 1];
    if (value === undefined || value === "") throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    i++;
    switch (flag) {
      case "--audience": audienceFlag = value; break;
      case "--scope": scope.push(value); break;
      case "--valid-for": validForText = value; break;
      case "--key": src.storeKey = value; break;
      case "--seed": src.seedHex = value; break;
      case "--key-file": src.keyFile = value; break;
      case "--seed-file": src.seedFile = value; break;
      case "--authority-file": authorityFile = value; break;
      default: throw new Error(`unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
    }
  }
  decideLoginSource(src);
  if (fd !== undefined && src.storeKey === undefined) {
    throw new Error(`--password-fd applies only to a store key (--key, or the default)\n${USAGE}`);
  }
  const authority = readAuthority(authorityFile);
  // WHAT YOU TYPED IS WHAT YOU SIGN — so what was typed is checked the way the service will
  // check it, here, before an offer nobody could begin on is registered.
  scope.forEach((entry, i) => {
    if (entry === "") throw new Error(`login: --scope entry ${i} is empty`);
    refuseUndisplayable(`--scope entry ${i}`, entry);
  });
  const validFor = parseValidFor(validForText);
  // RULE 1: the audience is the CLI's own configuration, a fixed point of §2.1's grammar,
  // refused before anything is fetched.
  const audience = configuredAudience(audienceFlag);

  // The code is the CLI's own entropy, registered under it. The service echoes the offer back;
  // an echo that differs is a service that altered what was offered, and nothing of it is
  // trusted from here on.
  const code = mintCode();
  const offered = await postOffer(audience, { code, scope, valid_for: validFor });
  checkOfferEcho(offered, code, scope, validFor);
  // STDERR, deliberately: the interactive channel, where the password prompt already lives.
  // `archon login … > file` must never write the code into a log (§4.1 rule 1).
  io.writeErr(`offer registered at ${audience}\n`);
  io.writeErr(`code: ${code}\n`);
  if (offered.page !== undefined) io.writeErr(`${describePage(audience, offered.page)}\n`);
  io.writeErr(`waiting for the page to take the offer, up to ${offered.expires_in}s\n`);

  // The prover paces ITSELF (ADR 0007 §C.7, #39): the route is unpaced because two parties
  // poll it, so the discipline is here — one interval before the first poll, so the page
  // always has the first window, and one between polls.
  const id = await pollOffer(audience, code, offered, io);

  // RULE 2: answer only the request the offer names, and only after re-checking it against
  // what was offered — never trusting that the service's refusal happened. K is RECORDED from
  // the request; it was never offered, so it is not checked, and it is what the ledger names.
  const request = await fetchLoginRequest(audience, id);
  validateLoginRequest(request, id);
  checkAgainstOffer(request, scope, validFor);

  // RULE 3: no confirmation. The key is unlocked now — for a store key this is where the
  // password is asked for, and a person who never finishes never types it — and the proof
  // made and posted.
  const seed = resolveLoginSeed(src, fd);
  const { proof, principal } = proveLogin(seed, audience, request);
  const { status, body } = await postAnswer(audience, id, {
    principal,
    possession: toHex(proof),
    authority: toHex(authority),
  });

  // RULE 4: the ledger, accepted or refused, on stdout — field by field, never the code.
  const refused = errorCodeOf(status, body);
  write(renderLedger(audience, request, io.now(), describeKeySource(src), refused));
  if (refused !== undefined) throw new Error(`login: the service refused the login (${refused})`);
}

/** Reads --valid-for. Required: a delegation's lifetime is typed, never assumed — a default
 *  here would be a number nobody chose, signed anyway. */
function parseValidFor(text: string | undefined): number {
  if (text === undefined) {
    throw new Error(`--valid-for <seconds> is required — a delegation's lifetime is typed, never assumed\n${USAGE}`);
  }
  if (!/^\d+$/.test(text)) throw new Error(`--valid-for must be a whole number of seconds, 1 or more; got ${JSON.stringify(text)}`);
  const n = Number(text);
  if (!Number.isSafeInteger(n) || n <= 0 || n > 0xffffffff) {
    throw new Error(`--valid-for must be a whole number of seconds, 1 or more; got ${JSON.stringify(text)}`);
  }
  return n;
}

/** §4.1 rule 1. The audience is --audience, or ARCHON_AUDIENCE as the configured default,
 *  checked exactly the same way: it must be a fixed point of §2.1's grammar — the very check
 *  the server applies to its own configuration — and the CLI refuses to start otherwise. The
 *  `/login/00` is the shortest invocation URL the grammar admits, there only to make the
 *  audience parseable as one; feeding the audience through the scheme's derivation asks the
 *  one question that matters: is this the string the service binds? */
export function configuredAudience(flag: string | undefined): string {
  const audience = flag !== undefined && flag !== "" ? flag : (process.env["ARCHON_AUDIENCE"] ?? "");
  if (audience === "") {
    throw new Error(
      "login: no audience — pass --audience <base> or set ARCHON_AUDIENCE; " +
        "in this form the audience is your configuration, never a page's word (docs/login.md §4.1)",
    );
  }
  let derived: string;
  try {
    derived = deriveAudience(`${audience}/login/00`).audience;
  } catch (err) {
    throw new Error(`login: audience ${JSON.stringify(audience)} is not valid: ${err instanceof Error ? err.message : String(err)} (docs/login.md §2.1)`);
  }
  if (derived !== audience) {
    throw new Error(`login: audience ${JSON.stringify(audience)} is not canonical — the service binds ${JSON.stringify(derived)}; pass that (docs/login.md §2.1)`);
  }
  return audience;
}

/** The code, from the OS CSPRNG. The randomness lives HERE, in the command, as every other
 *  randomness of the pinned tiers does (ADR 0006). */
function mintCode(): string {
  return toHex(new Uint8Array(randomBytes(CODE_BYTES)));
}

/** Registers the offer. Unknown fields in the response are refused, as everywhere in this
 *  command: a service adding fields is speaking a protocol this lane does not. */
async function postOffer(audience: string, offer: { code: string; scope: string[]; valid_for: number }): Promise<OfferResponse> {
  const endpoint = `${audience}/login/offers`;
  let response: Response;
  try {
    response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(offer) });
  } catch (err) {
    throw new Error(`login: could not reach ${endpoint}: ${err instanceof Error ? err.message : String(err)}`);
  }
  const body = await response.text();
  if (response.status !== 201) throw new Error(loginHttpError(response.status, body));
  return parseKnown(body, KNOWN_OFFER_FIELDS, "offer") as unknown as OfferResponse;
}

/** Parses a service response as an object carrying only known fields — a service adding
 *  fields is speaking a protocol this lane does not, and is refused rather than half-read. */
function parseKnown(body: string, known: Set<string>, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(`login: the service's ${what} is not the expected JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`login: the service's ${what} is not a JSON object`);
  for (const field of Object.keys(parsed)) {
    if (!known.has(field)) throw new Error(`login: the service's ${what} carries an unknown field ${JSON.stringify(field)} — refusing`);
  }
  return parsed as Record<string, unknown>;
}

/** Requires the service to have registered EXACTLY what was offered. The offer is what the
 *  person typed; a service that echoes something else has altered it, and a prover that went
 *  on would be waiting to sign a delegation nobody typed. */
function checkOfferEcho(offered: OfferResponse, code: string, scope: string[], validFor: number): void {
  if (offered.code !== code) throw new Error("login: the service altered the offer: the code it registered is not the one sent");
  const differs = scopeAndValidityDiffer(offered.scope ?? [], offered.valid_for, scope, validFor);
  if (differs !== undefined) throw new Error(`login: the service altered the offer: ${differs}`);
  if (!Number.isInteger(offered.expires_in) || offered.expires_in <= 0) throw new Error("login: the service's offer has no lifetime (expires_in)");
}

/** The one line about the page address, printed and MARKED, never opened (§4.1 rule 1; ADR
 *  0007 §C.7 (6)). "On the service's own origin" is a byte-exact comparison of scheme and host
 *  with the audience's — a differently spelled origin fails closed, the right direction for an
 *  address a person is about to click — and launching a browser is the person's action, never
 *  this command's: spawning a platform opener by name is the PATH surface §C.5 refuses. */
export function describePage(audience: string, page: string): string {
  const origin = originOf(audience);
  const onOrigin = page === origin || page.startsWith(`${origin}/`) || page.startsWith(`${origin}#`) || page.startsWith(`${origin}?`);
  return onOrigin ? `page: ${page} (on the service's own origin)` : `page: ${page} (NOT on the service's origin — do not open it)`;
}

/** The audience up to its path: scheme, host and port, as the audience spells them (canonical
 *  by construction — configuredAudience made sure). */
function originOf(audience: string): string {
  const afterScheme = audience.includes("://") ? audience.indexOf("://") + 3 : 0;
  const slash = audience.indexOf("/", afterScheme);
  return slash < 0 ? audience : audience.slice(0, slash);
}

/** Waits for the page to take the offer and returns the id of the request that did.
 *
 *  The pacing is the prover's own (ADR 0007 §C.7, #39): one advertised interval BEFORE the
 *  first poll — the page always gets the first window — and one between polls; a 429 from a
 *  server that paces anyway is sleep-and-retry, never an error. The wait is bounded by the
 *  offer's own lifetime, and a 404 before then is the offer gone — expired, or taken and already
 *  finished — which for a prover still waiting means the page never took it. */
async function pollOffer(audience: string, code: string, offered: OfferResponse, io: LoginIo): Promise<string> {
  const interval = Math.max(1, Math.floor(offered.interval));
  const deadline = io.now() + offered.expires_in;
  const endpoint = `${audience}/login/offers/${encodeURIComponent(code)}`;
  for (;;) {
    await io.sleep(interval);
    if (io.now() > deadline) throw new Error("login: the offer expired before the page took it");
    let response: Response;
    try {
      response = await fetch(endpoint);
    } catch (err) {
      throw new Error(`login: could not reach ${endpoint}: ${err instanceof Error ? err.message : String(err)}`);
    }
    const body = await response.text();
    if (response.status === 429) continue;
    if (response.status === 404) throw new Error("login: the offer expired before the page took it");
    if (response.status !== 200) throw new Error(loginHttpError(response.status, body));
    const read = parseKnown(body, KNOWN_OFFER_READ_FIELDS, "offer") as unknown as OfferRead;
    if (typeof read.request === "string" && read.request !== "") return read.request;
  }
}

/** §4.1 rule 2, done by the prover for itself: the request's scope must be what was offered,
 *  entry for entry, in order, and its validity equal. The service refuses a mismatched begin
 *  before storing anything — but a prover that relied on that would be trusting the service
 *  about the one thing it is about to sign. */
export function checkAgainstOffer(r: LoginRequest, scope: string[], validFor: number): void {
  const differs = scopeAndValidityDiffer(r.scope, r.valid_for, scope, validFor);
  if (differs !== undefined) throw new Error(`login: the service's request differs from the offer — ${differs} — refusing to sign`);
}

/** "Differs in any way", stated once for the echo and for the request: the same number of
 *  entries, each equal to its counterpart IN ORDER, the same validity. */
function scopeAndValidityDiffer(gotScope: string[], gotValidFor: number, scope: string[], validFor: number): string | undefined {
  if (gotValidFor !== validFor) return `valid_for is ${gotValidFor}, offered ${validFor}`;
  if (gotScope.length !== scope.length) return `${gotScope.length} scope entries, offered ${scope.length}`;
  for (let i = 0; i < scope.length; i++) {
    if (gotScope[i] !== scope[i]) return `scope entry ${i} is ${JSON.stringify(gotScope[i])}, offered ${JSON.stringify(scope[i])}`;
  }
  return undefined;
}

/** The service's verdict for the ledger: undefined for an accepted answer; otherwise the RFC
 *  8628 code from the error body, or the bare status when the body carries none. */
function errorCodeOf(status: number, body: string): string | undefined {
  if (status === 204 || status === 200) return undefined;
  try {
    const payload = JSON.parse(body) as { error?: unknown };
    if (payload !== null && typeof payload === "object" && typeof payload.error === "string" && payload.error !== "") return payload.error;
  } catch {
    // not JSON; fall through to the status
  }
  return `HTTP ${status}`;
}

/** Turn a non-success response into a diagnosis. RFC 8628's error vocabulary is used where
 *  the service speaks it, since this protocol adopts that shape. */
export function loginHttpError(status: number, body: string): string {
  try {
    const payload = JSON.parse(body) as { error?: string; error_description?: string };
    if (payload !== null && typeof payload === "object" && typeof payload.error === "string" && payload.error !== "") {
      if (payload.error === "expired_token") return "login: this request has expired — reload the page and run the new command";
      if (payload.error === "access_denied") return "login: the service refused the login";
      if (payload.error_description) return `login: ${payload.error_description} (${payload.error})`;
      return `login: the service answered ${JSON.stringify(payload.error)}`;
    }
  } catch {
    // not JSON; fall through to the status line
  }
  return `login: the service answered HTTP ${status}`;
}

// ---------------------------------------------------------------------------
// THE SCHEME SEAM
// ---------------------------------------------------------------------------
//
// The one place this lane reaches the login scheme, and the only part of this file that
// changes when sdk/ts/login lands. The scheme — binding layout, role tags, proof — is
// seat:cca's (archon#16). Pinned by their authorship comment, for whoever wires this up:
//
//   binding = role ‖ u16 len ‖ audience ‖ K[32] ‖ u16 len ‖ id ‖ scope ‖ u32 valid_for
//   scope   = u16 count ‖ (u16 len ‖ bytes)*
//   role    = 0x01 person's login proof (signed by P), 0x02 browser's collect proof (by K)
//   proof   = possession over the server's nonce and that binding, domain archon-login/1

/** The possession proof over this request, plus the person's principal as canonical key
 *  text. The principal is derived here — a property of the seed, not of the scheme — so
 *  only the proof itself waits on sdk/ts/login.
 *
 *  LOUD ON PURPOSE until then: a locally computed binding that merely looks right would
 *  produce proofs that verify nowhere and take a day to explain. */
export function proveLogin(
  seed: Uint8Array,
  audience: string,
  request: LoginRequest,
): { proof: Uint8Array; principal: string } {
  const principal = encodeKey(getPublicKey(seed));

  // Re-decoded rather than assumed: validateLoginRequest has already checked these, but it
  // runs on the flow's path and this function is reachable from any future caller. A silent
  // mis-decode would produce a proof bound to bytes nobody displayed.
  const nonce = fromHex(request.nonce);
  const browser = decodeKey(request.browser);

  // The id crosses as its bytes: the scheme binds it as an opaque field, so the CLI must
  // not normalise, case-fold or re-encode it on the way in.
  // THE ID IS HEX-DECODED, NOT HANDED OVER AS TEXT. docs/login.md §3.1 makes the id BYTES
  // carried as "hex in URLs and JSON"; the scheme binds the bytes. Encoding the hex string
  // as UTF-8 would bind the ASCII of the hex — 0x38 0x66 0x33 0x63 for "8f3c" instead of
  // 0x8f 0x3c — and the resulting proof verifies NOWHERE. A stub test that builds its
  // expected request the same wrong way still passes, which is how it survived.
  const scheme: SchemeRequest = {
    id: fromHex(request.id),
    nonce,
    browser,
    scope: request.scope,
    validFor: request.valid_for,
  };
  return { proof: schemeProveLogin(seed, audience, scheme), principal };
}
