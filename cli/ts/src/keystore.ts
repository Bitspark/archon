// The archon key store's file format — docs/keystore.md, ADR 0007 §A.
//
// Identical across cli/{rs,go,ts} and pinned by vectors/keystore.json. Version 2 (§8), the only
// one written:
//
//   "arck" ‖ 0x02 ‖ u32be(m KiB) ‖ u32be(t) ‖ u8(p) ‖ salt[16] ‖ pubkey[32]
//     ‖ u8(mode) ‖ u8(n) ‖ n × (u8(len) ‖ context)                             header, H
//   nonce[24]
//   XChaCha20Poly1305(seed[32], aad = header)                                    48 with tag
//
// Version 1 (§2) is the same without the policy, a fixed 134 bytes; it is still read.
//
// This module is the format and nothing else: no paths, no prompts, no policy. Custody is
// the command's (ADR 0007 §A) and nothing in core/ or sdk/ learns a password — but that
// cuts both ways, so the format does not learn a directory either.
//
// This is the slow lane: pure-JS Argon2id costs ~2.0 s per unlock at the shipping
// parameters against ~210 ms native (docs/keystore.md §3). `key list` never pays it,
// because the public key is in the clear.
import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { getPublicKey } from "@bitspark/archon";
import { displayUnsafe } from "@bitspark/archon-sdk";

// Follows the envelope's "arcn" ‖ version (sdk/{go,rs,ts}). It is what stops a 134-byte
// non-key file being LISTED as a key: `key list` reads the header without a password, so
// it is the one place a wrong file would be believed.
export const MAGIC = new Uint8Array([0x61, 0x72, 0x63, 0x6b]); // "arck"
// The fixed 134-byte file of docs/keystore.md §2. It is still PARSED, so that `key list`,
// `key rm` and `key policy` can name and convert it, and nothing signs with it.
export const VERSION_1 = 0x01;
// Adds the context policy of §8; the only version written.
export const VERSION_2 = 0x02;

export const SALT_SIZE = 16;
export const NONCE_SIZE = 24;
export const SEED_SIZE = 32;
export const PUBLIC_KEY_SIZE = 32;
// The fields every version shares, up to and including the public key.
const COMMON_SIZE = 4 + 1 + 4 + 4 + 1 + SALT_SIZE + PUBLIC_KEY_SIZE; // 62
const SEAL_SIZE = SEED_SIZE + 16;
export const V1_FILE_SIZE = COMMON_SIZE + NONCE_SIZE + SEAL_SIZE; // 134

// Version 2's policy: a mode, a count, then length-prefixed contexts (§8.1).
export const POLICY_UNRESTRICTED = 0x00;
export const POLICY_ALLOWLIST = 0x01;
export const MAX_CONTEXTS = 16;
export const MAX_CONTEXT_SIZE = 255;
export const MIN_V2_FILE_SIZE = COMMON_SIZE + 2 + NONCE_SIZE + SEAL_SIZE; // 136
export const MAX_V2_FILE_SIZE = COMMON_SIZE + 2 + MAX_CONTEXTS * (1 + MAX_CONTEXT_SIZE) + NONCE_SIZE + SEAL_SIZE; // 4232

// The shipping default, measured rather than assumed (docs/keystore.md §3): p=4 buys
// nothing in any lane we ship and costs two of three external oracles.
export const DEFAULT_MEMORY_KIB = 65536;
export const DEFAULT_TIME = 3;
export const DEFAULT_PARALLELISM = 1;

/** Argon2id cost parameters. Read from the header, never assumed. */
export type KeyParams = { memoryKiB: number; time: number; parallelism: number };

export const defaultParams = (): KeyParams => ({
  memoryKiB: DEFAULT_MEMORY_KIB,
  time: DEFAULT_TIME,
  parallelism: DEFAULT_PARALLELISM,
});

/**
 * The ceilings a header's parameters must stay under (docs/keystore.md §2). They exist only so
 * that a header someone else wrote cannot make an unlock unbounded, and they are generous on
 * purpose: RFC 9106's first recommended setting (2 GiB, t=1, p=4) still opens.
 */
export const MAX_MEMORY_KIB = 2 * 1024 * 1024;
export const MAX_TIME = 10;

/**
 * Refuses parameters no lane may derive with. The lower bounds are RFC 9106's validity rules
 * and nothing more (t ≥ 1, p ≥ 1, m ≥ 8p), so a weak but valid file keeps opening: its weakness
 * is its writer's. Stated here, once, before any derivation, so all three lanes refuse the same
 * headers at the same step whatever their Argon2 library does.
 */
function checkParams(p: KeyParams): void {
  if (p.time === 0 || p.parallelism === 0) {
    throw new Error("argon2id parameters are not usable: t and p must be at least 1");
  }
  if (p.memoryKiB < 8 * p.parallelism) {
    throw new Error(`argon2id parameters are not usable: m=${p.memoryKiB} KiB is below 8*p=${8 * p.parallelism}`);
  }
  if (p.memoryKiB > MAX_MEMORY_KIB) {
    throw new Error(`argon2id parameters are not usable: m=${p.memoryKiB} KiB is above ${MAX_MEMORY_KIB}`);
  }
  if (p.time > MAX_TIME) {
    throw new Error(`argon2id parameters are not usable: t=${p.time} is above ${MAX_TIME}`);
  }
}

/**
 * The authenticated prefix of a key file. `publicKey` is readable without a password —
 * that is what `key list` prints — but it is only a CLAIM until an unlock verifies the tag
 * over this header and re-derives it from the seed.
 */
export type KeyHeader = {
  version: number;
  params: KeyParams;
  salt: Uint8Array;
  publicKey: Uint8Array;
  /** null for a version-1 file, which has none. */
  policy: Policy | null;
  /** The header's length: the AEAD's associated data is file[0, size). */
  size: number;
};

/**
 * A refusal of the file itself, before any derivation. `kind` is the machine-mode category the
 * command reports (docs/keystore.md §8.2): "unsupported" for a version byte this binary does
 * not know, "malformed" for everything else.
 */
export class FormatError extends Error {
  constructor(readonly kind: "unsupported" | "malformed", message: string) {
    super(message);
  }
}

const malformed = (message: string): FormatError => new FormatError("malformed", message);

/**
 * A version-2 entry's context policy (§8.1): unrestricted, or an allowlist of contexts in
 * strictly ascending byte order. An empty allowlist denies every context.
 */
export type Policy = { unrestricted: boolean; contexts: string[] };

const utf8 = new TextEncoder();

/** Byte order, the order the format and the other lanes use: never UTF-16 code-unit order. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  }
  return a.length - b.length;
}

function checkContext(c: Uint8Array): void {
  if (c.length < 1 || c.length > MAX_CONTEXT_SIZE) {
    throw new Error(`a context is 1 to ${MAX_CONTEXT_SIZE} bytes (got ${c.length})`);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(c);
  } catch {
    throw new Error("a context is well-formed UTF-8");
  }
  // A policy is shown to the person (`key policy`, `key list`, the refusals), so a context holds
  // nothing a terminal would not show as itself (docs/login.md §5's set), by code point. Refused
  // on write and on read, so nothing is written that cannot be read, and nothing read that
  // cannot be shown.
  for (const ch of text) {
    const cp = ch.codePointAt(0) as number;
    if (displayUnsafe(cp)) {
      throw new Error(`a context may not contain U+${cp.toString(16).toUpperCase().padStart(4, "0")}: it would not be shown as itself`);
    }
  }
}

/**
 * Builds an allowlist from the contexts a person named: each a domain by ADR 0008 §2 (1..255
 * bytes of well-formed UTF-8), no duplicates, at most MAX_CONTEXTS. It sorts them by bytes, so
 * one policy has one encoding.
 */
export function allowlist(contexts: string[]): Policy {
  if (contexts.length > MAX_CONTEXTS) {
    throw new Error(`at most ${MAX_CONTEXTS} contexts (got ${contexts.length})`);
  }
  const encoded = contexts.map((c) => ({ c, b: utf8.encode(c) }));
  for (const { c, b } of encoded) {
    // A lone surrogate does not survive the encoder: compare the round trip, not the length.
    if (new TextDecoder().decode(b) !== c) throw new Error("a context is well-formed UTF-8");
    checkContext(b);
  }
  encoded.sort((x, y) => compareBytes(x.b, y.b));
  for (let i = 1; i < encoded.length; i++) {
    if (compareBytes((encoded[i - 1] as { b: Uint8Array }).b, (encoded[i] as { b: Uint8Array }).b) === 0) {
      throw new Error(`context ${JSON.stringify((encoded[i] as { c: string }).c)} is named twice`);
    }
  }
  return { unrestricted: false, contexts: encoded.map((e) => e.c) };
}

export const unrestricted = (): Policy => ({ unrestricted: true, contexts: [] });

/** Byte-exact membership: no prefix, no wildcard, no normalisation. */
export function permits(p: Policy, domain: string): boolean {
  return p.unrestricted || p.contexts.includes(domain);
}

/** The policy as the command prints it. */
export function describePolicy(p: Policy | null): string {
  if (p === null) return "no policy";
  if (p.unrestricted) return "unrestricted";
  if (p.contexts.length === 0) return "allow nothing";
  return `allow ${p.contexts.map(quote).join(", ")}`;
}

/** Spells a context by the JSON string rule, so a context holding ", " cannot read as two. The
 *  same rule in the three lanes: `"` and `\` escaped, C0 controls as \u00xx. */
function quote(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch === '"' || ch === "\\") out += `\\${ch}`;
    else if (cp < 0x20) out += `\\u${cp.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

function encodePolicy(p: Policy): Uint8Array {
  if (p.unrestricted) return new Uint8Array([POLICY_UNRESTRICTED, 0]);
  const parts = p.contexts.map((c) => utf8.encode(c));
  const out = new Uint8Array(2 + parts.reduce((n, b) => n + 1 + b.length, 0));
  out[0] = POLICY_ALLOWLIST;
  out[1] = parts.length;
  let off = 2;
  for (const b of parts) {
    out[off] = b.length;
    out.set(b, off + 1);
    off += 1 + b.length;
  }
  return out;
}

// Both ends refuse an empty password: a store sealed under one is a plaintext store that
// looks encrypted, and refusing at OPEN too keeps a file made by a lenient writer from
// ever being trusted.
export const EMPTY_PASSWORD = "an empty password is refused: it would look encrypted and not be";

/**
 * Derives the file key. The password is UTF-8, normalised NFC so the same characters typed
 * on different platforms derive the same key.
 */
function deriveKey(password: string, salt: Uint8Array, p: KeyParams): Uint8Array {
  const bytes = new TextEncoder().encode(password.normalize("NFC"));
  return argon2id(bytes, salt, { m: p.memoryKiB, t: p.time, p: p.parallelism, dkLen: 32 });
}

/** A version-2 header: the only version written (§8). */
function encodeHeader(p: KeyParams, salt: Uint8Array, publicKey: Uint8Array, policy: Policy): Uint8Array {
  const pol = encodePolicy(policy);
  const out = new Uint8Array(COMMON_SIZE + pol.length);
  out.set(MAGIC, 0);
  out[4] = VERSION_2;
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  dv.setUint32(5, p.memoryKiB, false);
  dv.setUint32(9, p.time, false);
  out[13] = p.parallelism;
  out.set(salt, 14);
  out.set(publicKey, 30);
  out.set(pol, COMMON_SIZE);
  return out;
}

/**
 * Reads the header of a key file WITHOUT a password, version 1 or 2. Every refusal here is
 * cheap, happens before any crypto runs, and is a FormatError.
 */
export function parseHeader(file: Uint8Array): KeyHeader {
  if (file.length < 5) throw malformed("bad magic: not an archon key file");
  for (let i = 0; i < MAGIC.length; i++) {
    if (file[i] !== MAGIC[i]) throw malformed("bad magic: not an archon key file");
  }
  let policy: Policy | null = null;
  let size: number;
  if (file[4] === VERSION_1) {
    if (file.length !== V1_FILE_SIZE) throw malformed(`not ${V1_FILE_SIZE} bytes (got ${file.length})`);
    size = COMMON_SIZE;
  } else if (file[4] === VERSION_2) {
    if (file.length < MIN_V2_FILE_SIZE || file.length > MAX_V2_FILE_SIZE) {
      throw malformed(`a version-2 key file is ${MIN_V2_FILE_SIZE} to ${MAX_V2_FILE_SIZE} bytes (got ${file.length})`);
    }
    ({ policy, size } = parsePolicy(file));
  } else {
    throw new FormatError("unsupported", `unknown key file version ${file[4]}`);
  }
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const params: KeyParams = {
    memoryKiB: dv.getUint32(5, false),
    time: dv.getUint32(9, false),
    parallelism: file[13] as number,
  };
  try {
    checkParams(params);
  } catch (e) {
    throw malformed(e instanceof Error ? e.message : String(e));
  }
  return {
    version: file[4] as number,
    params,
    salt: file.slice(14, 30),
    publicKey: file.slice(30, COMMON_SIZE),
    policy,
    size,
  };
}

/**
 * Reads §8.1's policy and returns it with the header's length. The file must be exactly that
 * header, the nonce and the seal: nothing missing, nothing trailing.
 */
function parsePolicy(file: Uint8Array): { policy: Policy; size: number } {
  const mode = file[COMMON_SIZE] as number;
  const n = file[COMMON_SIZE + 1] as number;
  if (mode === POLICY_UNRESTRICTED && n !== 0) throw malformed(`an unrestricted policy lists no contexts (got ${n})`);
  if (mode === POLICY_ALLOWLIST && n > MAX_CONTEXTS) throw malformed(`at most ${MAX_CONTEXTS} contexts (got ${n})`);
  if (mode !== POLICY_UNRESTRICTED && mode !== POLICY_ALLOWLIST) throw malformed(`unknown policy mode ${mode}`);
  const end = file.length - NONCE_SIZE - SEAL_SIZE;
  let off = COMMON_SIZE + 2;
  const contexts: string[] = [];
  let previous: Uint8Array | null = null;
  for (let i = 0; i < n; i++) {
    if (off >= end || off + 1 + (file[off] as number) > end) throw malformed("the policy runs past the header");
    const length = file[off] as number;
    const raw = file.slice(off + 1, off + 1 + length);
    try {
      checkContext(raw);
    } catch (e) {
      throw malformed(`policy: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (previous !== null && compareBytes(previous, raw) >= 0) {
      throw malformed("policy contexts are not in strictly ascending order");
    }
    contexts.push(new TextDecoder().decode(raw));
    previous = raw;
    off += 1 + length;
  }
  if (off !== end) throw malformed("the file is not exactly the header it declares, a nonce and a seal");
  return { policy: { unrestricted: mode === POLICY_UNRESTRICTED, contexts }, size: off };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/**
 * Produces a version-2 file. `salt` and `nonce` are ARGUMENTS: the randomness is the
 * command's, never this function's, which is what makes the format pinnable.
 */
export function seal(
  seed: Uint8Array,
  password: string,
  salt: Uint8Array,
  nonce: Uint8Array,
  p: KeyParams,
  policy: Policy,
): Uint8Array {
  if (seed.length !== SEED_SIZE) throw new Error(`seed must be ${SEED_SIZE} bytes`);
  if (password.length === 0) throw new Error(EMPTY_PASSWORD);
  if (salt.length !== SALT_SIZE) throw new Error(`salt must be ${SALT_SIZE} bytes`);
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
  checkParams(p);
  // The writer's half of §8.1: the same rules the reader enforces, so nothing is written that
  // would not be read back.
  if (policy.unrestricted) {
    if (policy.contexts.length !== 0) throw new Error("an unrestricted policy lists no contexts");
  } else {
    const canonical = allowlist(policy.contexts).contexts;
    if (canonical.some((c, i) => c !== policy.contexts[i])) {
      throw new Error("policy contexts must be sorted: build them with allowlist()");
    }
  }
  const header = encodeHeader(p, salt, getPublicKey(seed), policy);
  const key = deriveKey(password, salt, p);
  const ciphertext = xchacha20poly1305(key, nonce, header).encrypt(seed);
  const out = new Uint8Array(header.length + NONCE_SIZE + SEAL_SIZE);
  out.set(header, 0);
  out.set(nonce, header.length);
  out.set(ciphertext, header.length + NONCE_SIZE);
  return out;
}

/**
 * `key policy`'s step 4 (§8.3): opens `file` — version 1 or 2 — and seals the same seed under
 * the same salt and parameters, the new policy and a fresh nonce. Always version 2.
 */
export function reseal(file: Uint8Array, password: string, nonce: Uint8Array, policy: Policy): Uint8Array {
  const header = parseHeader(file);
  const seed = open(file, password);
  try {
    return seal(seed, password, header.salt, nonce, header.params, policy);
  } finally {
    seed.fill(0);
  }
}

/**
 * Reverses seal(), for version 1 or 2, and then checks the decrypted seed against the header's
 * public key. The tag proves the bytes are ours, policy included; that check proves they are
 * CONSISTENT — a file can verify and still be refused. Whether a version-1 seed may be USED is
 * the command's decision (§8.2), not this function's.
 */
export function open(file: Uint8Array, password: string): Uint8Array {
  const header = parseHeader(file);
  if (password.length === 0) throw new Error(EMPTY_PASSWORD);
  const key = deriveKey(password, header.salt, header.params);
  const nonce = file.slice(header.size, header.size + NONCE_SIZE);
  let seed: Uint8Array;
  try {
    seed = xchacha20poly1305(key, nonce, file.slice(0, header.size)).decrypt(
      file.slice(header.size + NONCE_SIZE),
    );
  } catch {
    // One message for a wrong password and a tampered file alike: which of the two it was
    // is not something the holder of a bad password should learn.
    throw new Error("could not open: wrong password, or the file has been altered");
  }
  if (seed.length !== SEED_SIZE) throw new Error("the sealed plaintext is not a seed");
  if (!sameBytes(getPublicKey(seed), header.publicKey)) {
    throw new Error("the sealed seed does not derive the public key in the header");
  }
  return seed;
}

// ---------------------------------------------------------------------------
// Names — docs/keystore.md §5.
// ---------------------------------------------------------------------------

export const NAME_MAX_BYTES = 64;

// Refused bare AND with any extension: Windows treats CON.key as the device CON, so
// `archon key add CON.key` would name a file nobody can open.
const RESERVED_DEVICE_NAMES = new Set([
  "con", "prn", "aux", "nul",
  "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
  "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
]);

/**
 * Restricts rather than escapes: a name is a path segment on three operating systems, and
 * quoting it correctly on all of them is a harder problem than refusing the characters
 * that make it interesting. Throws with the reason; callers that only want a verdict use
 * isValidName.
 */
export function validateName(name: string): void {
  if (name.length === 0) throw new Error("a key name may not be empty");
  const bytes = new TextEncoder().encode(name);
  if (bytes.length > NAME_MAX_BYTES) {
    throw new Error(`a key name may be at most ${NAME_MAX_BYTES} bytes (got ${bytes.length})`);
  }
  if (name.startsWith(".")) {
    throw new Error('a key name may not begin with ".": it would hide the key');
  }
  // Windows strips a trailing dot, so `alice.` and `alice` would be one file on one OS and
  // two on another.
  if (name.endsWith(".")) throw new Error('a key name may not end with "."');
  for (const b of bytes) {
    const ok =
      (b >= 0x61 && b <= 0x7a) || (b >= 0x41 && b <= 0x5a) || (b >= 0x30 && b <= 0x39) ||
      b === 0x2e || b === 0x5f || b === 0x2d;
    if (!ok) {
      if (b < 0x20 || b === 0x7f) throw new Error("a key name may not contain control characters");
      throw new Error('a key name may contain only letters, digits, ".", "_" and "-"');
    }
  }
  const stem = (name.split(".")[0] ?? name).toLowerCase();
  if (RESERVED_DEVICE_NAMES.has(stem)) {
    throw new Error(
      `${JSON.stringify(name)} is a reserved device name on Windows, with or without an extension`,
    );
  }
}

export function isValidName(name: string): boolean {
  try {
    validateName(name);
    return true;
  } catch {
    return false;
  }
}
