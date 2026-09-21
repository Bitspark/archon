// The archon key store's file format — docs/keystore.md, ADR 0007 §A.
//
// A fixed 134-byte layout, identical across cli/{rs,go,ts} and pinned by
// vectors/keystore.json:
//
//   "arck" ‖ version ‖ u32be(m KiB) ‖ u32be(t) ‖ u8(p) ‖ salt[16] ‖ pubkey[32]  header, 62
//   nonce[24]
//   XChaCha20Poly1305(seed[32], aad = header)                                    48 with tag
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

// Follows the envelope's "arcn" ‖ version (sdk/{go,rs,ts}). It is what stops a 134-byte
// non-key file being LISTED as a key: `key list` reads the header without a password, so
// it is the one place a wrong file would be believed.
export const MAGIC = new Uint8Array([0x61, 0x72, 0x63, 0x6b]); // "arck"
export const VERSION = 0x01;

export const SALT_SIZE = 16;
export const NONCE_SIZE = 24;
export const SEED_SIZE = 32;
export const PUBLIC_KEY_SIZE = 32;
export const HEADER_SIZE = 4 + 1 + 4 + 4 + 1 + SALT_SIZE + PUBLIC_KEY_SIZE; // 62
export const FILE_SIZE = HEADER_SIZE + NONCE_SIZE + SEED_SIZE + 16; // 134

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
 * The authenticated prefix of a key file. `publicKey` is readable without a password —
 * that is what `key list` prints — but it is only a CLAIM until an unlock verifies the tag
 * over this header and re-derives it from the seed.
 */
export type KeyHeader = { params: KeyParams; salt: Uint8Array; publicKey: Uint8Array };

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

export function encodeHeader(h: KeyHeader): Uint8Array {
  const out = new Uint8Array(HEADER_SIZE);
  out.set(MAGIC, 0);
  out[4] = VERSION;
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  dv.setUint32(5, h.params.memoryKiB, false);
  dv.setUint32(9, h.params.time, false);
  out[13] = h.params.parallelism;
  out.set(h.salt, 14);
  out.set(h.publicKey, 30);
  return out;
}

/**
 * Reads the header of a key file WITHOUT a password. Every refusal here is cheap and
 * happens before any crypto runs.
 */
export function parseHeader(file: Uint8Array): KeyHeader {
  if (file.length !== FILE_SIZE) throw new Error(`not ${FILE_SIZE} bytes (got ${file.length})`);
  for (let i = 0; i < MAGIC.length; i++) {
    if (file[i] !== MAGIC[i]) throw new Error("bad magic: not an archon key file");
  }
  if (file[4] !== VERSION) throw new Error(`unknown key file version ${file[4]}`);
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const params: KeyParams = {
    memoryKiB: dv.getUint32(5, false),
    time: dv.getUint32(9, false),
    parallelism: file[13] as number,
  };
  if (params.memoryKiB === 0 || params.time === 0 || params.parallelism === 0) {
    throw new Error("argon2id parameters in the header are not usable");
  }
  return {
    params,
    salt: file.slice(14, 30),
    publicKey: file.slice(30, HEADER_SIZE),
  };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/**
 * Produces the 134 bytes. `salt` and `nonce` are ARGUMENTS: the randomness is the
 * command's, never this function's, which is what makes the format pinnable.
 */
export function seal(
  seed: Uint8Array,
  password: string,
  salt: Uint8Array,
  nonce: Uint8Array,
  p: KeyParams,
): Uint8Array {
  if (seed.length !== SEED_SIZE) throw new Error(`seed must be ${SEED_SIZE} bytes`);
  if (password.length === 0) throw new Error(EMPTY_PASSWORD);
  if (salt.length !== SALT_SIZE) throw new Error(`salt must be ${SALT_SIZE} bytes`);
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
  const header = encodeHeader({ params: p, salt, publicKey: getPublicKey(seed) });
  const key = deriveKey(password, salt, p);
  const ciphertext = xchacha20poly1305(key, nonce, header).encrypt(seed);
  const out = new Uint8Array(FILE_SIZE);
  out.set(header, 0);
  out.set(nonce, HEADER_SIZE);
  out.set(ciphertext, HEADER_SIZE + NONCE_SIZE);
  return out;
}

/**
 * Reverses seal() and then checks the decrypted seed against the header's public key. The
 * tag proves the bytes are ours; that check proves they are CONSISTENT — a file can verify
 * and still be refused.
 */
export function open(file: Uint8Array, password: string): Uint8Array {
  const header = parseHeader(file);
  if (password.length === 0) throw new Error(EMPTY_PASSWORD);
  const key = deriveKey(password, header.salt, header.params);
  const nonce = file.slice(HEADER_SIZE, HEADER_SIZE + NONCE_SIZE);
  let seed: Uint8Array;
  try {
    seed = xchacha20poly1305(key, nonce, file.slice(0, HEADER_SIZE)).decrypt(
      file.slice(HEADER_SIZE + NONCE_SIZE),
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
