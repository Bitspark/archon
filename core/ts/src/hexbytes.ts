// Typed, fail-closed hex spellings for the three fixed-size values the floor deals in:
// a 32-byte seed, a 32-byte public key, a 64-byte signature.
//
// Every consumer hand-wrote these — `hexToBytes`, `bytesToHex`, `seed32` — around its
// archon calls, ~50 definitions in the ts lane alone, each one a place for a length
// bug. The value here is not hex (every language has hex) but the FIXED SIZE: a decoder
// that returns exactly 32 or 64 bytes or throws, never an array the caller must
// re-check. Encoding is always lowercase; decoding accepts either case. No `0x` prefix,
// no whitespace — a spelling is a spelling.
import { PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE } from "./crypto.js";

/** Render bytes as lowercase hex, two digits per byte. */
export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Decode the hex spelling of a 32-byte Ed25519 seed. Throws on odd length, any non-hex
 * character, or a decoded length other than 32.
 */
export function seedFromHex(text: string): Uint8Array {
  return fixed(text, SEED_SIZE, "seed");
}

/** Decode the hex spelling of a 32-byte Ed25519 public key. Same failure rules as `seedFromHex`. */
export function pubkeyFromHex(text: string): Uint8Array {
  return fixed(text, PUBLIC_KEY_SIZE, "public key");
}

/** Decode the hex spelling of a 64-byte Ed25519 signature. Same failure rules as `seedFromHex`. */
export function signatureFromHex(text: string): Uint8Array {
  return fixed(text, SIGNATURE_SIZE, "signature");
}

/**
 * Decode hex into exactly `n` bytes or throw. The length is checked on the text before
 * any byte is decoded, so a wrong-sized input never allocates.
 */
function fixed(text: string, n: number, what: string): Uint8Array {
  if (text.length !== n * 2) {
    throw new Error(`${what} hex is ${text.length} characters, expected ${n * 2}`);
  }
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = (hexDigit(text.charCodeAt(2 * i)) << 4) | hexDigit(text.charCodeAt(2 * i + 1));
  }
  return out;
}

/** Map one ASCII hex-digit char code (either case) to its nibble value. */
function hexDigit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10; // A-F
  throw new Error(`non-hex character ${JSON.stringify(String.fromCharCode(code))}`);
}
