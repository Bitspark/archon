// Canonical key text — the v1 wire form for a public key.
//
// A public key is rendered as `"ed25519:" + lowercaseHex(pubkeyBytes)` and parsed by
// stripping that prefix and hex-decoding the body. This is the one human/CLI-facing
// spelling of a key; the three cores agree on it byte-for-byte so a key printed by one
// core round-trips through any other.

/** The v1 key-text scheme prefix. Exactly one scheme exists today (Ed25519). */
const ED25519_PREFIX = "ed25519:";

/** The fixed length, in bytes, of an Ed25519 public key. */
const PUBLIC_KEY_LEN = 32;

/** Encode public-key bytes as the canonical key text `ed25519:<lowercase-hex>`. */
export function encodeKey(pubkey: Uint8Array): string {
  let hex = "";
  for (const b of pubkey) {
    hex += b.toString(16).padStart(2, "0");
  }
  return ED25519_PREFIX + hex;
}

/**
 * Decode canonical key text back to its raw public-key bytes. Strips the `ed25519:`
 * prefix and hex-decodes the body. Throws (never returns a partial result) when the
 * prefix is missing, the body is not even-length hex, or the decoded length is not 32
 * bytes.
 */
export function decodeKey(text: string): Uint8Array {
  if (!text.startsWith(ED25519_PREFIX)) {
    throw new Error(`missing '${ED25519_PREFIX}' prefix`);
  }
  const body = text.slice(ED25519_PREFIX.length);
  if (body.length % 2 !== 0) {
    throw new Error("key body has an odd number of hex digits");
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseHexByte(body, i * 2);
    out[i] = byte;
  }
  if (out.length !== PUBLIC_KEY_LEN) {
    throw new Error(`decoded key is ${out.length} bytes, expected ${PUBLIC_KEY_LEN}`);
  }
  return out;
}

/** Parse the two hex digits at `pos` into a byte, throwing on any non-hex character. */
function parseHexByte(body: string, pos: number): number {
  const hi = hexDigit(body.charCodeAt(pos));
  const lo = hexDigit(body.charCodeAt(pos + 1));
  return (hi << 4) | lo;
}

/** Map one ASCII hex-digit char code (either case) to its nibble value. */
function hexDigit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10; // A-F
  throw new Error(`non-hex character ${JSON.stringify(String.fromCharCode(code))} in key body`);
}
