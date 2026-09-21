// PKCS#8/SPKI PEM key codec (ed25519-key-codec-v1, spec Appendix A.8). Pure, IO-free
// conversions between raw 32-byte Ed25519 keys/seeds and the two standard PEM containers —
// PKCS#8 v1 (private) and SPKI (public). A byte codec, NOT key custody (archon ADR 0002): no key is
// held, no file is read, no randomness is drawn. The DER is fixed-size, so encode is a
// constant prefix followed by the 32 key bytes and decode is a bounded template match. Decode
// is PEM-only and total — it throws on any shape it does not recognize, never returns garbage.
// PKCS#8 is v1-only; v2 is rejected. Byte-pinned across the three cores by the `keycodec`
// conformance family.
//
// base64 is hand-rolled (not Node's lenient `Buffer.from(_, "base64")`, which silently strips
// invalid characters) so the strict accept/reject set matches the Go/Rust cores exactly. The
// codec is synchronous, like the rest of the core (WebCrypto's PKCS#8 import is async).

const KEY_LEN = 32;

// SubjectPublicKeyInfo header for an Ed25519 public key (the first 12 bytes of the 44-byte
// DER): SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING(0 unused) { pubkey } }. The
// trailing 0x00 is the unused-bits octet.
const SPKI_PREFIX = Uint8Array.of(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00);
// PKCS#8 v1 PrivateKeyInfo header for an Ed25519 seed (the first 16 bytes of the 48-byte DER):
// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }.
// Version 0 = v1 (no embedded public key).
const PKCS8_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);

const PEM_PUBLIC = "PUBLIC KEY";
const PEM_PRIVATE = "PRIVATE KEY";

/** Encode a 32-byte Ed25519 public key as SPKI PEM (`-----BEGIN PUBLIC KEY-----`). */
export function pubkeyToSpkiPem(pubkey: Uint8Array): string {
  return encode(pubkey, SPKI_PREFIX, PEM_PUBLIC);
}

/** Encode a 32-byte Ed25519 seed as PKCS#8 v1 PEM (`-----BEGIN PRIVATE KEY-----`). */
export function seedToPkcs8Pem(seed: Uint8Array): string {
  return encode(seed, PKCS8_PREFIX, PEM_PRIVATE);
}

/** Decode SPKI PEM back to the raw 32-byte Ed25519 public key. Throws on malformed input. */
export function spkiPemToPubkey(pem: string): Uint8Array {
  return decode(pem, SPKI_PREFIX, PEM_PUBLIC);
}

/** Decode PKCS#8 v1 PEM back to the raw 32-byte Ed25519 seed. Throws on malformed input. */
export function pkcs8PemToSeed(pem: string): Uint8Array {
  return decode(pem, PKCS8_PREFIX, PEM_PRIVATE);
}

function encode(key: Uint8Array, prefix: Uint8Array, pemType: string): string {
  if (key.length !== KEY_LEN) throw new Error(`keycodec: key must be ${KEY_LEN} bytes, got ${key.length}`);
  const der = new Uint8Array(prefix.length + KEY_LEN);
  der.set(prefix, 0);
  der.set(key, prefix.length);
  return `-----BEGIN ${pemType}-----\n${base64Encode(der)}\n-----END ${pemType}-----\n`;
}

function decode(pem: string, prefix: Uint8Array, pemType: string): Uint8Array {
  const trimmed = pem.replace(/\r\n/g, "\n").replace(/\n+$/, "");
  const begin = `-----BEGIN ${pemType}-----`;
  const end = `-----END ${pemType}-----`;
  const lines = trimmed.split("\n");
  if (lines.length < 3 || lines[0] !== begin || lines[lines.length - 1] !== end) {
    throw new Error(`keycodec: not a "${pemType}" PEM block`);
  }
  const der = base64Decode(lines.slice(1, -1).join(""));
  if (der.length !== prefix.length + KEY_LEN || !startsWith(der, prefix)) {
    throw new Error(`keycodec: DER does not match the ${pemType} ed25519-key-codec-v1 template`);
  }
  return der.slice(prefix.length);
}

function startsWith(a: Uint8Array, prefix: Uint8Array): boolean {
  if (a.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i += 1) if (a[i] !== prefix[i]) return false;
  return true;
}

// ----- base64 (RFC 4648 standard alphabet, with padding) — matches Go/Rust strictly -----

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64Encode(data: Uint8Array): string {
  let out = "";
  for (let i = 0; i < data.length; i += 3) {
    const b0 = data[i] ?? 0;
    const b1 = data[i + 1] ?? 0; // 0 past the end; the `has*` guards below control padding
    const b2 = data[i + 2] ?? 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < data.length ? B64[((b1 & 0x0f) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < data.length ? B64[b2 & 0x3f] : "=";
  }
  return out;
}

function b64Val(c: number): number {
  if (c >= 65 && c <= 90) return c - 65; // A-Z
  if (c >= 97 && c <= 122) return c - 97 + 26; // a-z
  if (c >= 48 && c <= 57) return c - 48 + 52; // 0-9
  if (c === 43) return 62; // +
  if (c === 47) return 63; // /
  throw new Error(`keycodec: invalid base64 character ${JSON.stringify(String.fromCharCode(c))}`);
}

function base64Decode(s: string): Uint8Array {
  if (s.length % 4 !== 0) throw new Error("keycodec: base64 length is not a multiple of 4");
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 4) {
    const c2 = s.charCodeAt(i + 2);
    const c3 = s.charCodeAt(i + 3);
    const v0 = b64Val(s.charCodeAt(i));
    const v1 = b64Val(s.charCodeAt(i + 1));
    out.push((v0 << 2) | (v1 >> 4));
    if (c2 === 61 /* = */) {
      if (c3 !== 61 || i + 4 !== s.length) throw new Error("keycodec: malformed base64 padding");
    } else {
      const v2 = b64Val(c2);
      out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
      if (c3 === 61 /* = */) {
        if (i + 4 !== s.length) throw new Error("keycodec: malformed base64 padding");
      } else {
        out.push(((v2 & 0x03) << 6) | b64Val(c3));
      }
    }
  }
  return Uint8Array.from(out);
}
