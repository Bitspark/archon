// Ed25519 sign / verify primitives (RFC 8032), generic — no authority vocabulary.
//
// Two ways to sign, deliberately:
//
// - `sign` / `verify` — RAW: pure Ed25519 over exactly the bytes given. The caller owns
//   separation; two protocols signing overlapping byte layouts with one key can replay
//   each other's signatures. This is what every consumer's on-disk signatures are today,
//   and it stays.
// - `signInDomain` / `verifyInDomain` — DOMAIN-SEPARATED: Ed25519ph with a context
//   string (RFC 8032 §5.1), the domain, mixed into the hash. A signature made in one
//   domain verifies in no other and never as a raw signature, and a raw signature
//   verifies in no domain — for every key the profile admits, by the construction and
//   not by any encoding convention. One key, many protocols, no cross-talk: the default
//   for any protocol that has no bytes on disk yet. The domain is the caller's
//   (`<repo>/<purpose>/v<n>` by convention); archon neither knows nor registers domains.
//
// Both verifies apply the verification profile (ADR 0008) before the equation: the
// public key and the signature's R must be canonical encodings of points of order
// exactly L — non-identity elements of the prime-order subgroup — and S must be in
// range. @noble with `{ zip215: false }` already refuses non-canonical encodings and
// small-order keys, but its equation is cofactored, so it accepts a mixed-order key for
// every message and a small-order R; Go and dalek, uncofactored, accept a mixed-order
// key for one message in eight and refuse a small-order R. The profile restricts the
// inputs to where the two equations agree, and is checked here explicitly so the
// accepted set is archon's, not the library's.
//
// Built on @noble/curves (which replaced @noble/ed25519 when domain separation landed:
// only the former exposes the Ed25519ph-with-context variant). Both are synchronous, so
// archon's LeafVerifier.verify stays synchronous, matching logos's sync SPI.
import { ed25519, ed25519ph } from "@noble/curves/ed25519.js";

/**
 * ADR 0008: `bytes` is a canonical encoding of a point of order exactly L. False for a
 * point not on the curve, a non-canonical spelling (y ≥ p, or x = 0 with the sign bit
 * set — @noble's strict decoder refuses both), the identity, any small-order point and
 * any mixed-order point. Point arithmetic is the library's; this is a check.
 */
function isPrimeOrderPoint(bytes: Uint8Array): boolean {
  if (bytes.length !== PUBLIC_KEY_SIZE) return false;
  try {
    const point = ed25519.Point.fromBytes(bytes, false);
    return !point.is0() && point.isTorsionFree();
  } catch {
    return false;
  }
}

/** The profile's shape conditions on a (key, signature) pair. S's range is @noble's. */
function inProfile(pub: Uint8Array, signature: Uint8Array): boolean {
  return (
    signature.length === SIGNATURE_SIZE &&
    pub.length === PUBLIC_KEY_SIZE &&
    isPrimeOrderPoint(pub) &&
    isPrimeOrderPoint(signature.subarray(0, PUBLIC_KEY_SIZE))
  );
}

/** Length of an Ed25519 public key, in bytes. Mirrors rs `PUBLIC_KEY_SIZE` / go `PublicKeySize`. */
export const PUBLIC_KEY_SIZE = 32;
/** Length of an Ed25519 signature, in bytes. Mirrors rs `SIGNATURE_SIZE` / go `SignatureSize`. */
export const SIGNATURE_SIZE = 64;
/** Length of an Ed25519 seed (private key), in bytes. Mirrors rs `SEED_SIZE` / go `SeedSize`. */
export const SEED_SIZE = 32;
/** The longest domain (RFC 8032 context) a signature can be made in, in bytes. */
export const MAX_DOMAIN_SIZE = 255;

/** Derive the 32-byte Ed25519 public key for a 32-byte seed. */
export function getPublicKey(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

/** Produce the 64-byte Ed25519 signature over `message` with the key from `seed`. */
export function sign(message: Uint8Array, seed: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}

/**
 * Verify a 64-byte Ed25519 `signature` over `message` against public key `pub`.
 *
 * Total: every shape failure (a signature that is not 64 bytes, a public key that is
 * not 32 bytes, or a malformed point) collapses to `false` rather than throwing — so
 * callers can treat all "bad signature" cases uniformly. This mirrors the Rust core's
 * `crypto::verify` (and Go's `crypto.Verify`), which shape-guard before delegating;
 * @noble's `verify` instead throws on a wrong-length input, so we guard the lengths and
 * wrap the call. (Issue #90: found by fast-check fuzzing.)
 *
 * `{ zip215: false }` selects @noble's strict decoding (canonical encodings only, no
 * small-order key), which issue #106 chose in the belief that Go's `crypto/ed25519` and
 * `ed25519-dalek` reject small-order keys. They do not — ADR 0008 measured it — and the
 * flag alone does not settle the accepted set either way, because @noble's equation is
 * cofactored and theirs is not. The profile check above is what settles it; the flag is
 * kept because it is the stricter decoder and costs nothing.
 */
export function verify(signature: Uint8Array, message: Uint8Array, pub: Uint8Array): boolean {
  if (!inProfile(pub, signature)) return false;
  try {
    return ed25519.verify(signature, message, pub, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Sign `message` with the key from `seed` IN `domain` (Ed25519ph with the domain as the
 * RFC 8032 context). Throws — never silently signs raw — when the domain is empty or
 * longer than `MAX_DOMAIN_SIZE` bytes: an empty domain is "sign in no domain", which is
 * exactly what this function exists to make impossible.
 */
export function signInDomain(seed: Uint8Array, domain: string, message: Uint8Array): Uint8Array {
  return ed25519ph.sign(message, seed, { context: domainBytes(domain) });
}

/**
 * Verify `signature` over `message` IN `domain` under `pub`. Total, like `verify`: every
 * shape failure — including an empty or over-long domain — is `false`. A raw signature
 * over the same message is `false` here; a signature from any other domain is `false`
 * here.
 */
export function verifyInDomain(
  pub: Uint8Array,
  domain: string,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (!inProfile(pub, signature)) return false;
  let context: Uint8Array;
  try {
    context = domainBytes(domain);
  } catch {
    return false;
  }
  try {
    return ed25519ph.verify(signature, message, pub, { context, zip215: false });
  } catch {
    return false;
  }
}

/**
 * A domain is 1..=255 bytes of UTF-8 — the RFC 8032 context bound, with the empty
 * context excluded on purpose (see `signInDomain`). A string that is not well-formed
 * (a lone surrogate) is refused rather than encoded: `TextEncoder` would silently
 * substitute U+FFFD, and a domain that changed on the way into the hash is not the
 * domain the caller named.
 */
function domainBytes(domain: string): Uint8Array {
  if (!isWellFormed(domain)) throw new Error("domain is not well-formed Unicode");
  const bytes = new TextEncoder().encode(domain);
  if (bytes.length === 0) throw new Error("domain is empty");
  if (bytes.length > MAX_DOMAIN_SIZE) {
    throw new Error(`domain is ${bytes.length} bytes, max ${MAX_DOMAIN_SIZE}`);
  }
  return bytes;
}

/**
 * `String.prototype.isWellFormed` without raising the compile target to ES2024: every
 * high surrogate is followed by a low one, and no low surrogate stands alone.
 */
function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}
