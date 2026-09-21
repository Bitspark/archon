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
//   verifies in no domain — cryptographically, whatever the bytes. One key, many
//   protocols, no cross-talk: the default for any protocol that has no bytes on disk yet.
//   The domain is the caller's (`<repo>/<purpose>/v<n>` by convention); archon neither
//   knows nor registers domains.
//
// Built on @noble/curves (which replaced @noble/ed25519 when domain separation landed:
// only the former exposes the Ed25519ph-with-context variant). Both are synchronous, so
// archon's LeafVerifier.verify stays synchronous, matching logos's sync SPI.
import { ed25519, ed25519ph } from "@noble/curves/ed25519.js";

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
 * `{ zip215: false }` selects RFC 8032 semantics: @noble defaults to ZIP-215
 * (cofactored) verification, which *accepts* small-order public keys, whereas Go's
 * `crypto/ed25519` and Rust's `ed25519-dalek` v2 *reject* them. Passing `zip215: false`
 * makes the TS core reject small-order keys identically, restoring tri-core parity so
 * the canonical Rust core and the TS core admit exactly the same signed-fact / Head
 * evidence. (Issue #106.)
 */
export function verify(signature: Uint8Array, message: Uint8Array, pub: Uint8Array): boolean {
  if (signature.length !== SIGNATURE_SIZE || pub.length !== PUBLIC_KEY_SIZE) return false;
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
  if (signature.length !== SIGNATURE_SIZE || pub.length !== PUBLIC_KEY_SIZE) return false;
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
 * context excluded on purpose (see `signInDomain`).
 */
function domainBytes(domain: string): Uint8Array {
  const bytes = new TextEncoder().encode(domain);
  if (bytes.length === 0) throw new Error("domain is empty");
  if (bytes.length > MAX_DOMAIN_SIZE) {
    throw new Error(`domain is ${bytes.length} bytes, max ${MAX_DOMAIN_SIZE}`);
  }
  return bytes;
}
