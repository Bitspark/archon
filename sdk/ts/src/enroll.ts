// Key enrollment — THIS NEW KEY BELONGS TO THIS ACCOUNT (ADR 0010 §7; docs/request.md §6,
// PROVISIONAL until ADR 0010 §8's gate is met).
//
// Login has a person approve a browser key. Enrollment is a different statement: a NEW key
// proves its own possession, while a separate authority — a session, or a bootstrap credential
// — says whose key it becomes. That authority lives in the service's pending transaction
// record, never in this proof: the service creates the record only after validating the
// authority, and the verifier rebuilds the binding from that record and its configured
// audience. A completion request names the transaction and carries the proof, nothing more.
//
// The proof is the possession scheme with the server's fresh nonce, in ENROLL_DOMAIN, over
//
//   version ‖ u16be(len purpose) ‖ purpose ‖ u16be(len audience) ‖ audience
//           ‖ u16be(len transaction) ‖ transaction ‖ new_key[32] ‖ intent_digest[32]
//
// The intent digest is the service's SHA-256 of its immutable enrollment intent; archon binds
// the 32 bytes and never reads what they digest. Enrollment shows that an account and a key are
// associated — not that the key is non-exportable, lives on one device, or is used by one
// process.
import { getPublicKey, PUBLIC_KEY_SIZE, SEED_SIZE } from "@bitspark/archon";

import {
  completePossession,
  MAX_FIELD_SIZE as POSSESSION_MAX_FIELD_SIZE,
  preparePossession,
  provePossession,
  verifyPossession,
} from "./possession.js";
import { signWith, type Signer, type SigningRequest } from "./signer.js";

/** The RFC 8032 context every enrollment proof is made in. */
export const ENROLL_DOMAIN = "archon-enroll/1";

/** The first byte of every enrollment binding. */
export const ENROLL_VERSION = 0x01;

/** The longest purpose, in bytes. */
export const ENROLL_MAX_PURPOSE_SIZE = 255;

/** The longest transaction id, in bytes. */
export const ENROLL_MAX_TRANSACTION_SIZE = 255;

/** The intent digest's length: a SHA-256. */
export const ENROLL_DIGEST_SIZE = 32;

/** A pending enrollment as the service recorded it. */
export interface EnrollRequest {
  /** The server's fresh entropy, at least the possession scheme's 16 bytes. */
  nonce: Uint8Array;
  /** The pending transaction's id, 1..=255 bytes, opaque. */
  transaction: Uint8Array;
  /** "add-key", "rotate", "recover", …: 1..=255 bytes of UTF-8, no control characters. */
  purpose: string;
  /** The public key being enrolled, exactly PUBLIC_KEY_SIZE bytes. */
  newKey: Uint8Array;
  /** SHA-256 of the service's immutable intent bytes, exactly ENROLL_DIGEST_SIZE bytes. */
  intentDigest: Uint8Array;
}

const utf8 = new TextEncoder();

/**
 * The bytes an enrollment proof is bound to, for `req` at `audience`. Throws on a purpose that
 * is empty, over 255 bytes, not UTF-8 or carrying a control character (U+0000–U+001F, U+007F);
 * an audience that is empty, not UTF-8 or carrying a control character; a transaction id that
 * is empty or over 255 bytes; a new key or intent digest of the wrong size; or a binding that
 * would not fit the possession scheme's u16 field.
 */
export function enrollBinding(audience: string, req: EnrollRequest): Uint8Array {
  const purpose = checkText("purpose", req.purpose);
  if (purpose.length > ENROLL_MAX_PURPOSE_SIZE) {
    throw new Error(`enroll: purpose is ${purpose.length} bytes, want 1..=${ENROLL_MAX_PURPOSE_SIZE}`);
  }
  const aud = checkText("audience", audience);
  if (req.transaction.length === 0 || req.transaction.length > ENROLL_MAX_TRANSACTION_SIZE) {
    throw new Error(`enroll: transaction is ${req.transaction.length} bytes, want 1..=${ENROLL_MAX_TRANSACTION_SIZE}`);
  }
  if (req.newKey.length !== PUBLIC_KEY_SIZE) {
    throw new Error(`enroll: new key is ${req.newKey.length} bytes, want ${PUBLIC_KEY_SIZE}`);
  }
  if (req.intentDigest.length !== ENROLL_DIGEST_SIZE) {
    throw new Error(`enroll: intent digest is ${req.intentDigest.length} bytes, want ${ENROLL_DIGEST_SIZE}`);
  }
  const size = 1 + 2 + purpose.length + 2 + aud.length + 2 + req.transaction.length + PUBLIC_KEY_SIZE + ENROLL_DIGEST_SIZE;
  if (size > POSSESSION_MAX_FIELD_SIZE) {
    throw new Error(`enroll: binding is ${size} bytes, over the possession scheme's ${POSSESSION_MAX_FIELD_SIZE}`);
  }
  const out = new Uint8Array(size);
  let at = 0;
  out[at++] = ENROLL_VERSION;
  at = putField(out, at, purpose);
  at = putField(out, at, aud);
  at = putField(out, at, req.transaction);
  out.set(req.newKey, at);
  at += PUBLIC_KEY_SIZE;
  out.set(req.intentDigest, at);
  return out;
}

/**
 * The enrollment proof: possession by the key behind `seed` — which must be `req.newKey` — in
 * ENROLL_DOMAIN, over `req.nonce` and `enrollBinding(audience, req)`. Throws for what the binding
 * throws, for a short nonce, for a seed of the wrong size, and for a seed that is not the new
 * key: only the key being enrolled can prove it holds itself.
 */
export function proveEnroll(seed: Uint8Array, audience: string, req: EnrollRequest): Uint8Array {
  if (seed.length !== SEED_SIZE) throw new Error(`enroll: seed is ${seed.length} bytes, want ${SEED_SIZE}`);
  const pub = getPublicKey(seed);
  if (pub.length !== req.newKey.length || !pub.every((b, i) => b === req.newKey[i])) {
    throw new Error("enroll: seed is not the new key the request names");
  }
  return provePossession(seed, ENROLL_DOMAIN, req.nonce, enrollBinding(audience, req));
}

/** Whether `signature` is the enrollment proof by `req.newKey` for `req` at `audience`. Total. */
export function verifyEnroll(audience: string, req: EnrollRequest, signature: Uint8Array): boolean {
  let binding: Uint8Array;
  try {
    binding = enrollBinding(audience, req);
  } catch {
    return false;
  }
  return verifyPossession(req.newKey, ENROLL_DOMAIN, req.nonce, binding, signature);
}

/**
 * The signing request the enrollment proof needs (ADR 0009 §4). Pure. The expected key is
 * `req.newKey`, so only that key's signer can complete it — `proveEnroll`'s refusal of any other
 * seed, carried into the request itself. Complete it with `completePossession`.
 */
export function prepareEnroll(audience: string, req: EnrollRequest): SigningRequest {
  return preparePossession(req.newKey, ENROLL_DOMAIN, req.nonce, enrollBinding(audience, req));
}

/** `proveEnroll` through a signer instead of a seed. A signer for any other key is refused. */
export async function proveEnrollWith(
  signer: Signer,
  audience: string,
  req: EnrollRequest,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const request = prepareEnroll(audience, req);
  return completePossession(request, await signWith(signer, request, signal));
}

/** Throws unless `s` is non-empty, well-formed UTF-8 (no lone surrogate) with no control
 *  character; returns its UTF-8 bytes. */
function checkText(what: string, s: string): Uint8Array {
  if (!isWellFormed(s)) throw new Error(`enroll: ${what} is not well-formed UTF-16 (a lone surrogate is not UTF-8)`);
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20 || cp === 0x7f) {
      throw new Error(`enroll: ${what} carries a control character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    }
  }
  const bytes = utf8.encode(s);
  if (bytes.length === 0 || bytes.length > POSSESSION_MAX_FIELD_SIZE) {
    throw new Error(`enroll: ${what} is ${bytes.length} bytes, want 1..=${POSSESSION_MAX_FIELD_SIZE}`);
  }
  return bytes;
}

function isWellFormed(s: string): boolean {
  const native = (s as unknown as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof native === "function") return native.call(s);
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

/** Writes u16be(len field) ‖ field at `at`; returns the new offset. */
function putField(out: Uint8Array, at: number, field: Uint8Array): number {
  out[at++] = (field.length >> 8) & 0xff;
  out[at++] = field.length & 0xff;
  out.set(field, at);
  return at + field.length;
}
