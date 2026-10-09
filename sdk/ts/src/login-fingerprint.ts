// The transaction fingerprint a person compares before approving a login (docs/login.md §5.3).
//
// The page that began the login computes it from its own K and the begin response, in the
// browser; the CLI computes it from the exact request it is about to sign. So this module runs
// anywhere the package does: SHA-256 is @noble/hashes (as in request.ts), never node:crypto.
import { sha256 } from "@noble/hashes/sha2.js";

import { LOGIN_MAX_FIELD_SIZE, LOGIN_ROLE_LOGIN, loginBinding, type LoginRequest } from "./login.js";
import { MIN_NONCE_SIZE } from "./possession.js";

/**
 * The label the transaction fingerprint's digest is computed under (docs/login.md §5.3). It is
 * not an RFC 8032 context: nothing is signed with it, and no login proof's bytes are ever a
 * fingerprint's input or the other way round.
 */
export const FINGERPRINT_DOMAIN = "archon-login-fingerprint/1";

const DOMAIN_BYTES = new TextEncoder().encode(FINGERPRINT_DOMAIN);

/**
 * The login's transaction fingerprint (docs/login.md §5.3), what a person compares before
 * approving: the page that began the login computes it from its own K and the begin response,
 * the CLI from the exact request it is about to sign, and the two agree only if every field the
 * login proof binds — audience, K, id, scope, validity — and the nonce are the same on both
 * sides. It is the first 16 bytes (128 bits) of
 *
 *   SHA-256( u16be(len domain) ‖ domain ‖ u16be(len nonce) ‖ nonce ‖ loginBinding(LOGIN_ROLE_LOGIN, audience, req) )
 *
 * with domain `FINGERPRINT_DOMAIN` — an encoding of its own beside the proof's, pinned by
 * vectors/login.json's login_fingerprint family. Throws for everything
 * `loginBinding(LOGIN_ROLE_LOGIN, …)` throws for, and for a nonce shorter than `MIN_NONCE_SIZE`
 * or longer than the u16 prefix allows.
 */
export function fingerprint(audience: string, req: LoginRequest): Uint8Array {
  const binding = loginBinding(LOGIN_ROLE_LOGIN, audience, req);
  if (req.nonce.length < MIN_NONCE_SIZE || req.nonce.length > LOGIN_MAX_FIELD_SIZE) {
    throw new Error(`login: nonce is ${req.nonce.length} bytes, want ${MIN_NONCE_SIZE}..=${LOGIN_MAX_FIELD_SIZE}`);
  }
  const input = new Uint8Array(2 + DOMAIN_BYTES.length + 2 + req.nonce.length + binding.length);
  let at = putField(input, 0, DOMAIN_BYTES);
  at = putField(input, at, req.nonce);
  input.set(binding, at);
  return sha256(input).slice(0, 16);
}

/**
 * `fp` as a person reads and compares it (docs/login.md §5.3): its 32 lowercase hex digits in
 * eight groups of four, separated by single ASCII spaces — `7a91 b2c3 d4e5 f607 1829 3a4b 5c6d
 * 7e8f`. The three lanes spell it identically, so the page's rendering and the CLI's can be
 * compared character by character. Throws unless `fp` is exactly 16 bytes.
 */
export function formatFingerprint(fp: Uint8Array): string {
  if (fp.length !== 16) throw new Error(`login: fingerprint is ${fp.length} bytes, want 16`);
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(fp[i]!.toString(16).padStart(2, "0") + fp[i + 1]!.toString(16).padStart(2, "0"));
  }
  return groups.join(" ");
}

/** Writes u16be(len field) ‖ field at `at`; returns the new offset. */
function putField(out: Uint8Array, at: number, field: Uint8Array): number {
  out[at++] = (field.length >> 8) & 0xff;
  out[at++] = field.length & 0xff;
  out.set(field, at);
  return at + field.length;
}
