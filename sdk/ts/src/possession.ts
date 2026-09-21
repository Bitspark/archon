// Proof of possession — CAN THEY SIGN, RIGHT NOW, FOR THIS CHANNEL?
//
// The challenger picks a `nonce` (fresh entropy, ≥ 16 bytes — its own, never this
// package's) and a `binding` (something only this channel has: a session key, a TLS
// exporter, the server's identity — the transport's, never this package's). The prover
// signs a fixed layout of both in the protocol's domain; the challenger verifies with the
// prover's public key.
//
// THE BINDING IS WHAT MAKES THIS A PROOF. A signed nonce alone is relayable: an attacker
// facing the server as the victim forwards the server's nonce to the victim under some
// pretext, gets it signed, and presents the signature. Bound to the channel, the
// signature is worthless anywhere else. So an empty binding is refused outright — the
// thing it would produce looks like a proof and is not one.
//
// The signed bytes are `SCHEME_TAG ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖
// binding`, signed with `signInDomain` in the caller's domain. The tag keeps a
// possession message and an envelope payload in the same domain from ever being the
// same bytes.
import { signInDomain, verifyInDomain } from "@bitspark/archon";

/** The first byte of every possession message. Distinct from the envelope's `SCHEME_TAG`. */
export const POSSESSION_SCHEME_TAG = 0x01;
/** The shortest nonce accepted, in bytes. Below this a proof is guessable, so it is refused. */
export const MIN_NONCE_SIZE = 16;
/** The longest nonce or binding, in bytes — the u16 length prefix's bound. */
export const MAX_FIELD_SIZE = 0xffff;

/**
 * Prove possession of the key behind `seed` to a challenger who supplied `nonce` and
 * `binding`, in `domain`. Throws on an invalid domain (see `signInDomain`), a nonce
 * shorter than `MIN_NONCE_SIZE`, an empty binding, or either field over `MAX_FIELD_SIZE`.
 */
export function provePossession(
  seed: Uint8Array,
  domain: string,
  nonce: Uint8Array,
  binding: Uint8Array,
): Uint8Array {
  return signInDomain(seed, domain, possessionMessageBytes(nonce, binding));
}

/**
 * Verify a possession proof: `signature` was made by the key behind `pub` over this
 * `nonce` and `binding` in `domain`. Total: every shape failure — bad domain, short
 * nonce, empty binding, wrong-sized key or signature — is `false`.
 */
export function verifyPossession(
  pub: Uint8Array,
  domain: string,
  nonce: Uint8Array,
  binding: Uint8Array,
  signature: Uint8Array,
): boolean {
  let message: Uint8Array;
  try {
    message = possessionMessageBytes(nonce, binding);
  } catch {
    return false;
  }
  return verifyInDomain(pub, domain, message, signature);
}

/** The pinned layout of what gets signed. Exported so a consumer can pin it too. */
export function possessionMessageBytes(nonce: Uint8Array, binding: Uint8Array): Uint8Array {
  if (nonce.length < MIN_NONCE_SIZE) throw new Error(`nonce is ${nonce.length} bytes, min ${MIN_NONCE_SIZE}`);
  if (nonce.length > MAX_FIELD_SIZE) throw new Error(`nonce is ${nonce.length} bytes, max ${MAX_FIELD_SIZE}`);
  if (binding.length === 0) throw new Error("binding is empty — an unbound proof is not a proof");
  if (binding.length > MAX_FIELD_SIZE) throw new Error(`binding is ${binding.length} bytes, max ${MAX_FIELD_SIZE}`);
  const out = new Uint8Array(1 + 2 + nonce.length + 2 + binding.length);
  let at = 0;
  out[at++] = POSSESSION_SCHEME_TAG;
  out[at++] = nonce.length >> 8;
  out[at++] = nonce.length & 0xff;
  out.set(nonce, at);
  at += nonce.length;
  out[at++] = binding.length >> 8;
  out[at++] = binding.length & 0xff;
  out.set(binding, at);
  return out;
}
