// The signed envelope — THESE BYTES, SIGNED BY THIS KEY, IN THIS DOMAIN.
//
// A fixed binary container, JWS-shaped and deliberately not JWT-shaped:
//
//   "arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ signature[64] ‖ payload
//
// where `signature = signInDomain(seed, domain, SCHEME_TAG ‖ payload)`. The domain is
// bound cryptographically (it is the RFC 8032 context), the public key is bound by
// verification, and the payload is opaque: the envelope says nothing about what it
// means. WHAT IS NOT HERE, ON PURPOSE: expiry, issuer, audience, key-id, nonce. Each is
// either policy — whose clock, whose trust? — or a second spelling of the key, and both
// belong to the consumer.
//
// `open` takes the domain the VERIFIER expects and refuses an envelope that claims
// another. The verifier chooses the domain; an envelope never gets to choose it for
// them. Whether to trust the key it names is, again, the verifier's.
import {
  getPublicKey,
  signInDomain,
  verifyInDomain,
  MAX_DOMAIN_SIZE,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE,
} from "@bitspark/archon";

/** The first four bytes of every envelope. */
export const ENVELOPE_MAGIC = new Uint8Array([0x61, 0x72, 0x63, 0x6e]); // "arcn"
/** The envelope format version. */
export const ENVELOPE_VERSION = 0x01;
/** The first byte of every signed envelope message. Distinct from the possession `SCHEME_TAG`. */
export const ENVELOPE_SCHEME_TAG = 0x02;

/** What `open` returns: the sealing key and the payload, both verified. */
export interface Opened {
  /** The public key that sealed the envelope. Trusting it is the caller's decision. */
  pubkey: Uint8Array;
  /** The payload, verbatim. */
  payload: Uint8Array;
}

/**
 * Seal `payload` in `domain` with the key behind `seed`. Throws on an invalid domain (see
 * `signInDomain`). An empty payload is allowed — the signed message is never empty
 * because of the scheme tag.
 */
export function seal(seed: Uint8Array, domain: string, payload: Uint8Array): Uint8Array {
  const signature = signInDomain(seed, domain, envelopeMessageBytes(payload));
  const pubkey = getPublicKey(seed);
  const d = new TextEncoder().encode(domain);
  const out = new Uint8Array(4 + 1 + 1 + d.length + PUBLIC_KEY_SIZE + SIGNATURE_SIZE + payload.length);
  let at = 0;
  out.set(ENVELOPE_MAGIC, at);
  at += 4;
  out[at++] = ENVELOPE_VERSION;
  out[at++] = d.length; // ≤ 255: signInDomain has already checked it
  out.set(d, at);
  at += d.length;
  out.set(pubkey, at);
  at += PUBLIC_KEY_SIZE;
  out.set(signature, at);
  at += SIGNATURE_SIZE;
  out.set(payload, at);
  return out;
}

/**
 * Open `envelope`, which the caller expects to be sealed in `domain`. Throws — never
 * returns a payload — when the bytes are not an envelope (magic, version, length), the
 * envelope claims a different domain, or the signature does not verify.
 */
export function open(envelope: Uint8Array, domain: string): Opened {
  let at = 0;
  const take = (n: number): Uint8Array => {
    if (at + n > envelope.length) throw new Error(`envelope truncated at byte ${envelope.length}`);
    const s = envelope.subarray(at, at + n);
    at += n;
    return s;
  };
  const magic = take(4);
  if (!ENVELOPE_MAGIC.every((b, i) => magic[i] === b)) throw new Error("not an envelope: bad magic");
  const version = take(1)[0]!;
  if (version !== ENVELOPE_VERSION) throw new Error(`unsupported envelope version ${version}`);
  const dlen = take(1)[0]!;
  if (dlen === 0 || dlen > MAX_DOMAIN_SIZE) throw new Error(`envelope domain length ${dlen} out of range`);
  const claimed = take(dlen);
  const expected = new TextEncoder().encode(domain);
  if (claimed.length !== expected.length || !expected.every((b, i) => claimed[i] === b)) {
    throw new Error("envelope claims a different domain");
  }
  const pubkey = new Uint8Array(take(PUBLIC_KEY_SIZE));
  const signature = take(SIGNATURE_SIZE);
  const payload = new Uint8Array(envelope.subarray(at));
  if (!verifyInDomain(pubkey, domain, envelopeMessageBytes(payload), signature)) {
    throw new Error("envelope signature does not verify");
  }
  return { pubkey, payload };
}

/** The pinned layout of what gets signed: the scheme tag, then the payload verbatim. */
export function envelopeMessageBytes(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + payload.length);
  out[0] = ENVELOPE_SCHEME_TAG;
  out.set(payload, 1);
  return out;
}
