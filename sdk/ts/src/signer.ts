// The signer contract — SIGNING CAPABILITY, NOT SEEDS (ADR 0009 §2–4).
//
// Every helper in this package can take a seed, which is right for a key held in software
// and wrong for one that is not: a stored key behind `archon sign --key`, or any backend a
// caller wires in. So each signing helper also comes in three parts — a PURE prepare (the
// exact request it needs signed), the signer's own work, and a PURE complete (the checked
// signature, then packaging) — with a convenience that runs the signer between them. The
// seed functions are unchanged and stay synchronous.
//
// A request is three things, and the scheme is a discriminated value, never a scheme name
// plus an optional domain: the public key the caller expects, raw Ed25519 or Ed25519ph with
// the domain as the RFC 8032 context, and the ORIGINAL message bytes — never a digest; a
// backend that wants a prehash computes it inside its own adapter.
//
// Three rules, all enforced here rather than trusted to a signer:
//
// - A request is validated BEFORE the signer is invoked: a wrong-length key or a domain the
//   floor refuses never reaches it.
// - A signer REPORTS what it can do, and a request outside that is refused before it is
//   invoked. A signer that cannot carry a context declares raw only; it must never sign an
//   Ed25519ph request with an empty context instead, and if it does anyway, the check below
//   catches it.
// - Every returned signature is VERIFIED against the requested key, scheme, domain and bytes
//   — never against values the signer echoes back. That catches a wrong key, a dropped
//   context, raw substituted for ph, and a wrong prehash adaptation. It does not prove that a
//   signer signs deterministically (ADR 0008 §1.7 requires it); that is a property of the
//   backend, tested against the `domain_sign` vectors, not something one signature can show.
//
// Domain separation is not authorization: whoever may ask for signatures in a domain gets
// any signature in that domain. Consent belongs to the caller that knows what the bytes mean.
import {
  getPublicKey,
  sign,
  signInDomain,
  verify,
  verifyInDomain,
  PUBLIC_KEY_SIZE,
  SEED_SIZE,
  SIGNATURE_SIZE,
} from "@bitspark/archon";

/** Raw Ed25519 over the message, or Ed25519ph with the domain as the RFC 8032 context. */
export type SigningScheme =
  | { readonly kind: "ed25519-raw" }
  | { readonly kind: "ed25519ph-context"; readonly domain: string };

/** What a signer is asked to sign. `message` is always the original bytes. */
export interface SigningRequest {
  readonly expectedPublicKey: Uint8Array;
  readonly scheme: SigningScheme;
  readonly message: Uint8Array;
}

/** What a signer can do. `domains`, when present, is the only set it will sign in. */
export interface SignerCapabilities {
  readonly schemes: readonly SigningScheme["kind"][];
  readonly domains?: readonly string[];
}

/**
 * A source of signatures. `sign` may prompt, call a subprocess or wait on a device; it is
 * given the abort signal, and a signature it returns after the signal fired is discarded,
 * never packaged.
 */
export interface Signer {
  readonly publicKey: Uint8Array;
  readonly capabilities: SignerCapabilities;
  sign(request: SigningRequest, signal?: AbortSignal): Promise<Uint8Array>;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Throws unless `request` is in range: a 32-byte expected key, a known scheme, and — for
 * Ed25519ph — a domain the floor accepts. The domain is checked by the floor's own rule (it
 * signs nothing with a throwaway key), so no copy of ADR 0008 §2 lives here to drift.
 */
export function validateSigningRequest(request: SigningRequest): void {
  if (!(request.expectedPublicKey instanceof Uint8Array) || request.expectedPublicKey.length !== PUBLIC_KEY_SIZE) {
    throw new Error(`signer: the expected public key must be ${PUBLIC_KEY_SIZE} bytes`);
  }
  if (!(request.message instanceof Uint8Array)) throw new Error("signer: the message must be bytes");
  const scheme = request.scheme as { kind?: unknown; domain?: unknown };
  if (scheme.kind === "ed25519-raw") {
    if ("domain" in scheme) throw new Error("signer: a raw request carries no domain");
    return;
  }
  if (scheme.kind !== "ed25519ph-context") throw new Error(`signer: unknown scheme ${JSON.stringify(scheme.kind)}`);
  if (typeof scheme.domain !== "string") throw new Error("signer: an ed25519ph-context request needs a domain");
  signInDomain(new Uint8Array(SEED_SIZE), scheme.domain, new Uint8Array(0));
}

/**
 * Throws unless `signature` verifies for exactly what was REQUESTED: its key, scheme, domain
 * and original bytes.
 */
export function checkSignature(request: SigningRequest, signature: Uint8Array): void {
  validateSigningRequest(request);
  const ok =
    signature instanceof Uint8Array &&
    signature.length === SIGNATURE_SIZE &&
    (request.scheme.kind === "ed25519-raw"
      ? verify(signature, request.message, request.expectedPublicKey)
      : verifyInDomain(request.expectedPublicKey, request.scheme.domain, request.message, signature));
  if (!ok) {
    throw new Error("signer: the signature does not verify for the requested key, scheme and message");
  }
}

/**
 * Throws unless `signer` claims to be able to sign `request`: its key is the expected one,
 * and the scheme and domain are among its capabilities. Called before it is invoked.
 */
export function checkCapability(signer: Signer, request: SigningRequest): void {
  if (!sameBytes(signer.publicKey, request.expectedPublicKey)) {
    throw new Error("signer: this signer's key is not the expected key");
  }
  const caps = signer.capabilities;
  if (!caps.schemes.includes(request.scheme.kind)) {
    throw new Error(`signer: this signer cannot produce ${request.scheme.kind}`);
  }
  if (request.scheme.kind === "ed25519ph-context" && caps.domains !== undefined && !caps.domains.includes(request.scheme.domain)) {
    throw new Error(`signer: this signer does not sign in domain ${JSON.stringify(request.scheme.domain)}`);
  }
}

/**
 * Validates, checks the signer's capabilities, invokes it, and returns the signature only
 * if the call was not aborted and the signature verifies for what was requested.
 */
export async function signWith(signer: Signer, request: SigningRequest, signal?: AbortSignal): Promise<Uint8Array> {
  validateSigningRequest(request);
  checkCapability(signer, request);
  signal?.throwIfAborted();
  const signature = await signer.sign(request, signal);
  signal?.throwIfAborted();
  checkSignature(request, signature);
  return new Uint8Array(signature);
}

/**
 * The software signer: a seed held in this process, both schemes, any domain the floor
 * accepts, deterministic by the floor's construction. The seed is copied.
 */
export function seedSigner(seed: Uint8Array): Signer {
  if (seed.length !== SEED_SIZE) throw new Error(`signer: seed is ${seed.length} bytes, want ${SEED_SIZE}`);
  const held = new Uint8Array(seed);
  return {
    publicKey: getPublicKey(held),
    capabilities: { schemes: ["ed25519-raw", "ed25519ph-context"] },
    sign: (request) =>
      Promise.resolve(
        request.scheme.kind === "ed25519-raw"
          ? sign(request.message, held)
          : signInDomain(held, request.scheme.domain, request.message),
      ),
  };
}
