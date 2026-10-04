// Request authentication — THIS KEY MADE THIS HTTP REQUEST (ADR 0010 §2–§6; docs/request.md
// §3–§5 and §7, version 1, fixed by ADR 0010's status note of 4 October 2026).
//
// archon's RFC 9421 application profile: the client signs the RFC 9421 signature base directly,
// in domain REQUEST_DOMAIN, with archon's construction (Ed25519ph with the domain as the RFC 8032
// context), and `alg` is never sent — the registered `ed25519` is pure Ed25519. The coverage is
// fixed: the method, the full target URI, the configured audience as a CHECKED ECHO, a SHA-256
// Content-Digest, Content-Type if present, and every product-declared header the request carries.
//
// This file is the sdk's part (ADR 0010 §1): the transcript, the strict parsing, the coverage
// rule and pure verification. Time is an argument, as everywhere in this package. What it does
// NOT do is remember: one-use enforcement (the replay store) and the HTTP extraction belong to the
// server adapters, so a VerifiedRequest is a proof that checked out, not yet a request that may
// reach an application.
import { sha256 } from "@noble/hashes/sha2.js";
import { decodeKey, encodeKey, getPublicKey, signInDomain, verifyInDomain, PUBLIC_KEY_SIZE } from "@bitspark/archon";

import { checkSignature, signWith, type Signer, type SigningRequest } from "./signer.js";

/** The RFC 8032 context every request signature is made in. */
export const REQUEST_DOMAIN = "archon-request/1";
/** The `tag` signature parameter; a verifier accepts only this. */
export const REQUEST_TAG = "archon-request/1";
/** The one dictionary member in Signature-Input and Signature. */
export const REQUEST_LABEL = "archon";
/** The nonce's least and greatest size, in bytes. */
export const REQUEST_MIN_NONCE_SIZE = 16;
export const REQUEST_MAX_NONCE_SIZE = 64;
/** The longest request-target, and the longest covered value, in bytes. */
export const REQUEST_MAX_TARGET_SIZE = 8192;
export const REQUEST_MAX_VALUE_SIZE = 8192;
/** The largest integer the profile spells: 15 digits. */
export const REQUEST_MAX_INT = 999_999_999_999_999;

/** What a client signs. `declared` holds the product-declared headers the request carries, in
 *  the product's declared order, names in lowercase. */
export interface RequestToSign {
  method: string;
  audience: string;
  requestTarget: string;
  body: Uint8Array;
  contentType?: string | undefined;
  declared: ReadonlyArray<readonly [string, string]>;
  created: number;
  expires: number;
  nonce: Uint8Array;
}

/** The four headers archon adds to a request, named in lowercase. */
export interface RequestHeaders {
  "archon-audience": string;
  "content-digest": string;
  "signature-input": string;
  signature: string;
}

/** A request prepared for a signer: the base it will sign, and the signing request. */
export interface PreparedRequest {
  base: string;
  signing: SigningRequest;
  headers: Omit<RequestHeaders, "signature">;
}

/** What a verifier is configured with. */
export interface RequestPolicy {
  audience: string;
  declared: readonly string[];
  /** W: the longest acceptable `expires − created`, in seconds. */
  maxLifetime: number;
  /** δ: the clock tolerance, in seconds. */
  skew: number;
}

/** A request as the server received it: the method, the raw request-target, every header field
 *  in the order received (names in any case), and the body after transfer framing. */
export interface ReceivedRequest {
  method: string;
  requestTarget: string;
  headers: ReadonlyArray<readonly [string, string]>;
  body: Uint8Array;
}

/** A proof that checked out under the policy at `now`. Not yet replay-checked. */
export interface VerifiedRequest {
  principal: Uint8Array;
  keyText: string;
  created: number;
  expires: number;
  nonce: Uint8Array;
  method: string;
  targetUri: string;
  /** Every covered field, in coverage order, with the value that was verified. */
  covered: Array<[string, string]>;
  contentDigest: Uint8Array;
}

const utf8 = new TextEncoder();
const TCHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const VISIBLE = /^[\x21-\x7e]+$/;
const RESERVED = new Set(["archon-audience", "content-digest", "content-type", "signature-input", "signature"]);

/** The origin of an audience, or a throw: docs/request.md §3.1. */
export function requestOrigin(audience: string): string {
  if (!VISIBLE.test(audience)) throw new Error("request: the audience is not visible ASCII");
  const m = /^(https?:\/\/)([^/]*)(\/.*)?$/.exec(audience);
  if (m === null) throw new Error("request: the audience is not an http or https URL");
  const authority = m[2]!;
  if (authority === "" || authority.includes("@")) throw new Error("request: the audience's authority is empty or carries userinfo");
  if (/[?#]/.test(audience)) throw new Error("request: the audience carries a query or a fragment");
  if (audience.endsWith("/")) throw new Error("request: the audience ends in /");
  return m[1]! + authority;
}

function checkMethod(method: string): void {
  if (!TCHAR.test(method)) throw new Error("request: the method is not a token");
}

function checkTarget(target: string): void {
  if (target.length === 0 || target.length > REQUEST_MAX_TARGET_SIZE) throw new Error("request: the request-target's length");
  if (!target.startsWith("/") || !VISIBLE.test(target) || target.includes("#")) {
    throw new Error("request: the request-target is not origin form");
  }
}

/** A covered value, trimmed of leading and trailing SP and HTAB, or a throw. */
function coveredValue(value: string): string {
  const v = value.replace(/^[ \t]+|[ \t]+$/g, "");
  if (v.length === 0 || v.length > REQUEST_MAX_VALUE_SIZE || !/^[\t\x20-\x7e]+$/.test(v)) {
    throw new Error("request: a covered value is empty, too long, or not visible ASCII, SP and HTAB");
  }
  return v;
}

function checkDeclaredName(name: string): void {
  if (!/^[a-z0-9-]+$/.test(name) || RESERVED.has(name)) throw new Error(`request: ${JSON.stringify(name)} cannot be a declared header`);
}

function checkInt(n: number, what: string): void {
  if (!Number.isInteger(n) || n < 0 || n > REQUEST_MAX_INT) throw new Error(`request: ${what} is not an integer in 0..=${REQUEST_MAX_INT}`);
}

function checkNonce(nonce: Uint8Array): void {
  if (nonce.length < REQUEST_MIN_NONCE_SIZE || nonce.length > REQUEST_MAX_NONCE_SIZE) {
    throw new Error(`request: the nonce is ${nonce.length} bytes, want ${REQUEST_MIN_NONCE_SIZE}..=${REQUEST_MAX_NONCE_SIZE}`);
  }
}

/** The RFC 9421 signature base: one `"<name>": <value>` line per covered component, then
 *  `"@signature-params": <inner list>` with no trailing line feed (docs/request.md §4). */
export function requestSignatureBase(components: ReadonlyArray<readonly [string, string]>, innerList: string): string {
  return components.map(([n, v]) => `"${n}": ${v}\n`).join("") + `"@signature-params": ${innerList}`;
}

function contentDigestHeader(body: Uint8Array): string {
  return `sha-256=:${b64Encode(sha256(body), B64, true)}:`;
}

/** The base and headers for `input`, for a signer whose key is `publicKey`. Pure; throws on any
 *  value outside docs/request.md §3.1. */
export function prepareRequest(publicKey: Uint8Array, input: RequestToSign): PreparedRequest {
  if (publicKey.length !== PUBLIC_KEY_SIZE) throw new Error("request: the public key is not 32 bytes");
  checkMethod(input.method);
  const origin = requestOrigin(input.audience);
  checkTarget(input.requestTarget);
  checkInt(input.created, "created");
  checkInt(input.expires, "expires");
  if (input.created >= input.expires) throw new Error("request: created must be before expires");
  checkNonce(input.nonce);
  const digest = contentDigestHeader(input.body);
  const components: Array<[string, string]> = [
    ["@method", input.method],
    ["@target-uri", origin + input.requestTarget],
    ["archon-audience", input.audience],
    ["content-digest", digest],
  ];
  if (input.contentType !== undefined) components.push(["content-type", coveredValue(input.contentType)]);
  const seen = new Set<string>();
  for (const [name, value] of input.declared) {
    checkDeclaredName(name);
    if (seen.has(name)) throw new Error(`request: ${name} is declared twice`);
    seen.add(name);
    components.push([name, coveredValue(value)]);
  }
  const keyText = encodeKey(publicKey);
  const inner =
    `(${components.map(([n]) => `"${n}"`).join(" ")});created=${input.created};expires=${input.expires}` +
    `;nonce="${b64Encode(input.nonce, B64URL, false)}";keyid="${keyText}";tag="${REQUEST_TAG}"`;
  const base = requestSignatureBase(components, inner);
  return {
    base,
    signing: { expectedPublicKey: publicKey, scheme: { kind: "ed25519ph-context", domain: REQUEST_DOMAIN }, message: utf8.encode(base) },
    headers: { "archon-audience": input.audience, "content-digest": digest, "signature-input": `${REQUEST_LABEL}=${inner}` },
  };
}

/** The headers, from a signature over a prepared request: checked against it first. Pure. */
export function completeRequest(prepared: PreparedRequest, signature: Uint8Array): RequestHeaders {
  checkSignature(prepared.signing, signature);
  return { ...prepared.headers, signature: `${REQUEST_LABEL}=:${b64Encode(signature, B64, true)}:` };
}

/** Sign `input` with the key behind `seed`: the base, and the four headers to send. */
export function signRequest(seed: Uint8Array, input: RequestToSign): { base: string; headers: RequestHeaders } {
  const prepared = prepareRequest(getPublicKey(seed), input);
  const signature = signInDomain(seed, REQUEST_DOMAIN, prepared.signing.message);
  return { base: prepared.base, headers: completeRequest(prepared, signature) };
}

/** `signRequest` through a signer instead of a seed. */
export async function signRequestWith(signer: Signer, input: RequestToSign, signal?: AbortSignal): Promise<RequestHeaders> {
  const prepared = prepareRequest(signer.publicKey, input);
  return completeRequest(prepared, await signWith(signer, prepared.signing, signal));
}

const SIGNATURE_INPUT =
  /^archon=\(("[^"]*"(?: "[^"]*")*)\);created=(0|[1-9][0-9]{0,14});expires=(0|[1-9][0-9]{0,14});nonce="([A-Za-z0-9_-]+)";keyid="([^"\\]*)";tag="archon-request\/1"$/;
const SIGNATURE = /^archon=:([A-Za-z0-9+/=]+):$/;
const CONTENT_DIGEST = /^sha-256=:([A-Za-z0-9+/=]+):$/;

/**
 * Verify `received` under `policy` at `now` (seconds since the epoch): docs/request.md §7 steps
 * 1–7. Throws on any refusal; returns what was verified. It does not check replay: a server
 * adapter must insert (REQUEST_TAG, audience, principal, nonce) into its replay store before the
 * request reaches an application.
 */
export function verifyRequest(policy: RequestPolicy, now: number, received: ReceivedRequest): VerifiedRequest {
  const origin = requestOrigin(policy.audience);
  const declared = new Set<string>();
  for (const d of policy.declared) {
    checkDeclaredName(d);
    if (declared.has(d)) throw new Error(`request: ${d} is declared twice`);
    declared.add(d);
  }
  checkInt(policy.maxLifetime, "max_lifetime");
  if (policy.maxLifetime < 1) throw new Error("request: max_lifetime must be at least 1");
  checkInt(policy.skew, "skew");
  checkInt(now, "now");

  const fields = new Map<string, string[]>();
  for (const [name, value] of received.headers) {
    // ASCII case folding only: HTTP field names are tokens, and Unicode folding would turn
    // U+212A KELVIN SIGN into `k` — a different header in a lane that folds ASCII only.
    const key = name.replace(/[A-Z]/g, (ch) => ch.toLowerCase());
    const list = fields.get(key) ?? [];
    list.push(value.replace(/^[ \t]+|[ \t]+$/g, ""));
    fields.set(key, list);
  }
  const once = (name: string): string => {
    const list = fields.get(name);
    if (list === undefined || list.length !== 1) throw new Error(`request: ${name} must appear exactly once`);
    return list[0]!;
  };

  // 1. The two proof fields parse, in their one spelling.
  const si = SIGNATURE_INPUT.exec(once("signature-input"));
  if (si === null) throw new Error("request: Signature-Input is not the profile's spelling");
  const sigText = SIGNATURE.exec(once("signature"));
  if (sigText === null) throw new Error("request: Signature is not the profile's spelling");
  const signature = b64Decode(sigText[1]!, B64, true);
  if (signature.length !== 64) throw new Error("request: the signature is not 64 bytes");
  const names = si[1]!.split(" ").map((q) => q.slice(1, -1));
  const created = Number(si[2]);
  const expires = Number(si[3]);
  const nonce = b64Decode(si[4]!, B64URL, false);
  checkNonce(nonce);

  // 2. keyid is a canonical principal (the tag was matched by the grammar).
  const keyText = si[5]!;
  let principal: Uint8Array;
  try {
    principal = decodeKey(keyText);
  } catch {
    throw new Error("request: keyid is not a principal");
  }
  if (encodeKey(principal) !== keyText) throw new Error("request: keyid is not the canonical key text");

  // 3. The coverage is exactly §3.1's, for what this request carries.
  const expected = ["@method", "@target-uri", "archon-audience", "content-digest"];
  if (fields.has("content-type")) expected.push("content-type");
  for (const d of policy.declared) if (fields.has(d)) expected.push(d);
  if (names.length !== expected.length || names.some((n, i) => n !== expected[i])) {
    throw new Error("request: the coverage is not the profile's for this request");
  }
  checkMethod(received.method);
  checkTarget(received.requestTarget);
  const components: Array<[string, string]> = [];
  for (const n of names) {
    if (n === "@method") components.push([n, received.method]);
    else if (n === "@target-uri") components.push([n, origin + received.requestTarget]);
    else components.push([n, coveredValue(once(n))]);
  }

  // 4. The audience echo is the configured audience, byte for byte.
  if (once("archon-audience") !== policy.audience) throw new Error("request: Archon-Audience is not the configured audience");

  // 5. The digest is the received content's.
  const cd = CONTENT_DIGEST.exec(once("content-digest"));
  if (cd === null) throw new Error("request: Content-Digest is not the profile's spelling");
  const contentDigest = b64Decode(cd[1]!, B64, true);
  const actual = sha256(received.body);
  if (contentDigest.length !== actual.length || contentDigest.some((b, i) => b !== actual[i])) {
    throw new Error("request: Content-Digest does not match the content");
  }

  // 6. Freshness: 0 < e − c ≤ W and c − δ ≤ now < e + δ.
  if (!(created < expires && expires - created <= policy.maxLifetime)) throw new Error("request: the lifetime is out of bounds");
  if (!(created - policy.skew <= now && now < expires + policy.skew)) throw new Error("request: not fresh at now");

  // 7. The signature, over the base built from what was received and configured.
  const base = requestSignatureBase(components, si[0].slice(REQUEST_LABEL.length + 1));
  if (!verifyInDomain(principal, REQUEST_DOMAIN, utf8.encode(base), signature)) throw new Error("request: the signature does not verify");

  return {
    principal,
    keyText,
    created,
    expires,
    nonce,
    method: received.method,
    targetUri: origin + received.requestTarget,
    covered: components.filter(([n]) => !n.startsWith("@")),
    contentDigest,
  };
}

// ---------------------------------------------------------------------------------------------
// base64, both alphabets, accepted only in their one canonical spelling (docs/request.md §3.1):
// decoding and re-encoding must give back the same text.
// ---------------------------------------------------------------------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64Encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((bytes.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += alphabet[(n >> (18 - 6 * j)) & 63];
    if (pad) out += "=".repeat(4 - chars);
  }
  return out;
}

function b64Decode(text: string, alphabet: string, pad: boolean): Uint8Array {
  const body = pad ? text.replace(/=+$/, "") : text;
  const bytes: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of body) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new Error("request: not base64");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 0xff);
    }
  }
  const out = new Uint8Array(bytes);
  if (b64Encode(out, alphabet, pad) !== text) throw new Error("request: not the canonical base64 spelling");
  return out;
}
