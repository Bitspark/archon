// The archon login scheme — MAY THIS EPHEMERAL KEY ACT AS ME, HERE, FOR THIS, UNTIL THEN?
//
// A browser (any key-less client) holds an ephemeral key K and opens a request at a service;
// the person's CLI, holding P, proves to that service that P agrees to let K act there for a
// stated scope and validity. The proof is the possession scheme (./possession.ts) in the
// domain `LOGIN_DOMAIN`, over the server's nonce and a binding that names everything the
// person approved: the audience the CLI talks to, K, the request, the scope entries and the
// validity — see docs/login.md §3.
//
// THE AUDIENCE IS DERIVED, NEVER TRANSPORTED: the CLI takes it from the URL it was invoked
// with and the server from its own configuration (docs/login.md §2). This module takes it as
// an argument and binds it; it never reads it off a message. Everything this module refuses
// to source — the nonce, the id, K, clocks, the delegation's contents, custody, sockets — is
// an argument or another layer's (ADR 0004, ADR 0007).
//
// Two proofs share the layout and differ in a role byte: the login proof (0x01) is made by P;
// the collect proof (0x02) is made by K when the browser collects the answer, so a bystander
// who saw the request id cannot consume the login.
import { getPublicKey, PUBLIC_KEY_SIZE, SEED_SIZE } from "@bitspark/archon";

import { MAX_FIELD_SIZE as POSSESSION_MAX_FIELD_SIZE, provePossession, verifyPossession } from "./possession.js";

/** The RFC 8032 context every login-scheme proof is made in. */
export const LOGIN_DOMAIN = "archon-login/1";

/** The binding's first byte for the person's proof (made by P). */
export const LOGIN_ROLE_LOGIN = 0x01;

/** The binding's first byte for the browser's collect proof (made by K). */
export const LOGIN_ROLE_COLLECT = 0x02;

/**
 * The longest audience, id or scope entry, in bytes — the u16 length prefix's bound. It also
 * bounds the scope entry count and the whole binding (which must fit the possession scheme's
 * own u16 field).
 */
export const LOGIN_MAX_FIELD_SIZE = 0xffff;

/**
 * A pending login as the server issued it and the CLI reads it back (docs/login.md §3.1).
 * The nonce is validated by the possession scheme (≥ 16 bytes) at proof time; the other
 * fields by `loginBinding`.
 */
export interface LoginRequest {
  /** The server's, opaque, 1..=LOGIN_MAX_FIELD_SIZE bytes. */
  id: Uint8Array;
  /** The server's fresh entropy, one per request. */
  nonce: Uint8Array;
  /** K's public key, exactly PUBLIC_KEY_SIZE bytes. */
  browser: Uint8Array;
  /** Ordered; each 1..=LOGIN_MAX_FIELD_SIZE bytes of UTF-8 with no control characters. */
  scope: string[];
  /** The delegation's requested lifetime in seconds, > 0 (a u32). */
  validFor: number;
}

const utf8 = new TextEncoder();

/**
 * The bytes both proofs are bound to, for `role` over `audience` and `req` (docs/login.md
 * §3.2):
 *
 *   role ‖ u16be(len audience) ‖ audience ‖ browser[32] ‖ u16be(len id) ‖ id
 *        ‖ u16be(count scope) ‖ ( u16be(len entry) ‖ entry )* ‖ u32be(valid_for)
 *
 * Throws on an unknown role, an empty or oversized audience, an audience or scope entry
 * carrying a control character (U+0000–U+001F, U+007F) or a lone surrogate (not UTF-8), an
 * empty scope entry, a browser key of the wrong size, an empty or oversized id, a validity
 * that is not an integer in 1..=2^32-1, or a binding that would not fit the possession
 * scheme's u16 field.
 */
export function loginBinding(role: number, audience: string, req: LoginRequest): Uint8Array {
  if (role !== LOGIN_ROLE_LOGIN && role !== LOGIN_ROLE_COLLECT) throw new Error(`login: unknown role 0x${role.toString(16)}`);
  const aud = checkText("audience", audience);
  if (req.browser.length !== PUBLIC_KEY_SIZE) {
    throw new Error(`login: browser key is ${req.browser.length} bytes, want ${PUBLIC_KEY_SIZE}`);
  }
  if (req.id.length === 0 || req.id.length > LOGIN_MAX_FIELD_SIZE) {
    throw new Error(`login: id is ${req.id.length} bytes, want 1..=${LOGIN_MAX_FIELD_SIZE}`);
  }
  if (req.scope.length > LOGIN_MAX_FIELD_SIZE) {
    throw new Error(`login: ${req.scope.length} scope entries, want at most ${LOGIN_MAX_FIELD_SIZE}`);
  }
  const entries = req.scope.map((entry, i) => checkText(`scope[${i}]`, entry));
  if (!Number.isInteger(req.validFor) || req.validFor < 1 || req.validFor > 0xffffffff) {
    throw new Error(`login: valid_for is ${req.validFor}, want an integer in 1..=4294967295`);
  }

  let size = 1 + 2 + aud.length + PUBLIC_KEY_SIZE + 2 + req.id.length + 2 + 4;
  for (const e of entries) size += 2 + e.length;
  if (size > POSSESSION_MAX_FIELD_SIZE) {
    throw new Error(`login: binding is ${size} bytes, over the possession scheme's ${POSSESSION_MAX_FIELD_SIZE}`);
  }
  const out = new Uint8Array(size);
  let at = 0;
  out[at++] = role;
  at = putField(out, at, aud);
  out.set(req.browser, at);
  at += PUBLIC_KEY_SIZE;
  at = putField(out, at, req.id);
  out[at++] = (entries.length >> 8) & 0xff;
  out[at++] = entries.length & 0xff;
  for (const e of entries) at = putField(out, at, e);
  out[at++] = (req.validFor >>> 24) & 0xff;
  out[at++] = (req.validFor >>> 16) & 0xff;
  out[at++] = (req.validFor >>> 8) & 0xff;
  out[at++] = req.validFor & 0xff;
  return out;
}

/**
 * The person's login proof: possession by the key behind `seed`, in `LOGIN_DOMAIN`, over
 * `req.nonce` and `loginBinding(LOGIN_ROLE_LOGIN, audience, req)`. Throws for what
 * `loginBinding` throws, for a short nonce, and for a seed of the wrong size.
 */
export function proveLogin(seed: Uint8Array, audience: string, req: LoginRequest): Uint8Array {
  if (seed.length !== SEED_SIZE) throw new Error(`login: seed is ${seed.length} bytes, want ${SEED_SIZE}`);
  return provePossession(seed, LOGIN_DOMAIN, req.nonce, loginBinding(LOGIN_ROLE_LOGIN, audience, req));
}

/**
 * Whether `signature` is the login proof by the key behind `pub` for `req` at `audience`.
 * Total: every shape failure is `false`.
 */
export function verifyLogin(pub: Uint8Array, audience: string, req: LoginRequest, signature: Uint8Array): boolean {
  let binding: Uint8Array;
  try {
    binding = loginBinding(LOGIN_ROLE_LOGIN, audience, req);
  } catch {
    return false;
  }
  return verifyPossession(pub, LOGIN_DOMAIN, req.nonce, binding, signature);
}

/**
 * The browser's collect proof: possession by the key behind `seed` — which must be the key
 * `req` names as `browser` — in `LOGIN_DOMAIN`, over `req.nonce` and
 * `loginBinding(LOGIN_ROLE_COLLECT, audience, req)`. A seed whose public key is not
 * `req.browser` throws: the proof is only meaningful from the key the request names.
 */
export function proveCollect(seed: Uint8Array, audience: string, req: LoginRequest): Uint8Array {
  if (seed.length !== SEED_SIZE) throw new Error(`login: seed is ${seed.length} bytes, want ${SEED_SIZE}`);
  const pub = getPublicKey(seed);
  if (pub.length !== req.browser.length || !pub.every((b, i) => b === req.browser[i])) {
    throw new Error("login: seed is not the browser key the request names");
  }
  return provePossession(seed, LOGIN_DOMAIN, req.nonce, loginBinding(LOGIN_ROLE_COLLECT, audience, req));
}

/** Whether `signature` is the collect proof by `req.browser` for `req` at `audience`. Total. */
export function verifyCollect(audience: string, req: LoginRequest, signature: Uint8Array): boolean {
  let binding: Uint8Array;
  try {
    binding = loginBinding(LOGIN_ROLE_COLLECT, audience, req);
  } catch {
    return false;
  }
  return verifyPossession(req.browser, LOGIN_DOMAIN, req.nonce, binding, signature);
}

/**
 * The rule shared by the audience and every scope entry: 1..=LOGIN_MAX_FIELD_SIZE bytes of
 * well-formed UTF-8 with no control character (U+0000–U+001F, U+007F). These bytes are
 * displayed verbatim by the CLI before signing; a control character could make the display
 * lie about what is bound. Returns the UTF-8 bytes.
 */
function checkText(what: string, s: string): Uint8Array {
  if (!isWellFormed(s)) throw new Error(`login: ${what} is not well-formed UTF-16 (a lone surrogate is not UTF-8)`);
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20 || cp === 0x7f) {
      throw new Error(`login: ${what} carries a control character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    }
  }
  const bytes = utf8.encode(s);
  if (bytes.length === 0 || bytes.length > LOGIN_MAX_FIELD_SIZE) {
    throw new Error(`login: ${what} is ${bytes.length} bytes, want 1..=${LOGIN_MAX_FIELD_SIZE}`);
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
