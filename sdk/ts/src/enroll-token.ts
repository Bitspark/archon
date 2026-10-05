// `archon enroll`'s formats (docs/enroll.md §2–§3, ADR 0013): the intent in format 1, which a
// service builds and the command renders, and the two tokens a person carries by hand between
// the signed-in page and the command. The proof never reads an intent; these are for the
// command, which must show the person which account a key joins before it signs.
//
// Pinned by vectors/enroll.json.
import { PUBLIC_KEY_SIZE } from "@bitspark/archon";
import { sha256 } from "@noble/hashes/sha2.js";

import { ENROLL_MAX_TRANSACTION_SIZE, type EnrollRequest } from "./enroll.js";
import { displayUnsafe } from "./login-display.js";
import { MIN_NONCE_SIZE } from "./possession.js";

/** The first byte of an intent in format 1. */
export const ENROLL_INTENT_FORMAT = 0x01;
/** The shortest blind: 128 bits, so the digest cannot confirm a guess. */
export const ENROLL_MIN_BLIND_SIZE = 16;
/** The longest blind. */
export const ENROLL_MAX_BLIND_SIZE = 64;
/** The longest account id, account name, purpose or restriction, in bytes. */
export const ENROLL_MAX_TEXT_SIZE = 255;
/** The most restrictions an intent holds. */
export const ENROLL_MAX_RESTRICTIONS = 32;
/** The challenge token's prefix. */
export const ENROLL_CHALLENGE_PREFIX = "archon-enroll-challenge-1:";
/** The proof token's prefix. */
export const ENROLL_PROOF_PREFIX = "archon-enroll-proof-1:";
/** The longest token, in bytes of text, surrounding whitespace excluded. */
export const ENROLL_MAX_TOKEN_SIZE = 65536;
/** The longest nonce a challenge token carries. */
export const ENROLL_MAX_NONCE_SIZE = 255;
/** The longest intent a challenge token carries. */
export const ENROLL_MAX_INTENT_SIZE = 0xffff;
/** The possession signature's length. */
export const ENROLL_PROOF_SIZE = 64;
/** 9999-12-31T23:59:59Z in Unix seconds: every lane renders it, and it fits in 53 bits. */
export const ENROLL_MAX_DEADLINE = 253402300799;

/**
 * An enrollment intent in format 1. The service builds it from its own validated records; the
 * command decodes it and shows it. Every text field is 1..=255 bytes of UTF-8 with no
 * display-unsafe code point (`displayUnsafe`).
 */
export interface EnrollIntent {
  /** 16..=64 bytes from a CSPRNG, fresh for every intent. */
  blind: Uint8Array;
  /** The service's identifier for the account. */
  accountId: string;
  /** The account's unique name, such as its sign-in handle: never a free display name. */
  accountName: string;
  /** The binding's purpose. */
  purpose: string;
  /** 0..=32 lines, in order. */
  restrictions: string[];
}

/** The challenge token's content. `intent` is the exact intent bytes; the token's codec checks
 *  only its own fields, and `enrollChallengeRequest` decodes the intent. */
export interface EnrollChallenge {
  audience: string;
  /** 1..=255 bytes. */
  transaction: Uint8Array;
  /** 16..=255 bytes. */
  nonce: Uint8Array;
  /** The key the record enrolls. */
  newKey: Uint8Array;
  /** 1..=65535 bytes. */
  intent: Uint8Array;
  /** The record's expiry in whole Unix seconds, 0..=ENROLL_MAX_DEADLINE. */
  deadline: number;
}

/** The proof token's content: what the command prints and the service reads back. */
export interface EnrollProof {
  /** 1..=255 bytes. */
  transaction: Uint8Array;
  /** The key that proved. */
  newKey: Uint8Array;
  /** The possession signature, 64 bytes. */
  proof: Uint8Array;
}

const utf8 = new TextEncoder();
// fatal: refuse what is not UTF-8. ignoreBOM: KEEP a leading U+FEFF, so the display check
// refuses it as the other lanes do, instead of the decoder silently dropping it.
const utf8Strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Writes `intent` in format 1, refusing any field outside its bounds. */
export function encodeEnrollIntent(intent: EnrollIntent): Uint8Array {
  checkBlind(intent.blind);
  const fields = [
    shownBytes("account id", intent.accountId),
    shownBytes("account name", intent.accountName),
    shownBytes("purpose", intent.purpose),
  ];
  if (intent.restrictions.length > ENROLL_MAX_RESTRICTIONS) {
    throw new Error(`enroll: ${intent.restrictions.length} restrictions, want at most ${ENROLL_MAX_RESTRICTIONS}`);
  }
  const restrictions = intent.restrictions.map((r, n) => shownBytes(`restriction ${n}`, r));
  const out: number[] = [ENROLL_INTENT_FORMAT];
  pushField(out, intent.blind);
  for (const f of fields) pushField(out, f);
  out.push(restrictions.length);
  for (const r of restrictions) pushField(out, r);
  return Uint8Array.from(out);
}

/** Reads an intent in format 1. Refuses an unknown format, any field outside its bounds,
 *  display-unsafe or non-UTF-8 text, and any byte left over. */
export function decodeEnrollIntent(bytes: Uint8Array): EnrollIntent {
  const r = new Reader(bytes);
  const format = r.take(1)[0]!;
  if (format !== ENROLL_INTENT_FORMAT) {
    throw new Error(`enroll: intent format 0x${hex2(format)}, want 0x${hex2(ENROLL_INTENT_FORMAT)}`);
  }
  const blind = r.field().slice();
  checkBlind(blind);
  const accountId = shownText(r, "account id");
  const accountName = shownText(r, "account name");
  const purpose = shownText(r, "purpose");
  const count = r.take(1)[0]!;
  if (count > ENROLL_MAX_RESTRICTIONS) {
    throw new Error(`enroll: ${count} restrictions, want at most ${ENROLL_MAX_RESTRICTIONS}`);
  }
  const restrictions: string[] = [];
  for (let n = 0; n < count; n++) restrictions.push(shownText(r, `restriction ${n}`));
  r.end();
  return { blind, accountId, accountName, purpose, restrictions };
}

/** Writes `challenge` as a challenge token. */
export function encodeEnrollChallenge(challenge: EnrollChallenge): string {
  const audience = checkChallenge(challenge);
  const out: number[] = [];
  pushField(out, audience);
  pushField(out, challenge.transaction);
  pushField(out, challenge.nonce);
  out.push(...challenge.newKey);
  pushField(out, challenge.intent);
  const hi = Math.floor(challenge.deadline / 0x1_0000_0000);
  const lo = challenge.deadline % 0x1_0000_0000;
  out.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
  out.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
  const text = ENROLL_CHALLENGE_PREFIX + toHex(Uint8Array.from(out));
  if (text.length > ENROLL_MAX_TOKEN_SIZE) {
    throw new Error(`enroll: challenge token is ${text.length} bytes, over ${ENROLL_MAX_TOKEN_SIZE}`);
  }
  return text;
}

/** Reads a challenge token. Surrounding tabs, line feeds, carriage returns and spaces are
 *  ignored; anything else that is not exactly the prefix and lowercase hex of the fields, with
 *  no byte left over, is refused. */
export function decodeEnrollChallenge(text: string): EnrollChallenge {
  const r = new Reader(unwrap(text, ENROLL_CHALLENGE_PREFIX));
  let audience: string;
  try {
    audience = utf8Strict.decode(r.field());
  } catch {
    throw new Error("enroll: audience is not valid UTF-8");
  }
  const transaction = r.field().slice();
  const nonce = r.field().slice();
  const newKey = r.take(PUBLIC_KEY_SIZE).slice();
  const intent = r.field().slice();
  const d = r.take(8);
  r.end();
  const hi = ((d[0]! << 24) | (d[1]! << 16) | (d[2]! << 8) | d[3]!) >>> 0;
  const lo = ((d[4]! << 24) | (d[5]! << 16) | (d[6]! << 8) | d[7]!) >>> 0;
  if (hi > Math.floor(ENROLL_MAX_DEADLINE / 0x1_0000_0000)) throw new Error("enroll: deadline is after 9999-12-31T23:59:59Z");
  const challenge = { audience, transaction, nonce, newKey, intent, deadline: hi * 0x1_0000_0000 + lo };
  checkChallenge(challenge);
  return challenge;
}

/**
 * The enrollment request a challenge token yields (docs/enroll.md §3): the token's nonce,
 * transaction and new key, the intent's purpose, and SHA-256 of the token's intent bytes, with
 * the decoded intent. Refuses an intent that is not format 1. It is the one derivation of what
 * an `archon enroll` proof binds, so what the command shows is what it binds.
 */
export function enrollChallengeRequest(challenge: EnrollChallenge): { request: EnrollRequest; intent: EnrollIntent } {
  checkChallenge(challenge);
  const intent = decodeEnrollIntent(challenge.intent);
  return {
    request: {
      nonce: challenge.nonce.slice(),
      transaction: challenge.transaction.slice(),
      purpose: intent.purpose,
      newKey: challenge.newKey.slice(),
      intentDigest: sha256(challenge.intent),
    },
    intent,
  };
}

/** Writes `proof` as a proof token. */
export function encodeEnrollProof(proof: EnrollProof): string {
  checkProof(proof);
  const out: number[] = [];
  pushField(out, proof.transaction);
  out.push(...proof.newKey, ...proof.proof);
  return ENROLL_PROOF_PREFIX + toHex(Uint8Array.from(out));
}

/** Reads a proof token, under `decodeEnrollChallenge`'s rules. */
export function decodeEnrollProof(text: string): EnrollProof {
  const r = new Reader(unwrap(text, ENROLL_PROOF_PREFIX));
  const proof = { transaction: r.field().slice(), newKey: r.take(PUBLIC_KEY_SIZE).slice(), proof: r.take(ENROLL_PROOF_SIZE).slice() };
  r.end();
  checkProof(proof);
  return proof;
}

/** Checks a challenge's fields; returns the audience's UTF-8 bytes. The audience rule is
 *  stricter than the binding's (C0 and DEL only): a command that refuses a token prints its
 *  audience, so nothing display-unsafe may get that far. */
function checkChallenge(c: EnrollChallenge): Uint8Array {
  const audience = utf8.encode(c.audience);
  if (!isWellFormed(c.audience) || audience.length === 0 || audience.length > 0xffff) {
    throw new Error(`enroll: audience is ${audience.length} bytes, want 1..=65535 of UTF-8`);
  }
  refuseUnsafe("audience", c.audience);
  if (c.transaction.length === 0 || c.transaction.length > ENROLL_MAX_TRANSACTION_SIZE) {
    throw new Error(`enroll: transaction is ${c.transaction.length} bytes, want 1..=${ENROLL_MAX_TRANSACTION_SIZE}`);
  }
  if (c.nonce.length < MIN_NONCE_SIZE || c.nonce.length > ENROLL_MAX_NONCE_SIZE) {
    throw new Error(`enroll: nonce is ${c.nonce.length} bytes, want ${MIN_NONCE_SIZE}..=${ENROLL_MAX_NONCE_SIZE}`);
  }
  if (c.newKey.length !== PUBLIC_KEY_SIZE) {
    throw new Error(`enroll: new key is ${c.newKey.length} bytes, want ${PUBLIC_KEY_SIZE}`);
  }
  if (c.intent.length === 0 || c.intent.length > ENROLL_MAX_INTENT_SIZE) {
    throw new Error(`enroll: intent is ${c.intent.length} bytes, want 1..=${ENROLL_MAX_INTENT_SIZE}`);
  }
  if (!Number.isSafeInteger(c.deadline) || c.deadline < 0 || c.deadline > ENROLL_MAX_DEADLINE) {
    throw new Error("enroll: deadline must be whole seconds from 1970 to 9999-12-31T23:59:59Z");
  }
  return audience;
}

function checkProof(p: EnrollProof): void {
  if (p.transaction.length === 0 || p.transaction.length > ENROLL_MAX_TRANSACTION_SIZE) {
    throw new Error(`enroll: transaction is ${p.transaction.length} bytes, want 1..=${ENROLL_MAX_TRANSACTION_SIZE}`);
  }
  if (p.newKey.length !== PUBLIC_KEY_SIZE) throw new Error(`enroll: new key is ${p.newKey.length} bytes, want ${PUBLIC_KEY_SIZE}`);
  if (p.proof.length !== ENROLL_PROOF_SIZE) throw new Error(`enroll: proof is ${p.proof.length} bytes, want ${ENROLL_PROOF_SIZE}`);
}

function checkBlind(blind: Uint8Array): void {
  if (blind.length < ENROLL_MIN_BLIND_SIZE || blind.length > ENROLL_MAX_BLIND_SIZE) {
    throw new Error(`enroll: blind is ${blind.length} bytes, want ${ENROLL_MIN_BLIND_SIZE}..=${ENROLL_MAX_BLIND_SIZE}`);
  }
}

/** The rule for text the command shows: 1..=255 bytes of well-formed UTF-8 with no
 *  display-unsafe code point. Returns the UTF-8 bytes. The code point is named, never echoed. */
function shownBytes(what: string, s: string): Uint8Array {
  if (!isWellFormed(s)) throw new Error(`enroll: ${what} is not well-formed UTF-16 (a lone surrogate is not UTF-8)`);
  const bytes = utf8.encode(s);
  if (bytes.length === 0 || bytes.length > ENROLL_MAX_TEXT_SIZE) {
    throw new Error(`enroll: ${what} is ${bytes.length} bytes, want 1..=${ENROLL_MAX_TEXT_SIZE}`);
  }
  refuseUnsafe(what, s);
  return bytes;
}

function shownText(r: Reader, what: string): string {
  let s: string;
  try {
    s = utf8Strict.decode(r.field());
  } catch {
    throw new Error(`enroll: ${what} is not valid UTF-8`);
  }
  shownBytes(what, s);
  return s;
}

function refuseUnsafe(what: string, s: string): void {
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (displayUnsafe(cp)) {
      throw new Error(`enroll: ${what} carries a code point that cannot be shown, U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    }
  }
}

/** Strips the surrounding whitespace the token rules allow and decodes the hex after `prefix`:
 *  lowercase only, even length, nothing else. */
function unwrap(text: string, prefix: string): Uint8Array {
  let i = 0;
  let j = text.length;
  const ws = (c: string) => c === "\t" || c === "\n" || c === "\r" || c === " ";
  while (i < j && ws(text[i]!)) i++;
  while (j > i && ws(text[j - 1]!)) j--;
  const t = text.slice(i, j);
  const size = utf8.encode(t).length;
  if (size > ENROLL_MAX_TOKEN_SIZE) throw new Error(`enroll: token is ${size} bytes, over ${ENROLL_MAX_TOKEN_SIZE}`);
  if (!t.startsWith(prefix)) throw new Error(`enroll: not a token beginning ${JSON.stringify(prefix)}`);
  const h = t.slice(prefix.length);
  if (h.length % 2 !== 0) throw new Error("enroll: token hex has an odd length");
  if (!/^[0-9a-f]*$/.test(h)) throw new Error("enroll: token is not lowercase hex");
  const out = new Uint8Array(h.length / 2);
  for (let k = 0; k < out.length; k++) out[k] = Number.parseInt(h.slice(k * 2, k * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function hex2(n: number): string {
  return n.toString(16).padStart(2, "0");
}

function pushField(out: number[], field: Uint8Array): void {
  out.push((field.length >> 8) & 0xff, field.length & 0xff);
  for (const b of field) out.push(b);
}

function isWellFormed(s: string): boolean {
  const native = (s as unknown as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof native === "function") return native.call(s);
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

/** Takes length-prefixed fields off a byte array, refusing anything that runs past it. */
class Reader {
  readonly bytes: Uint8Array;
  #pos = 0;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  take(n: number): Uint8Array {
    if (n > this.bytes.length - this.#pos) throw new Error("enroll: truncated");
    const out = this.bytes.subarray(this.#pos, this.#pos + n);
    this.#pos += n;
    return out;
  }

  field(): Uint8Array {
    const n = this.take(2);
    return this.take((n[0]! << 8) | n[1]!);
  }

  end(): void {
    if (this.#pos !== this.bytes.length) throw new Error(`enroll: ${this.bytes.length - this.#pos} bytes left over`);
  }
}
