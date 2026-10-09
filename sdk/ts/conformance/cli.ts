// Conformance CLI (ts, sdk) — a dev/CI artifact, not part of the published package surface.
// Same `conformance v1` protocol as the floor's CLI: `cli <family>` reads the whole
// vectors/sdk.json on stdin, selects its family, recomputes each result from the case
// INPUTS, and writes one NDJSON line per case to stdout in input order.
//
//   possession_prove  : in {name, seed, domain, nonce, binding}        out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//   possession_verify : in {name, pubkey, domain, nonce, binding, sig} out {"name","valid":<bool>}
//   envelope_seal     : in {name, seed, domain, payload}               out {"name","result":{"ok":"<hex>"}|{"error":true}}
//   envelope_open     : in {name, envelope, domain}                    out {"name","result":{"ok":{"pubkey","payload"}}|{"error":true}}
//
// vectors/request.json (`request` is {nonce, transaction, purpose[hex], new_key, intent_digest}):
//
//   enroll_binding : in {name, audience, request}       out {"name","result":{"ok":"<hex>"}|{"error":true}}
//   enroll_prove   : in {name, seed, audience, request} out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//   enroll_verify  : in {name, audience, request, sig}  out {"name","valid":<bool>}
//   request_sign   : in {name, seed, method, audience, request_target, body, content_type, declared, created, expires, nonce}
//                    out {"name","result":{"ok":{"base","headers"}}|{"error":true}}
//   request_verify : in {name, policy, now, request{method, request_target, headers, body}}
//                    out {"name","result":{"ok":{"principal","created","expires","nonce","target_uri"}}|{"error":true}}
//
// vectors/enroll.json (text fields of an intent as hex):
//
//   enroll_intent_encode     : in {name, intent}      out {"name","result":{"ok":"<hex>"}|{"error":true}}
//   enroll_intent_decode     : in {name, bytes}       out {"name","result":{"ok":{intent}}|{"error":true}}
//   enroll_challenge_encode  : in {name, challenge}   out {"name","result":{"ok":"<token>"}|{"error":true}}
//   enroll_challenge_decode  : in {name, text}        out {"name","result":{"ok":{challenge}}|{"error":true}}
//   enroll_challenge_request : in {name, text}        out {"name","result":{"ok":{"audience","request"}}|{"error":true}}
//   enroll_proof_encode      : in {name, proof_token} out {"name","result":{"ok":"<token>"}|{"error":true}}
//   enroll_proof_decode      : in {name, text}        out {"name","result":{"ok":{proof_token}}|{"error":true}}

import { readFileSync } from "node:fs";
import { provePossession, verifyPossession, seal, open, loginBinding, proveLogin, verifyLogin, proveCollect, verifyCollect, deriveAudience, fingerprint, formatFingerprint, enrollBinding, proveEnroll, verifyEnroll, signRequest, verifyRequest, encodeEnrollIntent, decodeEnrollIntent, encodeEnrollChallenge, decodeEnrollChallenge, enrollChallengeRequest, encodeEnrollProof, decodeEnrollProof } from "../src/index.js";
import type { EnrollIntent, EnrollRequest, LoginRequest } from "../src/index.js";

function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error(`case input is not valid hex: ${s}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// The oracle distinguishes success-with-a-value from failure, never the message.
function attempt<T>(f: () => T): { ok: T } | { error: true } {
  try {
    return { ok: f() };
  } catch {
    return { error: true };
  }
}

// The oracle's spelling of a login request (bytes as hex, scope entries as hex so that a
// non-UTF-8 entry can be a case). A scope entry that does not decode as UTF-8 throws here,
// which is the same refusal the scheme would make — reported as the error result.
const utf8Strict = new TextDecoder("utf-8", { fatal: true });
function loginRequest(c: Record<string, unknown>): LoginRequest {
  const r = c["request"] as { id: string; nonce: string; browser: string; scope: string[]; valid_for: number };
  return {
    id: fromHex(r.id),
    nonce: fromHex(r.nonce),
    browser: fromHex(r.browser),
    scope: r.scope.map((entry) => utf8Strict.decode(fromHex(entry))),
    validFor: r.valid_for,
  };
}
// The oracle's spelling of an enrollment request: bytes as hex, the purpose as hex so that a
// non-UTF-8 purpose can be a case (a failed decode is the same refusal the scheme would make).
function enrollRequest(c: Record<string, unknown>): EnrollRequest {
  const r = c["request"] as { nonce: string; transaction: string; purpose: string; new_key: string; intent_digest: string };
  return {
    nonce: fromHex(r.nonce),
    transaction: fromHex(r.transaction),
    purpose: utf8Strict.decode(fromHex(r.purpose)),
    newKey: fromHex(r.new_key),
    intentDigest: fromHex(r.intent_digest),
  };
}
// The oracle's spelling of an intent in format 1: every text field as hex. This decoder KEEPS a
// leading U+FEFF (ignoreBOM), so a case that starts with one reaches the codec, which refuses
// it; the default decoder would drop it and let the case pass for the wrong reason.
const utf8Exact = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function enrollIntent(c: Record<string, unknown>): EnrollIntent {
  const i = c["intent"] as { blind: string; account_id: string; account_name: string; purpose: string; restrictions: string[] };
  const text = (h: string) => utf8Exact.decode(fromHex(h));
  return {
    blind: fromHex(i.blind),
    accountId: text(i.account_id),
    accountName: text(i.account_name),
    purpose: text(i.purpose),
    restrictions: i.restrictions.map(text),
  };
}
function spellIntent(i: EnrollIntent): Record<string, unknown> {
  const hexText = (s: string) => toHex(new TextEncoder().encode(s));
  return {
    blind: toHex(i.blind),
    account_id: hexText(i.accountId),
    account_name: hexText(i.accountName),
    purpose: hexText(i.purpose),
    restrictions: i.restrictions.map(hexText),
  };
}
function totally(f: () => boolean): boolean {
  try {
    return f();
  } catch {
    return false;
  }
}

const family = process.argv[2];
if (!family) {
  console.error("usage: cli <family>");
  process.exit(2);
}
const doc = JSON.parse(readFileSync(0, "utf8")) as Record<string, unknown>;
const cases = doc[family];
if (!Array.isArray(cases)) throw new Error(`unknown family: ${family}`);

for (const c of cases as Array<Record<string, string>>) {
  const name = c["name"];
  let out: Record<string, unknown>;
  switch (family) {
    case "possession_prove":
      out = { name, result: attempt(() => toHex(provePossession(fromHex(c["seed"]!), c["domain"]!, fromHex(c["nonce"]!), fromHex(c["binding"]!)))) };
      break;
    case "possession_verify":
      out = { name, valid: verifyPossession(fromHex(c["pubkey"]!), c["domain"]!, fromHex(c["nonce"]!), fromHex(c["binding"]!), fromHex(c["sig"]!)) };
      break;
    case "envelope_seal":
      out = { name, result: attempt(() => toHex(seal(fromHex(c["seed"]!), c["domain"]!, fromHex(c["payload"]!)))) };
      break;
    case "envelope_open":
      out = {
        name,
        result: attempt(() => {
          const o = open(fromHex(c["envelope"]!), c["domain"]!);
          return { pubkey: toHex(o.pubkey), payload: toHex(o.payload) };
        }),
      };
      break;
    case "login_audience":
      out = {
        name,
        result: attempt(() => {
          const d = deriveAudience(c["url"]!);
          return { audience: d.audience, id: toHex(d.id) };
        }),
      };
      break;
    case "login_binding":
      out = { name, result: attempt(() => toHex(loginBinding(Number((c as Record<string, unknown>)["role"]), c["audience"]!, loginRequest(c)))) };
      break;
    case "login_prove":
      out = { name, result: attempt(() => toHex(proveLogin(fromHex(c["seed"]!), c["audience"]!, loginRequest(c)))) };
      break;
    case "login_verify":
      out = { name, valid: totally(() => verifyLogin(fromHex(c["pubkey"]!), c["audience"]!, loginRequest(c), fromHex(c["sig"]!))) };
      break;
    case "login_collect_prove":
      out = { name, result: attempt(() => toHex(proveCollect(fromHex(c["seed"]!), c["audience"]!, loginRequest(c)))) };
      break;
    case "login_collect_verify":
      out = { name, valid: totally(() => verifyCollect(c["audience"]!, loginRequest(c), fromHex(c["sig"]!))) };
      break;
    case "login_fingerprint":
      out = {
        name,
        result: attempt(() => {
          const fp = fingerprint(c["audience"]!, loginRequest(c));
          return { fingerprint: toHex(fp), display: formatFingerprint(fp) };
        }),
      };
      break;
    case "enroll_binding":
      out = { name, result: attempt(() => toHex(enrollBinding(c["audience"]!, enrollRequest(c)))) };
      break;
    case "enroll_prove":
      out = { name, result: attempt(() => toHex(proveEnroll(fromHex(c["seed"]!), c["audience"]!, enrollRequest(c)))) };
      break;
    case "enroll_verify":
      out = { name, valid: totally(() => verifyEnroll(c["audience"]!, enrollRequest(c), fromHex(c["sig"]!))) };
      break;
    case "request_sign": {
      const k = c as Record<string, unknown>;
      out = {
        name,
        result: attempt(() =>
          signRequest(fromHex(k["seed"] as string), {
            method: k["method"] as string,
            audience: k["audience"] as string,
            requestTarget: k["request_target"] as string,
            body: fromHex(k["body"] as string),
            contentType: (k["content_type"] as string | null) ?? undefined,
            declared: k["declared"] as Array<[string, string]>,
            created: k["created"] as number,
            expires: k["expires"] as number,
            nonce: fromHex(k["nonce"] as string),
          }),
        ),
      };
      break;
    }
    case "request_verify": {
      const k = c as Record<string, unknown>;
      const p = k["policy"] as { audience: string; declared: string[]; max_lifetime: number; skew: number };
      const r = k["request"] as { method: string; request_target: string; headers: Array<[string, string]>; body: string };
      out = {
        name,
        result: attempt(() => {
          const v = verifyRequest(
            { audience: p.audience, declared: p.declared, maxLifetime: p.max_lifetime, skew: p.skew },
            k["now"] as number,
            { method: r.method, requestTarget: r.request_target, headers: r.headers, body: fromHex(r.body) },
          );
          return { principal: v.keyText, created: v.created, expires: v.expires, nonce: toHex(v.nonce), target_uri: v.targetUri };
        }),
      };
      break;
    }
    case "enroll_intent_encode":
      out = { name, result: attempt(() => toHex(encodeEnrollIntent(enrollIntent(c)))) };
      break;
    case "enroll_intent_decode":
      out = { name, result: attempt(() => spellIntent(decodeEnrollIntent(fromHex(c["bytes"]!)))) };
      break;
    case "enroll_challenge_encode": {
      const ch = (c as Record<string, unknown>)["challenge"] as {
        audience: string; transaction: string; nonce: string; new_key: string; intent: string; deadline: number;
      };
      out = {
        name,
        result: attempt(() =>
          encodeEnrollChallenge({
            audience: ch.audience, transaction: fromHex(ch.transaction), nonce: fromHex(ch.nonce),
            newKey: fromHex(ch.new_key), intent: fromHex(ch.intent), deadline: ch.deadline,
          }),
        ),
      };
      break;
    }
    case "enroll_challenge_decode":
      out = {
        name,
        result: attempt(() => {
          const ch = decodeEnrollChallenge(c["text"]!);
          return {
            audience: ch.audience, transaction: toHex(ch.transaction), nonce: toHex(ch.nonce),
            new_key: toHex(ch.newKey), intent: toHex(ch.intent), deadline: ch.deadline,
          };
        }),
      };
      break;
    case "enroll_challenge_request":
      out = {
        name,
        result: attempt(() => {
          const ch = decodeEnrollChallenge(c["text"]!);
          const { request } = enrollChallengeRequest(ch);
          return {
            audience: ch.audience,
            request: {
              nonce: toHex(request.nonce), transaction: toHex(request.transaction),
              purpose: toHex(new TextEncoder().encode(request.purpose)), new_key: toHex(request.newKey),
              intent_digest: toHex(request.intentDigest),
            },
          };
        }),
      };
      break;
    case "enroll_proof_encode": {
      const p = (c as Record<string, unknown>)["proof_token"] as { transaction: string; new_key: string; proof: string };
      out = {
        name,
        result: attempt(() =>
          encodeEnrollProof({ transaction: fromHex(p.transaction), newKey: fromHex(p.new_key), proof: fromHex(p.proof) }),
        ),
      };
      break;
    }
    case "enroll_proof_decode":
      out = {
        name,
        result: attempt(() => {
          const p = decodeEnrollProof(c["text"]!);
          return { transaction: toHex(p.transaction), new_key: toHex(p.newKey), proof: toHex(p.proof) };
        }),
      };
      break;
    default:
      throw new Error(`unknown family: ${family}`);
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
