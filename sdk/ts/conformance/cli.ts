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

import { readFileSync } from "node:fs";
import { provePossession, verifyPossession, seal, open, loginBinding, proveLogin, verifyLogin, proveCollect, verifyCollect, deriveAudience, enrollBinding, proveEnroll, verifyEnroll, signRequest, verifyRequest } from "../src/index.js";
import type { EnrollRequest, LoginRequest } from "../src/index.js";

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
    default:
      throw new Error(`unknown family: ${family}`);
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
