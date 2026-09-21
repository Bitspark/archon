// Conformance CLI (ts, sdk) — a dev/CI artifact, not part of the published package surface.
// Same `conformance v1` protocol as the floor's CLI: `cli <family>` reads the whole
// vectors/sdk.json on stdin, selects its family, recomputes each result from the case
// INPUTS, and writes one NDJSON line per case to stdout in input order.
//
//   possession_prove  : in {name, seed, domain, nonce, binding}        out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//   possession_verify : in {name, pubkey, domain, nonce, binding, sig} out {"name","valid":<bool>}
//   envelope_seal     : in {name, seed, domain, payload}               out {"name","result":{"ok":"<hex>"}|{"error":true}}
//   envelope_open     : in {name, envelope, domain}                    out {"name","result":{"ok":{"pubkey","payload"}}|{"error":true}}

import { readFileSync } from "node:fs";
import { provePossession, verifyPossession, seal, open, loginBinding, proveLogin, verifyLogin, proveCollect, verifyCollect, deriveAudience } from "../src/index.js";
import type { LoginRequest } from "../src/index.js";

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
    default:
      throw new Error(`unknown family: ${family}`);
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
