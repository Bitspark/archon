// Conformance CLI (ts) — a dev/CI artifact, not part of the published package surface.
//
// Implements the `conformance v1` protocol archon inherits from thesmos ADR 0006:
// `conformance <family>` reads the whole vectors/identity.json on stdin, selects its
// family's cases, recomputes each result from the case INPUTS (ignoring the expected
// value the oracle carries), and writes one NDJSON line per case to stdout in input
// order. The harness (conformance/harness.mjs) drives this and the rs/go CLIs as black
// boxes and asserts each line against the oracle.
//
//   pubkey_from_seed : in {name, seed}                 out {"name","pubkey":"<64-hex>"}
//   key_encode       : in {name, pubkey}               out {"name","text":"<key text>"}
//   keycodec         : in {name, kind, key?|pem?}      out {"name","result":{"ok":"<PEM|hex>"}|{"error":true}}
//   signature_verify : in {name, pubkey, message, sig} out {"name","valid":<bool>}
//   hex_decode       : in {name, kind, hex}            out {"name","result":{"ok":"<hex>"}|{"error":true}}
//   domain_sign      : in {name, seed, domain, message} out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
//   domain_verify    : in {name, pubkey, domain, message, sig} out {"name","valid":<bool>}

import { readFileSync } from "node:fs";
import { getPublicKey, verify, signInDomain, verifyInDomain } from "../src/crypto.js";
import { seedFromHex, pubkeyFromHex, signatureFromHex, toHex as hexOf } from "../src/hexbytes.js";
import { encodeKey } from "../src/keytext.js";
import {
  pubkeyToSpkiPem,
  seedToPkcs8Pem,
  spkiPemToPubkey,
  pkcs8PemToSeed,
} from "../src/keycodec.js";

function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error(`case input is not valid hex: ${s}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// The oracle distinguishes success-with-a-value from failure, never the message: the
// reject *reason* is a core's own diagnostic, the reject *decision* is what must agree
// across three languages.
function attempt(f: () => string): { ok: string } | { error: true } {
  try {
    return { ok: f() };
  } catch {
    return { error: true };
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
    case "pubkey_from_seed":
      out = { name, pubkey: toHex(getPublicKey(fromHex(c["seed"]!))) };
      break;
    case "key_encode":
      out = { name, text: encodeKey(fromHex(c["pubkey"]!)) };
      break;
    case "keycodec": {
      const kind = c["kind"];
      const result =
        kind === "encode_pkcs8"
          ? attempt(() => seedToPkcs8Pem(fromHex(c["key"]!)))
          : kind === "encode_spki"
            ? attempt(() => pubkeyToSpkiPem(fromHex(c["key"]!)))
            : kind === "decode_pkcs8"
              ? attempt(() => toHex(pkcs8PemToSeed(c["pem"]!)))
              : kind === "decode_spki"
                ? attempt(() => toHex(spkiPemToPubkey(c["pem"]!)))
                : (() => {
                    throw new Error(`unknown keycodec kind: ${kind}`);
                  })();
      out = { name, result };
      break;
    }
    case "signature_verify":
      // note the argument order: @noble's verify is (signature, message, publicKey).
      out = { name, valid: verify(fromHex(c["sig"]!), fromHex(c["message"]!), fromHex(c["pubkey"]!)) };
      break;
    case "hex_decode": {
      const kind = c["kind"];
      const text = c["hex"]!;
      const result =
        kind === "seed"
          ? attempt(() => hexOf(seedFromHex(text)))
          : kind === "pubkey"
            ? attempt(() => hexOf(pubkeyFromHex(text)))
            : kind === "signature"
              ? attempt(() => hexOf(signatureFromHex(text)))
              : (() => {
                  throw new Error(`unknown hex_decode kind: ${kind}`);
                })();
      out = { name, result };
      break;
    }
    case "domain_sign":
      out = {
        name,
        result: attempt(() => toHex(signInDomain(fromHex(c["seed"]!), c["domain"]!, fromHex(c["message"]!)))),
      };
      break;
    case "domain_verify":
      out = {
        name,
        valid: verifyInDomain(fromHex(c["pubkey"]!), c["domain"]!, fromHex(c["message"]!), fromHex(c["sig"]!)),
      };
      break;
    default:
      throw new Error(`unknown family: ${family}`);
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
