// Conformance CLI (ts, cli) — a dev/CI artifact, not part of the command's surface. Same
// `conformance v1` protocol as the floor's and the sdk's: `conformance <family>` reads the
// whole vectors/keystore.json on stdin, selects its family, recomputes each result from
// the case INPUTS, and writes one NDJSON line per case to stdout in input order.
//
//   keystore_seal : in {name, seed, password, salt, nonce, m_kib, t, p}
//                   out {"name","result":{"ok":{"file","public_key"}}|{"error":true}}
//   keystore_open : in {name, file, password}
//                   out {"name","result":{"ok":{"seed"}}|{"error":true}}
//   keystore_name : in {name, input}
//                   out {"name","result":{"ok":<bool>}}
//
// It lives in cli/ because the store does (ADR 0007 §A): the format is the command's, so
// its oracle is driven by the command's lane, not by core/ or sdk/.
import { readFileSync } from "node:fs";

import { isValidName, type KeyParams, open, seal } from "../src/keystore.js";

const hexDecode = (s: string): Uint8Array => {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const hexEncode = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

type Case = Record<string, unknown>;
const str = (c: Case, k: string): string => (typeof c[k] === "string" ? (c[k] as string) : "");
const num = (c: Case, k: string): number => (typeof c[k] === "number" ? (c[k] as number) : 0);

const family = process.argv[2];
if (family === undefined) {
  process.stderr.write("usage: conformance <family>\n");
  process.exit(2);
}

const doc = JSON.parse(readFileSync(0, "utf8")) as Record<string, Case[]>;
const cases = doc[family];
if (cases === undefined) throw new Error(`unknown family: ${family}`);

for (const c of cases) {
  let result: unknown;
  switch (family) {
    case "keystore_seal": {
      const params: KeyParams = {
        memoryKiB: num(c, "m_kib"),
        time: num(c, "t"),
        parallelism: num(c, "p"),
      };
      try {
        const blob = seal(
          hexDecode(str(c, "seed")),
          str(c, "password"),
          hexDecode(str(c, "salt")),
          hexDecode(str(c, "nonce")),
          params,
        );
        result = { ok: { file: hexEncode(blob), public_key: hexEncode(blob.slice(30, 62)) } };
      } catch {
        result = { error: true };
      }
      break;
    }
    case "keystore_open": {
      try {
        result = { ok: { seed: hexEncode(open(hexDecode(str(c, "file")), str(c, "password"))) } };
      } catch {
        result = { error: true };
      }
      break;
    }
    case "keystore_name": {
      result = { ok: isValidName(str(c, "input")) };
      break;
    }
    default:
      throw new Error(`unknown family: ${family}`);
  }
  process.stdout.write(`${JSON.stringify({ name: str(c, "name"), result })}\n`);
}
