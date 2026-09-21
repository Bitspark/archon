// archon verify — verify a signature over raw bytes, raw or in a domain. Prints `valid`
// (exit 0) or `invalid` (exit 1) on stdout: a verdict, not a usage error, so a bad
// signature is silent on stderr. Not thesmos's `verify` — that one verifies facts, proofs
// and freshness. This one verifies bytes.
import { decodeKey, pubkeyFromHex, signatureFromHex, verify, verifyInDomain } from "@bitspark/archon";

import { readBytes, Verdict, wantsHelp } from "../io.js";

const USAGE =
  "usage: archon verify --pubkey <ed25519:...|hex> --sig <hex> [--domain <d>] [--in <file>]\n  " +
  "verifies the signature over the input bytes (stdin, or --in <file>); prints valid (exit 0) " +
  "or invalid (exit 1). --domain checks a domain-separated signature.";

export function run(args: string[]): void {
  if (wantsHelp(args)) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  let pubkey: Uint8Array | undefined;
  let sig: Uint8Array | undefined;
  let domain: string | undefined;
  let inFile: string | undefined;
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]!;
    const value = args[i + 1];
    if (value === undefined || (value === "" && flag !== "--domain")) {
      throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    }
    switch (flag) {
      case "--pubkey":
        pubkey = parsePubkey(value);
        break;
      case "--sig":
        try {
          sig = signatureFromHex(value);
        } catch (e) {
          throw new Error(`--sig: ${(e as Error).message}`);
        }
        break;
      case "--domain":
        domain = value;
        break;
      case "--in":
        inFile = value;
        break;
      default:
        throw new Error(`unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
    }
  }
  if (pubkey === undefined || sig === undefined) {
    throw new Error(`--pubkey and --sig are required\n${USAGE}`);
  }
  const message = readBytes(inFile);
  const ok = domain !== undefined ? verifyInDomain(pubkey, domain, message, sig) : verify(sig, message, pubkey);
  if (ok) {
    process.stdout.write("valid\n");
    return;
  }
  process.stdout.write("invalid\n");
  throw new Verdict("invalid");
}

/** A public key as canonical key text (`ed25519:<hex>`) or bare hex. */
function parsePubkey(value: string): Uint8Array {
  try {
    return value.startsWith("ed25519:") ? decodeKey(value) : pubkeyFromHex(value);
  } catch (e) {
    throw new Error(`--pubkey: ${(e as Error).message}`);
  }
}
