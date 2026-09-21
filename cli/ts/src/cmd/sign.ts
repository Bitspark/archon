// archon sign — sign raw bytes, raw or in a domain. The message is the input, verbatim.
// With --domain the signature is domain-separated (Ed25519ph with the domain as RFC 8032
// context) and verifies only there; without it, the signature is raw Ed25519 and
// separation is the caller's problem. This is NOT thesmos's `sign` — that one signs a
// fact and knows what a fact is. This one knows nothing.
import { sign, signInDomain, toHex } from "@bitspark/archon";

import { readBytes, resolveSeed, wantsHelp } from "../io.js";

const USAGE =
  "usage: archon sign (--key-file <pkcs8.pem> | --seed <hex>) [--domain <d>] [--in <file>]\n  " +
  "signs the input bytes (stdin, or --in <file>) and prints the signature as hex. --domain " +
  "makes the signature domain-separated: it verifies in that domain and nowhere else.";

export function run(args: string[]): void {
  if (wantsHelp(args)) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  let keyFile: string | undefined;
  let seedHex: string | undefined;
  let domain: string | undefined;
  let inFile: string | undefined;
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]!;
    const value = args[i + 1];
    if (value === undefined || (value === "" && flag !== "--domain")) {
      throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    }
    switch (flag) {
      case "--key-file":
        keyFile = value;
        break;
      case "--seed":
        seedHex = value;
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
  if (keyFile === undefined && seedHex === undefined) {
    throw new Error(`one of --key-file or --seed is required\n${USAGE}`);
  }
  const seed = resolveSeed(seedHex, keyFile, USAGE);
  const message = readBytes(inFile);
  const sig = domain !== undefined ? signInDomain(seed, domain, message) : sign(message, seed);
  process.stdout.write(`${toHex(sig)}\n`);
}
