// archon key — convert between raw key bytes and the canonical key text, or between raw
// key/seed bytes and the standard PEM containers (PKCS#8 v1 / SPKI):
//
//   archon key encode <pubkey-hex>        -> prints encodeKey(bytes) to stdout
//   archon key decode <ed25519:...>       -> prints the decoded bytes as hex to stdout
//   archon key pkcs8 encode <seed-hex>    -> prints the PKCS#8 v1 PEM to stdout
//   archon key pkcs8 decode               -> reads a PEM on stdin, prints the seed hex
//   archon key spki encode <pubkey-hex>   -> prints the SPKI PEM to stdout
//   archon key spki decode                -> reads a PEM on stdin, prints the pubkey hex
//   archon key pub [...]                  -> the public key of a private key
//
// Every hex input goes through the floor's typed decoders (hexbytes), so a 31-byte
// "public key" is refused here exactly as the library refuses it. PEM decode is total: a
// malformed block throws a clean error (caught by main → exit non-zero), never garbage.
import {
  decodeKey,
  encodeKey,
  getPublicKey,
  pkcs8PemToSeed,
  pubkeyFromHex,
  pubkeyToSpkiPem,
  seedFromHex,
  seedToPkcs8Pem,
  spkiPemToPubkey,
  toHex,
} from "@bitspark/archon";

import { readText, takeInFlag, wantsHelp } from "../io.js";
import { parsePubFormat, type PubFormat, renderPub } from "../pubrender.js";
import * as store from "./key_store.js";

const USAGE =
  "usage: archon key <encode <pubkey-hex>|decode <ed25519:...>|" +
  "pkcs8 <encode <seed-hex>|decode>|spki <encode <pubkey-hex>|decode>|" +
  "pub [--in <file>|--seed <hex>] [--format spki|text|hex]|" +
  "add <name> [--seed <hex>|--seed-file <file>|--pkcs8 <file>]|list [--json]|" +
  "rm <name> [--force]|default [<name>]|export <name> --reveal --out <file>>\n  " +
  "pkcs8/spki decode read a PEM block on stdin (or --in <file>); " +
  "pub derives the public key from a private key, default --format text.\n  " +
  "add/list/rm/default/export are the password-protected seed store (ADR 0007 §A); " +
  "keys live in $ARCHON_HOME/keys, default ~/.archon.";

export function run(args: string[]): void {
  if (wantsHelp(args)) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  const [op, ...rest] = args;
  switch (op) {
    // The store (ADR 0007 §A). Siblings of the codec cases below: `key encode`
    // converts bytes it is handed, `key add` keeps a seed. Same noun, nothing else.
    case "add":
      store.runAdd(rest);
      return;
    case "list":
      store.runList(rest);
      return;
    case "rm":
      store.runRm(rest);
      return;
    case "default":
      store.runDefault(rest);
      return;
    case "export":
      store.runExport(rest);
      return;
    case "encode":
      if (rest.length !== 1) throw new Error(USAGE);
      process.stdout.write(`${encodeKey(pubkeyFromHex(rest[0]!))}\n`);
      return;
    case "decode":
      if (rest.length !== 1) throw new Error(USAGE);
      process.stdout.write(`${toHex(decodeKey(rest[0]!))}\n`);
      return;
    case "pkcs8":
      pem(rest, "pkcs8");
      return;
    case "spki":
      pem(rest, "spki");
      return;
    case "pub":
      pub(rest);
      return;
    default:
      throw new Error(USAGE);
  }
}

// `pkcs8|spki <encode <hex>|decode>`: a 32-byte seed or public key <-> its PEM container.
function pem(args: string[], container: "pkcs8" | "spki"): void {
  const [op, ...rest] = args;
  if (op === "encode" && rest.length === 1) {
    // keycodec emits the PEM with its own single trailing newline; write verbatim.
    process.stdout.write(
      container === "pkcs8" ? seedToPkcs8Pem(seedFromHex(rest[0]!)) : pubkeyToSpkiPem(pubkeyFromHex(rest[0]!)),
    );
    return;
  }
  if (op === "decode") {
    const [extra, inFile] = takeInFlag(rest);
    if (extra.length !== 0) throw new Error(USAGE);
    const input = readText(inFile);
    process.stdout.write(`${toHex(container === "pkcs8" ? pkcs8PemToSeed(input) : spkiPemToPubkey(input))}\n`);
    return;
  }
  throw new Error(USAGE);
}

// `pub [--in <file>|--seed <hex>] [--format spki|text|hex]`: derive the public key from a
// private key. --format is validated at parse time, so a bad format errors before any
// input is read.
function pub(args: string[]): void {
  let inFile: string | undefined;
  let seedHex: string | undefined;
  let fmt: PubFormat = "text";
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]!;
    if (i + 1 >= args.length) throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    const value = args[i + 1]!;
    switch (flag) {
      case "--in":
        if (value === "") throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
        inFile = value;
        break;
      case "--seed":
        seedHex = value;
        break;
      case "--format":
        fmt = parsePubFormat(value);
        break;
      default:
        throw new Error(`unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
    }
  }
  if (inFile !== undefined && seedHex !== undefined) {
    throw new Error(`--in and --seed are mutually exclusive\n${USAGE}`);
  }
  let seed: Uint8Array;
  if (seedHex !== undefined) {
    try {
      seed = seedFromHex(seedHex);
    } catch (e) {
      throw new Error(`--seed: ${(e as Error).message}`);
    }
  } else {
    seed = pkcs8PemToSeed(readText(inFile));
  }
  process.stdout.write(renderPub(getPublicKey(seed), fmt));
}
