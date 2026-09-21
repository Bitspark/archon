// archon keygen — generate (or deterministically derive) an Ed25519 key pair: the
// canonical public key to stdout — the shareable part — and the private key as a PKCS#8
// v1 PEM, never the raw seed hex, either to --out <file> (the recommended path) or to
// stderr behind a clear warning.
//
// The RNG is the one deliberately-unpinned edge, and it lives here, in the CLI: the
// library takes a seed it is given and never invents one (ADR 0002). This is not custody
// in stele's sense — nothing is named, stored or managed; a file you name is written and
// forgotten.
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

import { encodeKey, getPublicKey, seedFromHex, seedToPkcs8Pem, SEED_SIZE } from "@bitspark/archon";

import { wantsHelp } from "../io.js";
import * as keystore from "../keystore.js";
import * as store from "./key_store.js";
import { parsePubFormat, type PubFormat, renderPub } from "../pubrender.js";

const USAGE =
  "usage: archon keygen [--seed <hex>] [--store <name>] [--out <file>] [--pub-out <file>] [--pub-format spki|text|hex]\n  " +
  "prints the public key (canonical text) on stdout; writes the PKCS#8 PEM private key to " +
  "<file> (--out) or, by default, to stderr behind a SECRET warning; --pub-out writes the " +
  "public key (--pub-format spki|text|hex, default spki) to a file. --seed derives the " +
  "key deterministically.";

interface Opts {
  seed: Uint8Array;
  out?: string | undefined;
  pubOut?: string | undefined;
  pubFormat: PubFormat;
}

export function run(args: string[]): void {
  if (wantsHelp(args)) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  const { rest: afterStore, store: storeName } = takeStoreFlag(args);
  const { rest: parsedArgs, fd: pwFd } = store.takePasswordFd(afterStore);
  // Validated before anything is generated or printed: a bad name should cost nothing.
  if (storeName !== undefined) keystore.validateName(storeName);
  const opts = parseOpts(parsedArgs);
  if (storeName !== undefined && opts.out !== undefined) {
    throw new Error(
      "--store and --out are mutually exclusive: one keeps the seed, the other writes it out",
    );
  }
  const pub = getPublicKey(opts.seed);
  process.stdout.write(`${encodeKey(pub)}\n`);
  // --store: the seed stays in the store and no PEM is produced at all. Same seal path
  // `key add` uses (sealAndWrite), reached from the command that owns the CSPRNG.
  if (storeName !== undefined) {
    store.storeGenerated(storeName, opts.seed, pwFd);
    if (opts.pubOut !== undefined) {
      writeFileSync(opts.pubOut, renderPub(pub, opts.pubFormat));
      process.stderr.write(`wrote public key (${opts.pubFormat}) to ${opts.pubOut}\n`);
    }
    return;
  }

  const pem = seedToPkcs8Pem(opts.seed);
  if (opts.out !== undefined) {
    writeFileSync(opts.out, pem, { mode: 0o600 });
    process.stderr.write(`wrote PKCS#8 private key PEM to ${opts.out}\n`);
  } else {
    process.stderr.write("SECRET — do not share. Anyone with this private key controls the identity:\n");
    process.stderr.write(pem);
  }
  if (opts.pubOut !== undefined) {
    writeFileSync(opts.pubOut, renderPub(pub, opts.pubFormat));
    process.stderr.write(`wrote public key (${opts.pubFormat}) to ${opts.pubOut}\n`);
  }
}

function parseOpts(args: string[]): Opts {
  let seed: Uint8Array | undefined;
  let out: string | undefined;
  let pubOut: string | undefined;
  let pubFormat: PubFormat = "spki";
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]!;
    if (i + 1 >= args.length) throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    const value = args[i + 1]!;
    switch (flag) {
      case "--seed":
        try {
          seed = seedFromHex(value);
        } catch (e) {
          throw new Error(`--seed: ${(e as Error).message}`);
        }
        break;
      case "--out":
        out = value;
        break;
      case "--pub-out":
        pubOut = value;
        break;
      case "--pub-format":
        // Validated at parse time so a bad format never leaves a private key behind.
        pubFormat = parsePubFormat(value);
        break;
      default:
        throw new Error(`unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
    }
  }
  return { seed: seed ?? new Uint8Array(randomBytes(SEED_SIZE)), out, pubOut, pubFormat };
}

/** Scans for `--store <name>` and removes it, the same shape as takeInFlag. */
function takeStoreFlag(args: string[]): { rest: string[]; store: string | undefined } {
  const rest: string[] = [];
  let store: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--store") {
      const v = args[i + 1];
      if (v === undefined || v === "") throw new Error('flag "--store" needs a value');
      store = v;
      i++;
      continue;
    }
    rest.push(args[i] as string);
  }
  return { rest, store };
}
