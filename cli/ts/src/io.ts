// Input plumbing shared by every subcommand: stdin-or-`--in <file>`, as bytes or text.
// `--in <file>` exists because PowerShell has no `<` input redirection; when absent,
// behaviour is byte-identical to the stdin default. An empty `--in ""` is rejected as "no
// value" so all three lanes fail the same way.
import { readFileSync } from "node:fs";
import { pkcs8PemToSeed, seedFromHex } from "@bitspark/archon";

/** Read the whole input as raw bytes: the file when given, else stdin. */
export function readBytes(file?: string): Uint8Array {
  try {
    return new Uint8Array(file !== undefined ? readFileSync(file) : readFileSync(0));
  } catch (e) {
    throw new Error(file !== undefined ? `could not read ${JSON.stringify(file)}: ${(e as Error).message}` : `could not read stdin: ${(e as Error).message}`);
  }
}

/** Read the whole input as UTF-8 text (PEM blocks). */
export function readText(file?: string): string {
  return new TextDecoder().decode(readBytes(file));
}

/**
 * Scan args for an optional `--in <file>` pair; return [argsWithoutIt, file?]. A trailing
 * or empty `--in` throws.
 */
export function takeInFlag(args: string[]): [string[], string | undefined] {
  const rest: string[] = [];
  let file: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--in") {
      const v = args[i + 1];
      if (v === undefined || v === "") throw new Error('flag "--in" needs a value');
      file = v;
      i += 1;
      continue;
    }
    rest.push(args[i]!);
  }
  return [rest, file];
}

/** `<cmd> --help` / `-h` as the first token: help is success (usage to stdout, exit 0). */
export function wantsHelp(args: string[]): boolean {
  return args[0] === "--help" || args[0] === "-h";
}

/**
 * Resolve a private key from the two ways every signing command accepts one: `--seed
 * <hex>` (a raw 32-byte seed) or a PKCS#8 PEM from `--key-file <file>` / stdin.
 */
export function resolveSeed(seedHex: string | undefined, keyFile: string | undefined, usage: string): Uint8Array {
  if (seedHex !== undefined && keyFile !== undefined) {
    throw new Error(`--seed and --key-file are mutually exclusive\n${usage}`);
  }
  if (seedHex !== undefined) {
    try {
      return seedFromHex(seedHex);
    } catch (e) {
      throw new Error(`--seed: ${(e as Error).message}`);
    }
  }
  return pkcs8PemToSeed(readText(keyFile));
}

/** A verdict (`invalid`): already printed on stdout, exit 1, nothing on stderr. */
export class Verdict extends Error {}
