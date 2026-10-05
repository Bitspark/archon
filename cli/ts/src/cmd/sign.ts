// archon sign — sign raw bytes, raw or in a domain. The message is the input, verbatim.
// With --domain the signature is domain-separated (Ed25519ph with the domain as RFC 8032
// context) and verifies only there; without it, the signature is raw Ed25519 and
// separation is the caller's problem. This is NOT thesmos's `sign` — that one signs a
// fact and knows what a fact is. This one knows nothing.
//
// --key signs with a key in archon's store, and is the boundary ADR 0009 §5 draws for a tool
// that is not archon: the seed never leaves this process. With --key the domain is REQUIRED —
// the store does not sign raw — and so is --expect, the principal the caller read from
// `archon key list --json` and built its bytes around. A header that names another key is
// refused before the password is asked for, and the opened seed is checked again before
// signing, so a mismatched key never produces a signature. Every signature, whatever the key
// source, is verified against the requested key, scheme and bytes before it is printed.
import { createHash } from "node:crypto";

import { decodeKey, encodeKey, getPublicKey, sign, signInDomain, toHex, verify, verifyInDomain }
  from "@bitspark/archon";

import { jsonString, readBytes, resolveSeed, wantsHelp } from "../io.js";
import { openEntered, readPasswordEntry, StoreRefusal, takePasswordFd, usableKey, type PasswordEntry } from "./key_store.js";
import { describePolicy, type KeyHeader, permits } from "../keystore.js";

const USAGE =
  "usage: archon sign (--key-file <pkcs8.pem> | --seed <hex> | --key <name> --domain <d>) " +
  "[--domain <d>] [--expect <principal>] [--in <file>] [--password-fd <n>] [--json]\n  " +
  "signs the input bytes (stdin, or --in <file>) and prints the signature as hex. --domain " +
  "makes the signature domain-separated: it verifies in that domain and nowhere else. --key " +
  "signs with a key in archon's store, in a domain only, and needs --expect: the principal " +
  "`archon key list --json` shows for it. --json prints one versioned record instead.";

/** A refusal with the machine mode's category: what a caller branches on, where the human
 *  sentence on stderr is free to change. */
class SignFailure extends Error {
  constructor(readonly category: string, message: string) {
    super(message);
  }
}

/** Marks archon's own protocol domains (archon-login/1, archon-request/1, archon-enroll/1).
 *  Those signatures are made only by the commands that show the person what they mean; `sign`
 *  shows a length and a digest, so it refuses them for every key source, before anything is
 *  read. The prefix is compared code unit for code unit, which for this ASCII prefix is byte for
 *  byte, like a domain itself (ADR 0008 §2): "Archon-x" is not reserved. */
const RESERVED_DOMAIN_PREFIX = "archon-";

function as<T>(category: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof SignFailure) throw e;
    throw new SignFailure(category, e instanceof Error ? e.message : String(e));
  }
}

const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

export function run(args: string[]): void {
  if (wantsHelp(args)) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  const json = args.includes("--json");
  try {
    runSign(args.filter((a) => a !== "--json"), json);
  } catch (e) {
    if (json) {
      const category = e instanceof SignFailure ? e.category : "internal";
      process.stdout.write(`{"version":1,"error":${jsonString(category)}}\n`);
    }
    throw e;
  }
}

function runSign(argv: string[], json: boolean): void {
  const { rest: args, fd } = as("usage", () => takePasswordFd(argv));
  let keyFile: string | undefined;
  let seedHex: string | undefined;
  let keyName: string | undefined;
  let domain: string | undefined;
  let expectText: string | undefined;
  let inFile: string | undefined;
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]!;
    const value = args[i + 1];
    if (value === undefined || (value === "" && flag !== "--domain")) {
      throw new SignFailure("usage", `flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    }
    switch (flag) {
      case "--key-file":
        keyFile = value;
        break;
      case "--seed":
        seedHex = value;
        break;
      case "--key":
        keyName = value;
        break;
      case "--domain":
        domain = value;
        break;
      case "--expect":
        expectText = value;
        break;
      case "--in":
        inFile = value;
        break;
      default:
        throw new SignFailure("usage", `unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
    }
  }
  const sources = [keyFile, seedHex, keyName].filter((v) => v !== undefined).length;
  if (sources === 0) {
    throw new SignFailure("usage", `one of --key-file, --seed or --key is required\n${USAGE}`);
  }
  if (sources > 1) {
    throw new SignFailure("usage", `--key-file, --seed and --key are mutually exclusive\n${USAGE}`);
  }
  if (keyName !== undefined) {
    if (domain === undefined) {
      throw new SignFailure("usage", `--key needs --domain: archon's store does not sign raw\n${USAGE}`);
    }
    if (expectText === undefined) {
      throw new SignFailure(
        "usage",
        `--key needs --expect <principal>: \`archon key list --json\` shows it\n${USAGE}`,
      );
    }
  } else if (fd !== undefined) {
    throw new SignFailure("usage", `--password-fd applies only to --key\n${USAGE}`);
  }

  // The domain is checked by the core's own rule before anything is read or asked for:
  // signing nothing with a throwaway key refuses exactly what ADR 0008 §2 refuses, and no
  // copy of that rule lives here to drift from it.
  if (domain !== undefined) {
    const d = domain;
    as("domain", () => signInDomain(new Uint8Array(32), d, new Uint8Array(0)));
    if (d.startsWith(RESERVED_DOMAIN_PREFIX)) {
      throw new SignFailure(
        "domain",
        `domain ${jsonString(d)} is reserved: ${RESERVED_DOMAIN_PREFIX}* domains are signed only by ` +
          "archon's own commands, which show what they sign",
      );
    }
  }
  const expected =
    expectText === undefined ? undefined : as("usage", () => decodeKey(expectText as string));

  let seed: Uint8Array;
  let principal: Uint8Array;
  if (keyName !== undefined && expected !== undefined && domain !== undefined) {
    const name = keyName;
    // One read of the file: the header checked here is the header the tag authenticates at
    // unlock, policy included (docs/keystore.md §8.2, ADR 0012 §4).
    let stored: { file: Uint8Array; header: KeyHeader };
    try {
      stored = usableKey(name);
    } catch (e) {
      if (e instanceof StoreRefusal) throw new SignFailure(e.category, e.message);
      throw new SignFailure("no-key", e instanceof Error ? e.message : String(e));
    }
    if (!same(stored.header.publicKey, expected)) {
      throw new SignFailure(
        "key-mismatch",
        `key ${name} is ${encodeKey(stored.header.publicKey)}, not the expected ${encodeKey(expected)}; refusing to sign`,
      );
    }
    // Refused before the message is read or a password is asked for.
    const policy = stored.header.policy;
    if (policy === null || !permits(policy, domain)) {
      throw new SignFailure(
        "policy",
        `key ${name} may not sign in domain ${jsonString(domain)}: its policy is ${describePolicy(policy)}`,
      );
    }
    const message = as("input", () => readBytes(inFile));
    const preamble =
      `signing ${message.length} bytes (sha256 ${createHash("sha256").update(message).digest("hex")}) ` +
      `in domain ${jsonString(domain)} with ${name} (${encodeKey(expected)})\n`;
    let entry: PasswordEntry;
    try {
      entry = readPasswordEntry(fd, false, preamble);
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      throw new SignFailure(why === "interrupted" ? "cancelled" : "password", why);
    }
    seed = as("unlock-failed", () => openEntered(name, stored.file, entry));
    principal = getPublicKey(seed);
    if (!same(principal, expected)) {
      throw new SignFailure("key-mismatch", `key ${name} did not open to the expected key; refusing to sign`);
    }
    emit(seed, principal, domain, message, json);
    return;
  }

  seed = as("input", () => resolveSeed(seedHex, keyFile, USAGE));
  principal = getPublicKey(seed);
  if (expected !== undefined && !same(principal, expected)) {
    throw new SignFailure(
      "key-mismatch",
      `the key is ${encodeKey(principal)}, not the expected ${encodeKey(expected)}; refusing to sign`,
    );
  }
  const message = as("input", () => readBytes(inFile));
  emit(seed, principal, domain, message, json);
}

/** Signs, checks the signature against what was REQUESTED, and prints it. */
function emit(
  seed: Uint8Array,
  principal: Uint8Array,
  domain: string | undefined,
  message: Uint8Array,
  json: boolean,
): void {
  const sig = domain !== undefined ? signInDomain(seed, domain, message) : sign(message, seed);
  const checked =
    domain !== undefined ? verifyInDomain(principal, domain, message, sig) : verify(sig, message, principal);
  if (!checked) throw new SignFailure("internal", "the signature did not verify; nothing was printed");
  if (!json) {
    process.stdout.write(`${toHex(sig)}\n`);
    return;
  }
  const scheme = domain !== undefined ? "ed25519ph-context" : "ed25519-raw";
  const domainMember = domain !== undefined ? `,"domain":${jsonString(domain)}` : "";
  process.stdout.write(
    `{"version":1,"principal":${jsonString(encodeKey(principal))},"scheme":${jsonString(scheme)}` +
      `${domainMember},"signature":${jsonString(toHex(sig))}}\n`,
  );
}
