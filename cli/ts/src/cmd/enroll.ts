// `archon enroll` (docs/enroll.md §4, ADR 0013): make the enrollment proof for a key in the
// store, but only after showing the person which account the key joins, decoded from the very
// intent bytes whose digest the proof binds. The challenge arrives as a token the person carries
// from the signed-in page; the proof leaves as a token they carry back. The command contacts no
// server, so its success means a proof was produced, never that the key is enrolled.
import { closeSync, openSync, readSync } from "node:fs";
import { createInterface } from "node:readline";

import { encodeKey, getPublicKey } from "@bitspark/archon";
import {
  decodeEnrollChallenge,
  ENROLL_DOMAIN,
  ENROLL_MAX_TOKEN_SIZE,
  encodeEnrollProof,
  enrollChallengeRequest,
  proveEnroll,
  verifyEnroll,
  type EnrollChallenge,
  type EnrollIntent,
} from "@bitspark/archon-sdk";

import { jsonString, wantsHelp } from "../io.js";
import * as keystore from "../keystore.js";
import {
  openControllingTerminal,
  openEntered,
  readDefaultKeyName,
  readPasswordEntry,
  readTerminalLine,
  takePasswordFd,
  usableKey,
} from "./key_store.js";
import { formatRfc3339Utc, selectedAudience } from "./login.js";

export const USAGE =
  "usage: archon enroll [--challenge-file <file>] [--audience <base>] [--key <name>] [--password-fd <n>]\n" +
  "  makes the enrollment proof for a key in the store, after showing which account it joins\n" +
  "  (docs/enroll.md). The challenge token is read from --challenge-file, or one line of stdin;\n" +
  "  the audience is --audience or ARCHON_AUDIENCE; the key is --key or the default key. The\n" +
  "  question is asked on the terminal, always, and the proof token is printed on stdout.";

/** The one purpose version 1 renders (docs/enroll.md §2). */
const PURPOSE = "add-key";

/** What is read before decoding: a token and its surrounding whitespace. */
const MAX_INPUT = 1 << 20;

const NO_TERMINAL =
  "enroll: there is no terminal to ask on; archon enroll asks every time, and a password from " +
  "ARCHON_KEY_PASSWORD or --password-fd does not answer it";

/** Where the command meets the world, so a test can stand in for the terminal and the clock. */
export interface EnrollIo {
  /** The controlling terminal: where the statement is shown and the question asked. */
  openTerminal(): { readLine(): string; write(text: string): void; close(): void };
  /** One line of stdin, and whether stdin is a terminal (whose line limit can cut a token). */
  readStdinLine(): Promise<{ text: string; fromTerminal: boolean }>;
  stdout(text: string): void;
  /** Unix seconds. */
  now(): number;
}

const realIo: EnrollIo = {
  openTerminal() {
    const terminal = openControllingTerminal();
    return {
      readLine: () => readTerminalLine(terminal),
      write: (text) => terminal.io.write(text),
      close: () => terminal.close(),
    };
  },
  async readStdinLine() {
    const fromTerminal = process.stdin.isTTY === true;
    const rl = createInterface({ input: process.stdin });
    const text = await new Promise<string>((resolve) => {
      rl.once("line", (value) => resolve(value));
      rl.once("close", () => resolve(""));
    });
    rl.close();
    return { text, fromTerminal };
  },
  stdout: (text) => process.stdout.write(text),
  now: () => Math.floor(Date.now() / 1000),
};

export async function run(args: string[], io: EnrollIo = realIo): Promise<void> {
  if (wantsHelp(args)) {
    io.stdout(`${USAGE}\n`);
    return;
  }
  const { rest, fd } = takePasswordFd(args);
  let challengeFile: string | undefined;
  let audienceFlag: string | undefined;
  let keyName: string | undefined;
  for (let i = 0; i < rest.length; i += 2) {
    const flag = rest[i]!;
    const value = rest[i + 1];
    if (value === undefined || value === "") throw new Error(`flag ${JSON.stringify(flag)} needs a value\n${USAGE}`);
    if (flag === "--challenge-file") challengeFile = value;
    else if (flag === "--audience") audienceFlag = value;
    else if (flag === "--key") keyName = value;
    else throw new Error(`unknown flag ${JSON.stringify(flag)}\n${USAGE}`);
  }
  if (challengeFile === undefined && fd === 0) {
    throw new Error("enroll: --password-fd 0 and a challenge token on stdin would read the same stream; pass the token with --challenge-file");
  }

  // 1. The entry: one read, whose header the seal authenticates at unlock (ADR 0012 §4).
  const name = keyName ?? readDefaultKeyName();
  if (name === undefined || name === "") {
    throw new Error("enroll: no default key is set; pass --key <name>, or choose one with: archon key default <name>");
  }
  const { file, header } = usableKey(name);
  if (header.policy === null || !keystore.permits(header.policy, ENROLL_DOMAIN)) {
    throw new Error(policyRefusal(name, header.policy));
  }

  // 2. The audience the person selected, and a terminal to ask on.
  const audience = selectedAudience("enroll", "the audience is your configuration, never a token's word (docs/enroll.md §4)", audienceFlag);
  let terminal: ReturnType<EnrollIo["openTerminal"]>;
  try {
    terminal = io.openTerminal();
  } catch {
    throw new Error(NO_TERMINAL);
  }
  try {
    // 3. The token, read and decoded once. From here on only these values are used.
    const { text, fromTerminal } = challengeFile !== undefined ? { text: readChallengeFile(challengeFile), fromTerminal: false } : await io.readStdinLine();
    let ch: EnrollChallenge;
    try {
      ch = decodeEnrollChallenge(text);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        fromTerminal ? `${message} (a terminal cuts a long pasted line; save the token to a file and pass --challenge-file)` : message,
      );
    }

    // 4.–7. Everything decidable before the person is asked.
    checkChallenge(ch, audience, header.publicKey, io.now());
    const { request, intent } = enrollChallengeRequest(ch);
    if (intent.purpose !== PURPOSE) {
      throw new Error(`enroll: the intent's purpose is ${jsonString(intent.purpose)}; this archon renders only "${PURPOSE}", so it signs nothing else`);
    }

    // 8. Show, and ask on the terminal.
    terminal.write(renderStatement(audience, intent, header.publicKey, ch.deadline, `the store key ${name}`) + prompt(intent));
    const answer = terminal.readLine().trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") {
      terminal.write("refused. nothing was signed.\n");
      return;
    }

    // 9. Only now is the key unlocked: the same snapshot, its header now authenticated.
    const seed = openEntered(name, file, readPasswordEntry(fd, false));
    try {
      if (!keystore.permits(header.policy, ENROLL_DOMAIN)) throw new Error(policyRefusal(name, header.policy));
      const opened = getPublicKey(seed);
      if (!equal(opened, header.publicKey) || !equal(header.publicKey, ch.newKey)) {
        throw new Error(`enroll: key ${name} did not open to the key that was shown; nothing was signed`);
      }

      // 10. The proof, over what was shown, checked before it is printed.
      const proof = proveEnroll(seed, audience, request);
      if (!verifyEnroll(audience, request, proof)) throw new Error("enroll: the proof did not verify; nothing was printed");
      const token = encodeEnrollProof({ transaction: request.transaction, newKey: request.newKey, proof });

      // 11. The proof token on stdout, alone; the person is told what it is not.
      io.stdout(`${token}\n`);
      terminal.write("proof produced. paste it into the service's page: the key is enrolled only when the page completes.\n");
    } finally {
      seed.fill(0);
    }
  } finally {
    terminal.close();
  }
}

/** Steps 4 to 6 of docs/enroll.md §4: the token's audience is the selected one, its key is the
 *  entry's, and its deadline is still ahead. The token's audience is display-safe already (the
 *  codec refuses otherwise), and is JSON-quoted to show where it ends. */
export function checkChallenge(ch: EnrollChallenge, audience: string, key: Uint8Array, now: number): void {
  if (ch.audience !== audience) {
    throw new Error(
      `enroll: the token is for ${jsonString(ch.audience)}, not the audience you selected, ${jsonString(audience)}; nothing was shown or signed`,
    );
  }
  if (!equal(ch.newKey, key)) {
    throw new Error(`enroll: the token enrolls ${encodeKey(ch.newKey)}, not this key, ${encodeKey(key)}; nothing was shown or signed`);
  }
  if (now >= ch.deadline) {
    throw new Error(`enroll: the request's deadline, about ${formatRfc3339Utc(ch.deadline)}, has passed; begin again on the service's page`);
  }
}

/** The statement of docs/enroll.md §4, byte-identical in every lane
 *  (cli/testdata/enroll-statement.json). */
export function renderStatement(audience: string, intent: EnrollIntent, key: Uint8Array, deadline: number, keySource: string): string {
  let out = `${audience} asks you to add a key to an account:\n`;
  out += `  account:      ${intent.accountName}\n`;
  out += `  account id:   ${intent.accountId}\n`;
  out += `  key:          ${encodeKey(key)}\n`;
  if (intent.restrictions.length === 0) {
    out += "  restrictions: none\n";
  } else {
    out += "  restrictions:\n";
    for (const r of intent.restrictions) out += `    ${r}\n`;
  }
  out += "the service may give this key the account's authority.\n";
  out += `the request's deadline is about ${formatRfc3339Utc(deadline)}, the service's word; it is not the key's expiry.\n`;
  out += `signing with ${keySource}\n`;
  return out;
}

/** The question, naming the account the person is agreeing to, in plain quotes. */
export function prompt(intent: EnrollIntent): string {
  return `add this key to the account "${intent.accountName}"? [y/N] `;
}

/** A context every shell receives as itself, unquoted: sh, cmd.exe and PowerShell alike. A
 *  leading `@` or `-` is left out, since PowerShell and flag parsers read those as something
 *  else (docs/enroll.md §4 step 1). */
const BARE_CONTEXT = /^[A-Za-z0-9][A-Za-z0-9._/:+=-]*$/;

/** Why the entry may not enroll, and how to change that. `key policy` replaces a list rather
 *  than adding to it, so the command printed names every context the entry keeps, then
 *  archon-enroll/1; it is printed only when every context needs no quoting in any shell, and
 *  otherwise the contexts are listed JSON-quoted. */
export function policyRefusal(name: string, policy: keystore.Policy | null): string {
  const head = `enroll: key ${name} may not sign in ${ENROLL_DOMAIN}: its policy is ${keystore.describePolicy(policy)}`;
  if (policy === null) return head;
  if (policy.contexts.length >= keystore.MAX_CONTEXTS) {
    return `${head}.\n  it already lists ${keystore.MAX_CONTEXTS} contexts, the most a policy holds: drop one with archon key policy, or keep a separate key for enrollment`;
  }
  if (!policy.contexts.every((c) => BARE_CONTEXT.test(c))) {
    return `${head}.\n  key policy replaces the list: run archon key policy ${name} with --allow for each of ${policy.contexts.map(jsonString).join(", ")}, and for ${ENROLL_DOMAIN}`;
  }
  const command = [`archon key policy ${name}`, ...policy.contexts.map((c) => `--allow ${c}`), `--allow ${ENROLL_DOMAIN}`].join(" ");
  return `${head}.\n  to let it enroll, keeping what it has (key policy replaces the list):\n    ${command}`;
}

function readChallengeFile(path: string): string {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (err) {
    throw new Error(`enroll: could not read ${JSON.stringify(path)}: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    const buf = Buffer.alloc(MAX_INPUT + 1);
    let n = 0;
    for (;;) {
      const got = readSync(fd, buf, n, buf.length - n, null);
      if (got === 0) break;
      n += got;
      if (n > MAX_INPUT) {
        throw new Error(`enroll: ${JSON.stringify(path)} is over ${MAX_INPUT} bytes; a challenge token is at most ${ENROLL_MAX_TOKEN_SIZE}`);
      }
    }
    return buf.subarray(0, n).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
