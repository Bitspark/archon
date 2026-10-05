// `archon enroll` (docs/enroll.md §4): the statement and the policy refusal against the fixture
// all three lanes read, then the command itself against a sealed store key, with the terminal,
// stdin and the clock played by an EnrollIo, and every refusal checked for where it lands:
// before the statement, or after a "no", and never with anything on stdout.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeKey, encodeKey, getPublicKey } from "@bitspark/archon";
import {
  decodeEnrollChallenge,
  decodeEnrollProof,
  ENROLL_DOMAIN,
  ENROLL_PROOF_PREFIX,
  encodeEnrollChallenge,
  encodeEnrollIntent,
  enrollChallengeRequest,
  verifyEnroll,
  type EnrollChallenge,
  type EnrollIntent,
} from "@bitspark/archon-sdk";

import { checkChallenge, policyRefusal, prompt, renderStatement, run, type EnrollIo } from "../src/cmd/enroll.js";
import { sealAndWrite } from "../src/cmd/key_store.js";
import * as keystore from "../src/keystore.js";

interface Fixture {
  cases: Array<{
    name: string;
    audience: string;
    intent: { account_id: string; account_name: string; restrictions: string[] };
    key: string;
    deadline: number;
    keySource: string;
    statement: string;
    prompt: string;
  }>;
  policy_cases: Array<{ name: string; key: string; policy: { contexts: string[] }; refusal: string }>;
}
const fixture = JSON.parse(readFileSync("../testdata/enroll-statement.json", "utf8")) as Fixture;

test("the statement and the prompt are the fixture's", () => {
  assert.ok(fixture.cases.length > 0);
  for (const c of fixture.cases) {
    const intent: EnrollIntent = {
      blind: new Uint8Array(16),
      accountId: c.intent.account_id,
      accountName: c.intent.account_name,
      purpose: "add-key",
      restrictions: c.intent.restrictions,
    };
    assert.equal(renderStatement(c.audience, intent, decodeKey(c.key), c.deadline, c.keySource), c.statement, c.name);
    assert.equal(prompt(intent), c.prompt, c.name);
  }
});

test("the policy refusal is the fixture's", () => {
  assert.ok(fixture.policy_cases.length > 0);
  for (const c of fixture.policy_cases) {
    assert.equal(policyRefusal(c.key, { unrestricted: false, contexts: c.policy.contexts }), c.refusal, c.name);
  }
});

const AUDIENCE = "https://bitshelf.dev/api";
const NOW = Date.UTC(2026, 9, 5, 10, 30, 0) / 1000;
const PASSWORD = "a password with a space";

interface World {
  home: string;
  key: Uint8Array;
  io: EnrollIo;
  terminal: string[];
  stdout: string[];
}

function world(policy: keystore.Policy, answer: string, opts: { noTerminal?: boolean } = {}): World {
  const home = mkdtempSync(join(tmpdir(), "archon-enroll-"));
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 0x21);
  sealAndWrite(join(home, "keys", "personal"), seed, PASSWORD, policy);
  const terminal: string[] = [];
  const stdout: string[] = [];
  const io: EnrollIo = {
    openTerminal() {
      if (opts.noTerminal) throw new Error("no terminal");
      return { readLine: () => answer, write: (t) => terminal.push(t), close: () => {} };
    },
    stdinIsTerminal: () => false,
    readStdinLine: async () => "",
    stdout: (t) => stdout.push(t),
    now: () => NOW,
  };
  return { home, key: getPublicKey(seed), io, terminal, stdout };
}

function token(w: World, edit?: (c: EnrollChallenge, i: EnrollIntent) => void): string {
  const i: EnrollIntent = { blind: new Uint8Array(16), accountId: "u_8f3c2a", accountName: "julia (bitspark)", purpose: "add-key", restrictions: [] };
  const c: EnrollChallenge = {
    audience: AUDIENCE,
    transaction: Uint8Array.of(0x8f, 0x3c),
    nonce: new Uint8Array(16),
    newKey: w.key,
    intent: new Uint8Array(1),
    deadline: NOW + 15 * 60,
  };
  edit?.(c, i);
  c.intent = encodeEnrollIntent(i);
  const path = join(w.home, "challenge.txt");
  writeFileSync(path, `${encodeEnrollChallenge(c)}\n`);
  return path;
}

/** Runs the command with the store at w.home and the password in the environment. */
async function enroll(w: World, args: string[]): Promise<Error | undefined> {
  const saved = { home: process.env["ARCHON_HOME"], pw: process.env["ARCHON_KEY_PASSWORD"], aud: process.env["ARCHON_AUDIENCE"] };
  process.env["ARCHON_HOME"] = w.home;
  process.env["ARCHON_KEY_PASSWORD"] = PASSWORD;
  delete process.env["ARCHON_AUDIENCE"];
  try {
    await run(args, w.io);
    return undefined;
  } catch (err) {
    return err as Error;
  } finally {
    for (const [k, v] of [["ARCHON_HOME", saved.home], ["ARCHON_KEY_PASSWORD", saved.pw], ["ARCHON_AUDIENCE", saved.aud]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test("enroll makes the proof for what it showed", async () => {
  const w = world({ unrestricted: false, contexts: [ENROLL_DOMAIN] }, "y");
  try {
    const path = token(w, (_, i) => {
      i.restrictions = ["read:projects"];
    });
    const err = await enroll(w, ["--challenge-file", path, "--audience", AUDIENCE, "--key", "personal"]);
    assert.equal(err, undefined, err?.message ?? "");
    // stdout is the proof token and nothing else.
    assert.equal(w.stdout.length, 1);
    const line = w.stdout[0]!;
    assert.ok(line.startsWith(ENROLL_PROOF_PREFIX) && line.endsWith("\n") && line.indexOf("\n") === line.length - 1);
    const p = decodeEnrollProof(line);
    const { request } = enrollChallengeRequest(decodeEnrollChallenge(readFileSync(path, "utf8")));
    assert.ok(verifyEnroll(AUDIENCE, request, p.proof));
    const shown = w.terminal.join("");
    for (const want of [
      "https://bitshelf.dev/api asks you to add a key to an account:\n",
      "  account:      julia (bitspark)\n",
      `  key:          ${encodeKey(w.key)}\n`,
      "  restrictions:\n    read:projects\n",
      "signing with the store key personal\n",
      'add this key to the account "julia (bitspark)"? [y/N] ',
      "proof produced.",
    ]) {
      assert.ok(shown.includes(want), `the terminal did not show ${JSON.stringify(want)}:\n${shown}`);
    }
  } finally {
    rmSync(w.home, { recursive: true, force: true });
  }
});

const enrollOnly: keystore.Policy = { unrestricted: false, contexts: [ENROLL_DOMAIN] };
const refusals: Array<{
  name: string;
  policy?: keystore.Policy;
  answer?: string;
  edit?: (c: EnrollChallenge, i: EnrollIntent) => void;
  args?: (path: string) => string[];
  noTerminal?: boolean;
  want: string;
  shownYet?: boolean;
}> = [
  { name: "another audience", edit: (c) => { c.audience = "https://bitshelf.dev/other"; },
    want: 'the token is for "https://bitshelf.dev/other", not the audience you selected, "https://bitshelf.dev/api"' },
  { name: "another key", edit: (c) => { c.newKey = getPublicKey(new Uint8Array(32)); }, want: "not this key" },
  { name: "the deadline is now", edit: (c) => { c.deadline = NOW; }, want: "has passed" },
  { name: "a purpose this archon does not render", edit: (_, i) => { i.purpose = "rotate"; }, want: 'the intent\'s purpose is "rotate"' },
  { name: "a policy without archon-enroll/1", policy: { unrestricted: false, contexts: ["thesmos/fact/v2"] },
    want: "archon key policy personal --allow thesmos/fact/v2 --allow archon-enroll/1" },
  { name: "the person says no", answer: "n", want: "refused. nothing was signed.", shownYet: true },
  { name: "no answer at all", answer: "", want: "refused. nothing was signed.", shownYet: true },
  { name: "the token and the password on one stdin", args: () => ["--audience", AUDIENCE, "--key", "personal", "--password-fd", "0"], want: "--password-fd 0" },
  { name: "no audience", args: (path) => ["--challenge-file", path, "--key", "personal"], want: "no audience" },
  { name: "no terminal", noTerminal: true, want: "no terminal to ask on" },
];

for (const r of refusals) {
  test(`enroll refuses: ${r.name}`, async () => {
    const w = world(r.policy ?? enrollOnly, r.answer ?? "y", { noTerminal: r.noTerminal === true });
    try {
      const path = token(w, r.edit);
      const args = r.args?.(path) ?? ["--challenge-file", path, "--audience", AUDIENCE, "--key", "personal"];
      const err = await enroll(w, args);
      assert.deepEqual(w.stdout, [], "a refusal prints nothing on stdout");
      const got = err?.message ?? w.terminal.join("");
      assert.ok(got.includes(r.want), `got ${JSON.stringify(got)}, want it to contain ${JSON.stringify(r.want)}`);
      if (r.shownYet === true) assert.ok(err !== undefined, "a decline exited as a success: a script would carry on with an empty stdout");
      if (r.shownYet !== true) {
        assert.ok(!w.terminal.join("").includes("asks you to add a key"), "the statement was shown before a refusal that needed nothing from the person");
      }
    } finally {
      rmSync(w.home, { recursive: true, force: true });
    }
  });
}

test("checkChallenge refuses another audience, another key and a passed deadline", () => {
  const key = new Uint8Array(32).fill(7);
  const c = (audience: string, k: Uint8Array, deadline: number): EnrollChallenge => ({
    audience, transaction: Uint8Array.of(1), nonce: new Uint8Array(16), newKey: k, intent: Uint8Array.of(1), deadline,
  });
  checkChallenge(c(AUDIENCE, key, 1000), AUDIENCE, key, 999);
  assert.throws(() => checkChallenge(c("https://other.example", key, 1000), AUDIENCE, key, 999), /"https:\/\/other\.example"/);
  assert.throws(() => checkChallenge(c(AUDIENCE, new Uint8Array(32).fill(8), 1000), AUDIENCE, key, 999), /not this key/);
  assert.throws(() => checkChallenge(c(AUDIENCE, key, 1000), AUDIENCE, key, 1000), /has passed/);
});
