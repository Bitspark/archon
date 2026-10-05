// archon#93: the delegation is [acceptedAt, acceptedAt + valid_for), and acceptedAt is the
// server's clock when it ACCEPTED the answer — taken once, handed to the law, and returned with
// the collected answer. The same cases as the Go lane's (server/go/login/accepted_test.go): they
// go red if the time is stamped at collection, if the law and the collecting client are told
// different instants, or if a refused answer before the accepted one moves it.

import test from "node:test";
import assert from "node:assert/strict";

import { encodeKey, getPublicKey } from "@bitspark/archon";
import { proveCollect, proveLogin, type LoginRequest } from "@bitspark/archon-sdk";

import { COLLECT_HEADER, Handler, type AdmitAuthority } from "../src/login.js";
import { fromHex, rfc3339, toHex } from "../src/json.js";

const AUDIENCE = "https://dawn.example/api";
const ORIGIN = "http://localhost:9999";
const T0 = 1_789_034_640;

function seedFor(b: number): Uint8Array {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = (b + i) & 0xff;
  return seed;
}

function harness(admit?: AdmitAuthority): { handler: Handler; now: { seconds: number } } {
  const now = { seconds: T0 };
  let n = 0;
  const handler = new Handler({
    audience: AUDIENCE,
    ...(admit === undefined ? {} : { admit }),
    clock: () => now.seconds,
    entropy: (size) => new Uint8Array(size).fill(++n & 0xff),
  });
  return { handler, now };
}

/** Begin, wait, answer `answers` times 4 s apart, wait, collect: the collected body. */
async function acceptLater(
  h: { handler: Handler; now: { seconds: number } },
  beforeAnswer: number,
  beforeCollect: number,
  answers = 1,
): Promise<Record<string, unknown>> {
  const browserSeed = seedFor(3);
  const personSeed = seedFor(150);
  const browser = getPublicKey(browserSeed);
  const scope = ["read:projects"];
  const begun = await h.handler.handle(
    new Request(`${ORIGIN}/`, { method: "POST", body: JSON.stringify({ browser: encodeKey(browser), scope, valid_for: 3600 }) }),
  );
  assert.equal(begun.status, 201);
  const opened = (await begun.json()) as Record<string, string>;
  const req: LoginRequest = { id: fromHex(opened["id"]!), nonce: fromHex(opened["nonce"]!), browser, scope, validFor: 3600 };
  const proof = proveLogin(personSeed, AUDIENCE, req);
  h.now.seconds += beforeAnswer;
  for (let i = 0; i < answers; i++) {
    await h.handler.handle(
      new Request(`${ORIGIN}/${opened["id"]}/answer`, {
        method: "POST",
        body: JSON.stringify({ principal: encodeKey(getPublicKey(personSeed)), possession: toHex(proof) }),
      }),
    );
    h.now.seconds += 4;
  }
  h.now.seconds += beforeCollect;
  const collected = await h.handler.handle(
    new Request(`${ORIGIN}/${opened["id"]}/answer`, { headers: { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) } }),
  );
  assert.equal(collected.status, 200);
  return (await collected.json()) as Record<string, unknown>;
}

test("the delegation starts when the answer is accepted", async () => {
  const seen: number[] = [];
  const h = harness((_b, _p, _a, req) => void seen.push(req.acceptedAt));
  const got = await acceptLater(h, 7, 40);
  assert.deepEqual(seen, [T0 + 7], "the law is handed the instant the answer was accepted");
  // Collected 44 s later than that, and still the acceptance instant: collection cannot move it.
  assert.equal(got["accepted_at"], rfc3339(T0 + 7));
});

test("a refused answer does not start the delegation", async () => {
  let calls = 0;
  let accepted: number | undefined;
  const h = harness((_b, _p, _a, req) => {
    calls += 1;
    if (calls === 1) throw new Error("not yet");
    accepted = req.acceptedAt;
  });
  // Two answers 4 s apart: the law refuses the first and accepts the second.
  const got = await acceptLater(h, 5, 10, 2);
  assert.equal(accepted, T0 + 9);
  assert.equal(got["accepted_at"], rfc3339(T0 + 9), "the answer that was STORED starts it");
});

test("a proof-only service is told the start too", async () => {
  // No law, so nothing is handed Admitted: the collected answer is how such a service learns it.
  const got = await acceptLater(harness(), 3, 20);
  assert.equal(got["accepted_at"], rfc3339(T0 + 3));
});

test("acceptedAt is whole seconds, and the law and the collected answer agree", async () => {
  let seen: number | undefined;
  const h = harness((_b, _p, _a, req) => void (seen = req.acceptedAt));
  h.now.seconds += 0.7;
  const got = await acceptLater(h, 0, 10);
  assert.ok(Number.isInteger(seen), `acceptedAt ${seen} is not whole seconds`);
  assert.equal(got["accepted_at"], rfc3339(seen!));
});
