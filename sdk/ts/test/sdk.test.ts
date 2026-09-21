import { test } from "node:test";
import assert from "node:assert/strict";

import { getPublicKey, sign, signInDomain, PUBLIC_KEY_SIZE, SIGNATURE_SIZE } from "@bitspark/archon";
import {
  provePossession,
  verifyPossession,
  possessionMessageBytes,
  POSSESSION_SCHEME_TAG,
  seal,
  open,
} from "../src/index.js";

const seed = new Uint8Array(32).fill(0x09);
const pk = getPublicKey(seed);
const enc = (s: string) => new TextEncoder().encode(s);

test("possession: proves, and refuses every substitution", () => {
  const D = "archon/test/pop";
  const nonce = new Uint8Array(16).fill(0xaa);
  const binding = enc("session:1");
  const sig = provePossession(seed, D, nonce, binding);
  assert.equal(verifyPossession(pk, D, nonce, binding, sig), true);
  assert.equal(verifyPossession(pk, D, new Uint8Array(16).fill(0xab), binding, sig), false, "other nonce");
  assert.equal(verifyPossession(pk, D, nonce, enc("session:2"), sig), false, "other binding");
  assert.equal(verifyPossession(pk, "archon/test/other", nonce, binding, sig), false, "other domain");
  assert.equal(verifyPossession(new Uint8Array(PUBLIC_KEY_SIZE), D, nonce, binding, sig), false, "other key");
  const m = possessionMessageBytes(nonce, binding);
  assert.equal(verifyPossession(pk, D, nonce, binding, sign(m, seed)), false, "raw is not a proof");
  assert.equal(verifyPossession(pk, D, nonce, binding, signInDomain(seed, D, nonce)), false, "bare nonce is not a proof");
});

test("possession: short nonce and empty binding are refused", () => {
  const D = "archon/test/pop";
  assert.throws(() => provePossession(seed, D, new Uint8Array(15).fill(0xaa), enc("b")));
  assert.throws(() => provePossession(seed, D, new Uint8Array(16).fill(0xaa), new Uint8Array(0)));
  assert.throws(() => provePossession(seed, "", new Uint8Array(16).fill(0xaa), enc("b")));
  assert.equal(verifyPossession(pk, D, new Uint8Array(15).fill(0xaa), enc("b"), new Uint8Array(SIGNATURE_SIZE)), false);
  assert.equal(verifyPossession(pk, D, new Uint8Array(16).fill(0xaa), new Uint8Array(0), new Uint8Array(SIGNATURE_SIZE)), false);
});

test("possession: the layout is the pinned one", () => {
  const m = possessionMessageBytes(new Uint8Array(16).fill(0x11), enc("ab"));
  const want = new Uint8Array([POSSESSION_SCHEME_TAG, 0x00, 0x10, ...new Uint8Array(16).fill(0x11), 0x00, 0x02, 0x61, 0x62]);
  assert.deepEqual(m, want);
});

test("envelope: seals, opens, and refuses every tamper", () => {
  const D = "archon/test/env";
  const env = seal(seed, D, enc("payload"));
  const o = open(env, D);
  assert.deepEqual(o.pubkey, pk);
  assert.deepEqual(o.payload, enc("payload"));
  assert.equal(open(seal(seed, D, new Uint8Array(0)), D).payload.length, 0, "empty payload allowed");
  assert.throws(() => open(env, "archon/test/other"), /different domain/);
  const mut = (f: (b: Uint8Array) => void) => {
    const b = new Uint8Array(env);
    f(b);
    return b;
  };
  assert.throws(() => open(mut((b) => (b[b.length - 1]! ^= 1)), D), "payload tampered");
  assert.throws(() => open(mut((b) => (b[0] = 0x78)), D), "bad magic");
  assert.throws(() => open(mut((b) => (b[4] = 0x02)), D), "unknown version");
  assert.throws(() => open(mut((b) => (b[6]! ^= 1)), D), "domain bytes altered");
  assert.throws(() => open(env.subarray(0, env.length - 8), D), "truncated");
  assert.throws(() => open(env.subarray(0, 10), D), "far too short");
  const other = seal(new Uint8Array(32).fill(0x0a), D, enc("payload"));
  const sigAt = 4 + 1 + 1 + D.length + PUBLIC_KEY_SIZE;
  assert.throws(() => open(mut((b) => b.set(other.subarray(sigAt, sigAt + SIGNATURE_SIZE), sigAt)), D), "another key's signature");
});
