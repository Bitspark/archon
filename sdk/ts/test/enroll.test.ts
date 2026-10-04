// Key enrollment (docs/request.md §6): what the vectors leave to the lanes — the oversize
// binding and the signer seam. The bytes themselves are pinned by vectors/request.json.
import { test } from "node:test";
import assert from "node:assert/strict";

import { getPublicKey } from "@bitspark/archon";
import {
  enrollBinding,
  MAX_FIELD_SIZE,
  proveEnroll,
  proveEnrollWith,
  seedSigner,
  verifyEnroll,
  type EnrollRequest,
} from "../src/index.js";

const AUDIENCE = "https://dawn.example/api";
const seedN = new Uint8Array(32).fill(0x44);

function request(): EnrollRequest {
  return {
    nonce: new Uint8Array(16).fill(0xcc),
    transaction: new TextEncoder().encode("txn-1"),
    purpose: "add-key",
    newKey: getPublicKey(seedN),
    intentDigest: new Uint8Array(32).fill(0x5f),
  };
}

test("a binding over the possession field is refused", () => {
  const room = MAX_FIELD_SIZE - (1 + 2 + 7 + 2 + 2 + 5 + 32 + 32);
  assert.equal(enrollBinding("a".repeat(room), request()).length, MAX_FIELD_SIZE);
  assert.throws(() => enrollBinding("a".repeat(room + 1), request()), /over the possession scheme/);
});

test("through a signer the proof is the seed's bytes, and only the new key signs", async () => {
  const want = proveEnroll(seedN, AUDIENCE, request());
  const got = await proveEnrollWith(seedSigner(seedN), AUDIENCE, request());
  assert.deepEqual(got, want);
  assert.equal(verifyEnroll(AUDIENCE, request(), got), true);
  await assert.rejects(proveEnrollWith(seedSigner(new Uint8Array(32).fill(0x11)), AUDIENCE, request()), /not the expected key/);
});
