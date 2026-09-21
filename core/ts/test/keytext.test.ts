import { test } from "node:test";
import assert from "node:assert/strict";

import { encodeKey, decodeKey } from "../src/index.js";

const u8 = (n: number, len = 32): Uint8Array => new Uint8Array(len).fill(n);

test("encode fixed form", () => {
  assert.equal(encodeKey(u8(0x11)), "ed25519:" + "11".repeat(32));
});

test("round-trip", () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  assert.deepEqual(decodeKey(encodeKey(key)), key);
});

test("decode accepts uppercase hex", () => {
  assert.deepEqual(decodeKey("ed25519:" + "AB".repeat(32)), decodeKey("ed25519:" + "ab".repeat(32)));
});

test("decode rejects missing prefix", () => {
  assert.throws(() => decodeKey("11".repeat(32)));
});

test("decode rejects odd-length body", () => {
  assert.throws(() => decodeKey("ed25519:111"));
});

test("decode rejects non-hex body", () => {
  assert.throws(() => decodeKey("ed25519:" + "zz".repeat(32)));
});

test("decode rejects wrong decoded length", () => {
  assert.throws(() => decodeKey("ed25519:" + "11".repeat(31)));
  assert.throws(() => decodeKey("ed25519:" + "11".repeat(33)));
});
