import { test } from "node:test";
import assert from "node:assert/strict";

import {
  getPublicKey,
  sign,
  verify,
  signInDomain,
  verifyInDomain,
  MAX_DOMAIN_SIZE,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE,
  toHex,
  seedFromHex,
  pubkeyFromHex,
  signatureFromHex,
} from "../src/index.js";

const seed = new Uint8Array(32).fill(0x09);
const pk = getPublicKey(seed);
const msg = new TextEncoder().encode("the law laid down");

test("a domain separates, and raw never crosses", () => {
  const sigA = signInDomain(seed, "archon/test/a", msg);
  assert.equal(verifyInDomain(pk, "archon/test/a", msg, sigA), true);
  assert.equal(verifyInDomain(pk, "archon/test/b", msg, sigA), false, "other domain");
  assert.equal(verify(sigA, msg, pk), false, "never raw");
  assert.equal(verifyInDomain(pk, "archon/test/a", msg, sign(msg, seed)), false, "raw never in-domain");
  assert.equal(verifyInDomain(pk, "archon/test/a", new TextEncoder().encode("other"), sigA), false);
  assert.equal(verifyInDomain(new Uint8Array(PUBLIC_KEY_SIZE), "archon/test/a", msg, sigA), false);
});

test("domain bounds: empty rejected, 255 accepted, 256 rejected", () => {
  assert.throws(() => signInDomain(seed, "", msg));
  assert.equal(verifyInDomain(pk, "", msg, new Uint8Array(SIGNATURE_SIZE)), false);
  const max = "d".repeat(MAX_DOMAIN_SIZE);
  const sig = signInDomain(seed, max, msg);
  assert.equal(verifyInDomain(pk, max, msg, sig), true);
  const over = max + "d";
  assert.throws(() => signInDomain(seed, over, msg));
  assert.equal(verifyInDomain(pk, over, msg, sig), false);
});

test("the OpenSSL 3.2.4 reference: seed 0x11*32, domain archon/test/v1, message 'hello'", () => {
  const s11 = new Uint8Array(32).fill(0x11);
  const sig = signInDomain(s11, "archon/test/v1", new TextEncoder().encode("hello"));
  assert.equal(
    toHex(sig),
    "6608574ea7800d10158d90b3c81318b998505ccc09e9f66e35d47fefe1daa13354bdc3e378a4348b224e7dbe21afb1503a2454a5fa6a27464118d7fad3d5c600",
  );
});

test("hexbytes round-trips, lowercases, and fails closed", () => {
  const s = new Uint8Array(32).fill(0xab);
  assert.equal(toHex(s), "ab".repeat(32));
  assert.deepEqual(seedFromHex("ab".repeat(32)), s);
  assert.deepEqual(seedFromHex("AB".repeat(32)), s);
  assert.deepEqual(pubkeyFromHex(toHex(pk)), pk);
  const sig = new Uint8Array(64).fill(0x5a);
  assert.deepEqual(signatureFromHex(toHex(sig)), sig);
  for (const bad of ["ab".repeat(31), "ab".repeat(33), "ab".repeat(31) + "a", "ab".repeat(31) + "zz", "0x" + "ab".repeat(31), ""]) {
    assert.throws(() => seedFromHex(bad), `accepted ${JSON.stringify(bad)}`);
  }
  assert.throws(() => signatureFromHex("ab".repeat(32)), "a key is not a signature");
});
