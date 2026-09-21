import { test } from "node:test";
import assert from "node:assert/strict";

import { seedToPkcs8Pem, pkcs8PemToSeed, pubkeyToSpkiPem, spkiPemToPubkey } from "../src/index.js";

const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
const pub = new Uint8Array(32).fill(0xab);

test("pkcs8 round-trip", () => {
  assert.deepEqual(pkcs8PemToSeed(seedToPkcs8Pem(seed)), seed);
});

test("spki round-trip", () => {
  assert.deepEqual(spkiPemToPubkey(pubkeyToSpkiPem(pub)), pub);
});

test("encode emits canonical single-line PEM", () => {
  const p = seedToPkcs8Pem(seed);
  assert.ok(p.startsWith("-----BEGIN PRIVATE KEY-----\n"));
  assert.ok(p.endsWith("\n-----END PRIVATE KEY-----\n"));
  assert.equal(p.split("\n").filter((l) => l.length > 0).length, 3); // header, one base64 line, footer
});

test("encode rejects non-32-byte input", () => {
  assert.throws(() => seedToPkcs8Pem(new Uint8Array(31)));
  assert.throws(() => pubkeyToSpkiPem(new Uint8Array(33)));
});

test("decode tolerates CRLF and trailing newlines", () => {
  const p = seedToPkcs8Pem(seed);
  assert.deepEqual(pkcs8PemToSeed(p.replace(/\n/g, "\r\n")), seed);
  assert.deepEqual(pkcs8PemToSeed(p + "\n\n"), seed);
  assert.deepEqual(pkcs8PemToSeed(p.replace(/\n+$/, "")), seed);
});

test("decode rejects cross-template, bare DER, bad base64, empty", () => {
  const validSpki = pubkeyToSpkiPem(pub);
  const validPkcs8 = seedToPkcs8Pem(seed);
  assert.throws(() => spkiPemToPubkey(validPkcs8)); // a PRIVATE KEY block handed to the SPKI decoder
  assert.throws(() => pkcs8PemToSeed(validSpki)); // a PUBLIC KEY block handed to the PKCS#8 decoder
  assert.throws(() => spkiPemToPubkey(validSpki.split("\n")[1] ?? "")); // bare base64, no PEM armor
  assert.throws(() => spkiPemToPubkey("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n")); // bad base64
  assert.throws(() => spkiPemToPubkey("")); // empty
});
