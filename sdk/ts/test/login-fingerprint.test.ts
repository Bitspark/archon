import { test } from "node:test";
import assert from "node:assert/strict";

import { sha256 } from "@noble/hashes/sha2.js";
import { getPublicKey } from "@bitspark/archon";
import {
  formatFingerprint,
  loginBinding,
  fingerprint,
  FINGERPRINT_DOMAIN,
  LOGIN_MAX_FIELD_SIZE,
  LOGIN_ROLE_COLLECT,
  LOGIN_ROLE_LOGIN,
  type LoginRequest,
} from "../src/index.js";

const seedP = new Uint8Array(32).fill(0x11);
const seedK = new Uint8Array(32).fill(0x22);
const audience = "https://dawn.example/api";
const utf8 = new TextEncoder();

function request(): LoginRequest {
  return {
    id: utf8.encode("req-1"),
    nonce: new Uint8Array(16).fill(0xaa),
    browser: getPublicKey(seedK),
    scope: ["read:projects", "read:campaigns"],
    validFor: 28800,
  };
}

// The digest recomputed from docs/login.md §5.3 with the domain spelled out here, not taken
// from the constant, so a change to either is caught.
test("fingerprint layout: SHA-256 over the domain, the nonce and the login binding, first 16 bytes", () => {
  const req = request();
  const fp = fingerprint(audience, req);
  const domain = utf8.encode("archon-login-fingerprint/1");
  const prefix = [0x00, domain.length, ...domain, 0x00, req.nonce.length, ...req.nonce];
  const binding = loginBinding(LOGIN_ROLE_LOGIN, audience, req);
  assert.deepEqual([...fp], [...sha256(new Uint8Array([...prefix, ...binding])).subarray(0, 16)]);
  assert.equal(FINGERPRINT_DOMAIN, "archon-login-fingerprint/1");
  const collect = loginBinding(LOGIN_ROLE_COLLECT, audience, req);
  assert.notDeepEqual([...fp], [...sha256(new Uint8Array([...prefix, ...collect])).subarray(0, 16)], "the collect role");
});

// The comparison is only worth making if a substitution of any field the proof binds, or of
// the nonce, changes what the person reads.
test("fingerprint: deterministic, and every bound field and the nonce change it", () => {
  const base = formatFingerprint(fingerprint(audience, request()));
  assert.equal(formatFingerprint(fingerprint(audience, request())), base);
  const req = request();
  const tampers: Array<[string, string, Partial<LoginRequest>]> = [
    ["audience", "https://evil.example/api", {}],
    ["browser", audience, { browser: getPublicKey(seedP) }],
    ["id", audience, { id: utf8.encode("req-2") }],
    ["nonce", audience, { nonce: new Uint8Array(16).fill(0xab) }],
    ["nonce length", audience, { nonce: new Uint8Array(17).fill(0xaa) }],
    ["scope order", audience, { scope: [...req.scope].reverse() }],
    ["scope entry", audience, { scope: ["read:projects", "write:campaigns"] }],
    ["scope extra", audience, { scope: [...req.scope, "admin"] }],
    ["valid_for", audience, { validFor: 28801 }],
  ];
  for (const [name, aud, patch] of tampers) {
    assert.notEqual(formatFingerprint(fingerprint(aud, { ...request(), ...patch })), base, name);
  }
});

// What the vectors do not carry — the nonce over the u16 field, a 130 KB vector — beside the
// shorter refusals they do.
test("fingerprint refusals", () => {
  const cases: Array<[string, string, Partial<LoginRequest>]> = [
    ["short nonce", audience, { nonce: new Uint8Array(15) }],
    ["empty nonce", audience, { nonce: new Uint8Array(0) }],
    ["nonce over the u16 field", audience, { nonce: new Uint8Array(LOGIN_MAX_FIELD_SIZE + 1) }],
    ["empty audience", "", {}],
    ["browser wrong size", audience, { browser: new Uint8Array(31) }],
    ["empty id", audience, { id: new Uint8Array(0) }],
    ["zero validity", audience, { validFor: 0 }],
    ["lone surrogate in scope", audience, { scope: ["read:\ud800projects"] }],
  ];
  for (const [name, aud, patch] of cases) {
    assert.throws(() => fingerprint(aud, { ...request(), ...patch }), name);
  }
  assert.doesNotThrow(() => fingerprint(audience, { ...request(), nonce: new Uint8Array(LOGIN_MAX_FIELD_SIZE) }));
});

test("formatFingerprint: eight groups of four lowercase hex digits", () => {
  assert.equal(formatFingerprint(Uint8Array.from({ length: 16 }, (_, i) => i)), "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f");
  assert.equal(formatFingerprint(new Uint8Array(16).fill(0xff)), "ffff ffff ffff ffff ffff ffff ffff ffff");
  const example = Uint8Array.from([0x7a, 0x91, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f]);
  assert.equal(formatFingerprint(example), "7a91 b2c3 d4e5 f607 1829 3a4b 5c6d 7e8f");
  assert.throws(() => formatFingerprint(new Uint8Array(15)));
  assert.throws(() => formatFingerprint(new Uint8Array(32)));
});
