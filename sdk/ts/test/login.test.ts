import { test } from "node:test";
import assert from "node:assert/strict";

import { getPublicKey, sign } from "@bitspark/archon";
import {
  loginBinding,
  proveLogin,
  verifyLogin,
  proveCollect,
  verifyCollect,
  provePossession,
  possessionMessageBytes,
  LOGIN_DOMAIN,
  LOGIN_ROLE_LOGIN,
  LOGIN_ROLE_COLLECT,
  LOGIN_MAX_FIELD_SIZE,
  deriveAudience,
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

test("binding layout is the pinned one; roles differ in the first byte", () => {
  const req = request();
  const b = loginBinding(LOGIN_ROLE_LOGIN, audience, req);
  const want = [
    0x01, 0x00, audience.length, ...utf8.encode(audience), ...req.browser,
    0x00, 0x05, ...utf8.encode("req-1"),
    0x00, 0x02, 0x00, 0x0d, ...utf8.encode("read:projects"), 0x00, 0x0e, ...utf8.encode("read:campaigns"),
    0x00, 0x00, 0x70, 0x80,
  ];
  assert.deepEqual([...b], want);
  const c = loginBinding(LOGIN_ROLE_COLLECT, audience, req);
  assert.equal(c[0], LOGIN_ROLE_COLLECT);
  assert.deepEqual([...c.subarray(1)], [...b.subarray(1)]);
});

test("login proof round-trips and every bound field binds", () => {
  const req = request();
  const sig = proveLogin(seedP, audience, req);
  const pubP = getPublicKey(seedP);
  assert.equal(verifyLogin(pubP, audience, req, sig), true);
  assert.equal(verifyLogin(pubP, "https://evil.example/api", req, sig), false);
  assert.equal(verifyLogin(pubP, audience, { ...req, browser: pubP }, sig), false);
  assert.equal(verifyLogin(pubP, audience, { ...req, id: utf8.encode("req-2") }, sig), false);
  assert.equal(verifyLogin(pubP, audience, { ...req, nonce: new Uint8Array(16).fill(0xab) }, sig), false);
  assert.equal(verifyLogin(pubP, audience, { ...req, scope: [...req.scope].reverse() }, sig), false);
  assert.equal(verifyLogin(pubP, audience, { ...req, scope: [...req.scope, "admin"] }, sig), false);
  assert.equal(verifyLogin(pubP, audience, { ...req, validFor: 28801 }, sig), false);
  assert.equal(verifyLogin(getPublicKey(seedK), audience, req, sig), false);
  const binding = loginBinding(LOGIN_ROLE_LOGIN, audience, req);
  const raw = sign(possessionMessageBytes(req.nonce, binding), seedP);
  assert.equal(verifyLogin(pubP, audience, req, raw), false, "a raw signature is not a proof");
  const other = provePossession(seedP, "archon-login/2", req.nonce, binding);
  assert.equal(verifyLogin(pubP, audience, req, other), false, "another domain is not a proof");
  const collect = proveCollect(seedK, audience, req);
  assert.equal(verifyLogin(getPublicKey(seedK), audience, req, collect), false, "the collect role is not a login proof");
  assert.equal(LOGIN_DOMAIN, "archon-login/1");
});

test("collect proof: only from the key the request names", () => {
  const req = request();
  const sig = proveCollect(seedK, audience, req);
  assert.equal(verifyCollect(audience, req, sig), true);
  assert.equal(verifyCollect("https://evil.example/api", req, sig), false);
  assert.equal(verifyCollect(audience, req, proveLogin(seedK, audience, req)), false);
  assert.throws(() => proveCollect(seedP, audience, req));
});

test("refusals", () => {
  const cases: Array<[string, string, Partial<LoginRequest>]> = [
    ["empty audience", "", {}],
    ["control char in audience", "https://dawn.example/api\n", {}],
    ["browser wrong size", audience, { browser: new Uint8Array(31) }],
    ["empty id", audience, { id: new Uint8Array(0) }],
    ["empty scope entry", audience, { scope: [""] }],
    ["control char in scope", audience, { scope: ["read:\u0007projects"] }],
    ["DEL in scope", audience, { scope: ["read:\u007fprojects"] }],
    ["lone surrogate in scope", audience, { scope: ["read:\ud800projects"] }],
    ["zero validity", audience, { validFor: 0 }],
    ["validity over u32", audience, { validFor: 0x1_0000_0000 }],
    ["fractional validity", audience, { validFor: 1.5 }],
    ["oversized id", audience, { id: new Uint8Array(LOGIN_MAX_FIELD_SIZE + 1) }],
    ["binding over the possession bound", audience, { scope: ["a".repeat(LOGIN_MAX_FIELD_SIZE), "b".repeat(LOGIN_MAX_FIELD_SIZE)] }],
  ];
  for (const [name, aud, patch] of cases) {
    const req = { ...request(), ...patch };
    assert.throws(() => loginBinding(LOGIN_ROLE_LOGIN, aud, req), name);
    assert.throws(() => proveLogin(seedP, aud, req), `${name}: prove`);
    assert.equal(verifyLogin(getPublicKey(seedP), aud, req, new Uint8Array(64)), false, `${name}: verify`);
  }
  assert.throws(() => loginBinding(0x03, audience, request()));
  assert.throws(() => proveLogin(seedP, audience, { ...request(), nonce: new Uint8Array(15) }));
  assert.throws(() => proveLogin(seedP.subarray(0, 31), audience, request()));
  assert.doesNotThrow(() => loginBinding(LOGIN_ROLE_LOGIN, audience, { ...request(), scope: [] }), "empty scope list is allowed");
});

test("deriveAudience: the §2.1 grammar, refused not normalised", () => {
  const id = "8f3c1d2e4b5a69780f1e2d3c4b5a6978";
  const accepts: Array<[string, string]> = [
    [`https://dawn.example/api/login/${id}`, "https://dawn.example/api"],
    [`https://dawn.example:443/api/login/${id}`, "https://dawn.example/api"],
    [`http://localhost:8080/login/${id}`, "http://localhost:8080"],
    [`HTTPS://Dawn.Example/API/login/${id}`, "https://dawn.example/API"],
    [`wss://dawn.example:80/login/${id}`, "https://dawn.example:80"],
    [`https://[2001:DB8::1]:443/login/${id}`, "https://[2001:db8::1]"],
    [`https://dawn.example/a/b%2Fc/login/${id}`, "https://dawn.example/a/b%2Fc"],
  ];
  for (const [url, want] of accepts) {
    const d = deriveAudience(url);
    assert.equal(d.audience, want, url);
    assert.equal(d.id.length, 16, url);
  }
  for (const url of [
    `dawn.example/login/${id}`,
    `ftp://dawn.example/login/${id}`,
    `https://dawn.example/api/login/${id}/`,
    `https://user:pass@dawn.example/api/login/${id}`,
    `https://dawn.example/login/${id}?x=1`,
    `https://dawn.example:0443/login/${id}`,
    "https://dawn.example/api/login/8F3C",
    "https://dawn.example/api/login/8f3",
    `https://dawn.example/a b/login/${id}`,
    `https://dawn.example/a%2/login/${id}`,
    `https://[fe80::1%25eth0]/login/${id}`,
    "",
  ]) {
    assert.throws(() => deriveAudience(url), url);
  }
});
