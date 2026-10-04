// The signer seam (ADR 0009 §2–4): every helper through a Signer produces the SAME bytes the
// seed functions produce — checked against the vectors, whose signatures OpenSSL derived — and
// every rule the seam enforces is exercised against a signer that breaks it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { getPublicKey, sign, signInDomain, toHex } from "@bitspark/archon";
import {
  checkSignature,
  completePossession,
  completeSeal,
  envelopeMessageBytes,
  open,
  possessionMessageBytes,
  prepareCollect,
  prepareLogin,
  preparePossession,
  prepareSeal,
  proveCollectWith,
  proveLoginWith,
  provePossessionWith,
  sealWith,
  seedSigner,
  signWith,
  type LoginRequest,
  type Signer,
  type SigningRequest,
} from "../src/index.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../../../vectors/${name}`, import.meta.url)), "utf8"));
const fromHex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));
const sdk = vectors("sdk.json");
const login = vectors("login.json");

interface VecRequest { id: string; nonce: string; browser: string; scope: string[]; valid_for: number }
const loginRequest = (r: VecRequest): LoginRequest => ({
  id: fromHex(r.id),
  nonce: fromHex(r.nonce),
  browser: fromHex(r.browser),
  scope: r.scope.map((s) => new TextDecoder().decode(fromHex(s))),
  validFor: r.valid_for,
});

/** A signer that records whether it was invoked and signs however `how` says. */
function signerFor(
  publicKey: Uint8Array,
  how: (request: SigningRequest) => Uint8Array,
  capabilities: Signer["capabilities"] = { schemes: ["ed25519-raw", "ed25519ph-context"] },
): Signer & { calls: number } {
  const s = {
    publicKey,
    capabilities,
    calls: 0,
    sign: (request: SigningRequest) => {
      s.calls++;
      return Promise.resolve(how(request));
    },
  };
  return s;
}

test("through a seed signer, every helper reproduces the vectors' bytes", async () => {
  let checked = 0;
  for (const c of sdk.possession_prove.filter((c: { result: object }) => "ok" in c.result)) {
    const sig = await provePossessionWith(seedSigner(fromHex(c.seed)), c.domain, fromHex(c.nonce), fromHex(c.binding));
    assert.equal(toHex(sig), c.result.ok, `possession ${c.name}`);
    checked++;
  }
  for (const c of sdk.envelope_seal.filter((c: { result: object }) => "ok" in c.result)) {
    const env = await sealWith(seedSigner(fromHex(c.seed)), c.domain, fromHex(c.payload));
    assert.equal(toHex(env), c.result.ok, `envelope ${c.name}`);
    checked++;
  }
  for (const c of login.login_prove.filter((c: { result: object }) => "ok" in c.result)) {
    const sig = await proveLoginWith(seedSigner(fromHex(c.seed)), c.audience, loginRequest(c.request));
    assert.equal(toHex(sig), c.result.ok, `login ${c.name}`);
    checked++;
  }
  for (const c of login.login_collect_prove.filter((c: { result: object }) => "ok" in c.result)) {
    const sig = await proveCollectWith(seedSigner(fromHex(c.seed)), c.audience, loginRequest(c.request));
    assert.equal(toHex(sig), c.result.ok, `collect ${c.name}`);
    checked++;
  }
  // Every OpenSSL-derived ok case across the four families: a key slip that skipped them all
  // would otherwise pass in silence.
  const okCases = (cases: { result: object }[]) => cases.filter((c) => "ok" in c.result).length;
  const want = okCases(sdk.possession_prove) + okCases(sdk.envelope_seal) + okCases(login.login_prove) + okCases(login.login_collect_prove);
  assert.equal(checked, want);
  assert.ok(checked >= 8, `checked ${checked} vector cases`);
});

test("prepare asks for exactly the pinned message, in the protocol's domain", () => {
  const pub = getPublicKey(new Uint8Array(32).fill(9));
  const nonce = new Uint8Array(16).fill(0xaa);
  const binding = new TextEncoder().encode("b");
  const p = preparePossession(pub, "archon/test/pop", nonce, binding);
  assert.deepEqual(p.scheme, { kind: "ed25519ph-context", domain: "archon/test/pop" });
  assert.deepEqual(p.message, possessionMessageBytes(nonce, binding));
  const s = prepareSeal(pub, "archon/test/env", new TextEncoder().encode("x"));
  assert.deepEqual(s.message, envelopeMessageBytes(new TextEncoder().encode("x")));
  const req = loginRequest(login.login_prove[0].request);
  assert.deepEqual(prepareLogin(pub, "https://dawn.example/api", req).scheme, { kind: "ed25519ph-context", domain: "archon-login/1" });
  assert.deepEqual(prepareCollect("https://dawn.example/api", req).expectedPublicKey, req.browser, "collect expects the request's browser key");
});

test("an out-of-range request is refused before the signer is invoked", async () => {
  const seed = new Uint8Array(32).fill(7);
  const s = signerFor(getPublicKey(seed), (r) => sign(r.message, seed));
  // Each prepare refuses what its seed function refuses.
  for (const c of sdk.possession_prove.filter((c: { name: string; result: object }) => "error" in c.result && c.name !== "seed-short-rejected")) {
    await assert.rejects(provePossessionWith(s, c.domain, fromHex(c.nonce), fromHex(c.binding)), `possession ${c.name}`);
  }
  for (const c of sdk.envelope_seal.filter((c: { name: string; result: object }) => "error" in c.result && c.name !== "seed-short-rejected")) {
    await assert.rejects(sealWith(s, c.domain, fromHex(c.payload)), `envelope ${c.name}`);
  }
  // And the contract's own rules: a key of the wrong length, a domain on a raw request.
  await assert.rejects(signWith(s, { expectedPublicKey: new Uint8Array(31), scheme: { kind: "ed25519-raw" }, message: new Uint8Array(1) }));
  await assert.rejects(signWith(s, { expectedPublicKey: s.publicKey, scheme: { kind: "ed25519-raw", domain: "x" } as never, message: new Uint8Array(1) }));
  assert.equal(s.calls, 0, "the signer must never have been asked");
});

test("a signer is asked only for what it says it can do", async () => {
  const seed = new Uint8Array(32).fill(7);
  const pub = getPublicKey(seed);
  const request = preparePossession(pub, "archon/test/pop", new Uint8Array(16).fill(1), new Uint8Array([1]));
  // A raw-only signer — every agent and device ADR 0007 §A measured — is refused for ph.
  const rawOnly = signerFor(pub, (r) => sign(r.message, seed), { schemes: ["ed25519-raw"] });
  await assert.rejects(signWith(rawOnly, request), /cannot produce ed25519ph-context/);
  const elsewhere = signerFor(pub, (r) => signInDomain(seed, "archon/test/pop", r.message), {
    schemes: ["ed25519ph-context"],
    domains: ["archon/test/other"],
  });
  await assert.rejects(signWith(elsewhere, request), /does not sign in domain/);
  const otherKey = signerFor(getPublicKey(new Uint8Array(32).fill(8)), (r) => sign(r.message, seed));
  await assert.rejects(signWith(otherKey, request), /not the expected key/);
  assert.equal(rawOnly.calls + elsewhere.calls + otherKey.calls, 0);
});

test("a signature is checked against the request, never against the signer's word", async () => {
  const seed = new Uint8Array(32).fill(7);
  const pub = getPublicKey(seed);
  const domain = "archon/test/pop";
  const request = preparePossession(pub, domain, new Uint8Array(16).fill(1), new Uint8Array([1]));
  const liars: [string, (r: SigningRequest) => Uint8Array][] = [
    ["signs with another key", (r) => signInDomain(new Uint8Array(32).fill(8), domain, r.message)],
    ["drops the context and signs raw", (r) => sign(r.message, seed)],
    ["signs in another domain", (r) => signInDomain(seed, "archon/test/other", r.message)],
    ["signs other bytes", () => signInDomain(seed, domain, new Uint8Array([0]))],
    ["returns 63 bytes", (r) => signInDomain(seed, domain, r.message).subarray(1)],
  ];
  for (const [label, how] of liars) {
    await assert.rejects(signWith(signerFor(pub, how), request), /does not verify/, label);
    assert.throws(() => completePossession(request, how(request)), /does not verify/, `complete: ${label}`);
  }
});

test("a signature that arrives after the caller aborted is never packaged", async () => {
  const seed = new Uint8Array(32).fill(7);
  const controller = new AbortController();
  const late: Signer = {
    publicKey: getPublicKey(seed),
    capabilities: { schemes: ["ed25519ph-context"] },
    sign: (r) => {
      controller.abort();
      return Promise.resolve(signInDomain(seed, (r.scheme as { domain: string }).domain, r.message));
    },
  };
  await assert.rejects(sealWith(late, "archon/test/env", new Uint8Array([1]), controller.signal));
  await assert.rejects(sealWith(late, "archon/test/env", new Uint8Array([1]), controller.signal), "aborted before it starts");
});

test("complete assembles from the request; the seed signer is deterministic", async () => {
  const seed = new Uint8Array(32).fill(7);
  const signer = seedSigner(seed);
  const request = prepareSeal(signer.publicKey, "archon/test/env", new TextEncoder().encode("payload"));
  const first = await signer.sign(request);
  assert.deepEqual(await signer.sign(request), first, "signing twice gives the same bytes");
  const env = completeSeal(request, first);
  assert.deepEqual(open(env, "archon/test/env").payload, new TextEncoder().encode("payload"));
  assert.throws(() => completeSeal(preparePossession(signer.publicKey, "d", new Uint8Array(16), new Uint8Array([1])), first), /not a seal request/);
  checkSignature(request, first);
});
