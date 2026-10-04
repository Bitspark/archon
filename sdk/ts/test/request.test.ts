// The request profile (docs/request.md): what the vectors leave to the lanes — a signed request
// verifying end to end, and the signer form producing the seed's exact headers.
import { test } from "node:test";
import assert from "node:assert/strict";

import { getPublicKey } from "@bitspark/archon";
import { seedSigner, signRequest, signRequestWith, verifyRequest, type RequestToSign } from "../src/index.js";

const seed = new Uint8Array(32).fill(0x44);
const input: RequestToSign = {
  method: "POST",
  audience: "https://dawn.example/api",
  requestTarget: "/api/v1/things?x=1",
  body: new TextEncoder().encode('{"a":1}'),
  contentType: "application/json",
  declared: [["idempotency-key", "k-1"]],
  created: 1_789_034_640,
  expires: 1_789_034_700,
  nonce: new Uint8Array(16).fill(7),
};

test("a signed request verifies, and the verifier reports what it verified", () => {
  const { headers } = signRequest(seed, input);
  const v = verifyRequest(
    { audience: input.audience, declared: ["idempotency-key"], maxLifetime: 300, skew: 30 },
    input.created + 5,
    {
      method: input.method,
      requestTarget: input.requestTarget,
      headers: [["Content-Type", "application/json"], ["Idempotency-Key", "k-1"], ...Object.entries(headers)],
      body: input.body,
    },
  );
  assert.deepEqual(v.principal, getPublicKey(seed));
  assert.equal(v.targetUri, "https://dawn.example/api/v1/things?x=1");
  assert.deepEqual(v.covered.map(([n]) => n), ["archon-audience", "content-digest", "content-type", "idempotency-key"]);
});

test("through a signer the headers are the seed's, and only that key's signer is asked", async () => {
  const { headers } = signRequest(seed, input);
  assert.deepEqual(await signRequestWith(seedSigner(seed), input), headers);
  // A signer is asked to sign as itself, so its keyid differs — but it is never asked to sign a
  // base that names another key.
  const other = await signRequestWith(seedSigner(new Uint8Array(32).fill(0x11)), input);
  assert.notEqual(other["signature-input"], headers["signature-input"]);
});
