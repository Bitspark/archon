// An OUTSIDE consumer of archon from npmjs: `@bitspark/archon-sdk` installed into an empty
// directory with a fresh npm cache, which pulls `@bitspark/archon` (the floor) through the
// RANGE the published sdk names — the range release.yml rewrote from a `file:` link at
// publish time, so this is also the proof that the rewrite happened. Run by release.yml
// after publication, and by hand as
//
//   d=$(mktemp -d) && cp conformance/consumers/ts/consumer.mjs "$d" && cd "$d" && npm init -y >/dev/null \
//     && npm_config_cache=$(mktemp -d) npm install --no-audit --no-fund @bitspark/archon-sdk@X @bitspark/archon@X \
//     && node consumer.mjs
import { readFileSync } from "node:fs";
import * as core from "@bitspark/archon";
import { provePossession, verifyPossession } from "@bitspark/archon-sdk";

const seed = new Uint8Array(32).fill(0x11);
const pub = core.getPublicKey(seed);
console.log("key:", core.encodeKey(pub));

const enc = (s) => new TextEncoder().encode(s);
const sig = core.signInDomain(seed, "archon/test/v1", enc("hello"));
const inDomain = core.verifyInDomain(pub, "archon/test/v1", enc("hello"), sig);
const otherDomain = core.verifyInDomain(pub, "archon/test/v2", enc("hello"), sig);
const asRaw = core.verify(sig, enc("hello"), pub);
console.log(`genuine: in v1=${inDomain} in v2=${otherDomain} raw=${asRaw}`);

// ADR 0008, asserted on inputs EVERY library accepted before it — the identity as R, and a
// mixed-order key with a challenge divisible by 8 (oracle cases profile-identity-R and
// profile-mixed-order-A-k-divisible) — so that only archon's own check can be what refuses
// them. The identity as a KEY would be decorative here: @noble refuses it on its own, so
// this consumer was green against 0.6.1, which has no profile at all.
const unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const refused = (pubkey, messageHex, sigHex) => !core.verify(unhex(sigHex), unhex(messageHex), pubkey);
const identityR = refused(pub, "68656c6c6f",
  "0100000000000000000000000000000000000000000000000000000000000000" +
  "04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07");
const mixedA = refused(unhex("05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4"),
  "6d697865642d6f72646572233133",
  "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1" +
  "20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b");
console.log(`profile: identity R refused=${identityR}, mixed-order key refused=${mixedA}`);

const nonce = new Uint8Array(32).fill(0x42);
const proof = provePossession(seed, "example/pop/v1", nonce, enc("binding"));
const pop = verifyPossession(pub, "example/pop/v1", nonce, enc("binding"), proof);
console.log(`possession: ${pop}`);

// The sdk's dependency on the floor resolved from the registry, not from a link.
const sdkPkg = JSON.parse(readFileSync("node_modules/@bitspark/archon-sdk/package.json", "utf8"));
const floorPkg = JSON.parse(readFileSync("node_modules/@bitspark/archon/package.json", "utf8"));
const range = sdkPkg.dependencies?.["@bitspark/archon"] ?? "";
console.log(`sdk ${sdkPkg.version} names the floor as "${range}"; installed floor ${floorPkg.version}`);
if (!range.startsWith("^") || range.includes("file:")) {
  console.error("FAIL: the published sdk does not name the floor by a registry range");
  process.exit(1);
}

if (!(inDomain && !otherDomain && !asRaw && identityR && mixedA && pop)) {
  console.error("FAIL: the published npm packages do not behave as the release claims");
  process.exit(1);
}
console.log("OK: @bitspark/archon + @bitspark/archon-sdk from registry.npmjs.org");
