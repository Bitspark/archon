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

// ADR 0008: the identity key's universal signature (R = B, S = 1) is refused.
const identity = new Uint8Array(32); identity[0] = 1;
const universal = new Uint8Array(64).fill(0x66, 0, 32); universal[0] = 0x58; universal[32] = 1;
const uRaw = core.verify(universal, enc("hello"), identity);
const uDomain = core.verifyInDomain(identity, "archon/test/v1", enc("hello"), universal);
console.log(`identity key: raw=${uRaw} in v1=${uDomain}`);

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

if (!(inDomain && !otherDomain && !asRaw && !uRaw && !uDomain && pop)) {
  console.error("FAIL: the published npm packages do not behave as the release claims");
  process.exit(1);
}
console.log("OK: @bitspark/archon + @bitspark/archon-sdk from registry.npmjs.org");
