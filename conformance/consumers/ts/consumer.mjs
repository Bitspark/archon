// An OUTSIDE consumer of archon from npmjs: `@bitspark/archon-sdk` installed into an empty
// directory with a fresh npm cache, which pulls `@bitspark/archon` (the floor) through the
// RANGE the published sdk names — the range release.yml rewrote from a `file:` link at
// publish time, so this is also the proof that the rewrite happened. Run by release.yml
// after publication, and by hand as
//
//   d=$(mktemp -d) && cp conformance/consumers/ts/consumer.mjs "$d" && cd "$d" && npm init -y >/dev/null \
//     && npm_config_cache=$(mktemp -d) npm install --no-audit --no-fund @bitspark/archon-sdk@X @bitspark/archon@X \
//     && node consumer.mjs
//
// With `--server`, and @bitspark/archon-server@X installed beside them, it also runs a whole
// login through the published server tier (below).
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

// The server tier, a whole login through the PUBLISHED handler, in-process: the browser
// begins, the person's command fetches what it will be shown, answers with the sdk's proof,
// and the browser collects with its own. Every version through 0.8.1 published this package
// as a package.json and nothing else (#55), and no step noticed, because nothing imported it.
let server = true;
if (process.argv.includes("--server")) {
  const { Handler, COLLECT_HEADER } = await import("@bitspark/archon-server");
  const { proveLogin, proveCollect, verifyLogin } = await import("@bitspark/archon-sdk");
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const audience = "https://service.example/api";
  const handler = new Handler({ audience, mount: "/api/login" });
  const call = (path, init) => handler.handle(new Request(`${audience}${path}`, init));
  const json = { "content-type": "application/json" };

  const kSeed = new Uint8Array(32).fill(0x22);
  const browser = core.getPublicKey(kSeed);
  const begun = await call("/login", {
    method: "POST", headers: json,
    body: JSON.stringify({ browser: core.encodeKey(browser), scope: ["read:projects"], valid_for: 60 }),
  });
  const { id, nonce } = await begun.json();
  const fetched = await call(`/login/${id}`);
  const shown = await fetched.json();
  const req = { id: unhex(id), nonce: unhex(nonce), browser, scope: shown.scope, validFor: shown.valid_for };
  const answered = await call(`/login/${id}/answer`, {
    method: "POST", headers: json,
    body: JSON.stringify({ principal: core.encodeKey(pub), possession: hex(proveLogin(seed, audience, req)) }),
  });
  const collected = await call(`/login/${id}/answer`, { headers: { [COLLECT_HEADER]: hex(proveCollect(kSeed, audience, req)) } });
  const answer = collected.status === 200 ? await collected.json() : {};
  server = begun.status === 201 && fetched.status === 200 && answered.status === 204 && collected.status === 200
    && answer.principal === core.encodeKey(pub) && verifyLogin(pub, audience, req, unhex(answer.possession));
  console.log(`server: begin ${begun.status}, fetch ${fetched.status}, answer ${answered.status}, collect ${collected.status}; login verified=${server}`);
}

if (!(inDomain && !otherDomain && !asRaw && identityR && mixedA && pop && server)) {
  console.error("FAIL: the published npm packages do not behave as the release claims");
  process.exit(1);
}
const which = process.argv.includes("--server") ? " + @bitspark/archon-server" : "";
console.log(`OK: @bitspark/archon + @bitspark/archon-sdk${which} from registry.npmjs.org`);
