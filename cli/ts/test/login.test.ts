// Unit tests for `archon login` (TS lane). Deliberately the same cases as the Go and Rust
// lanes: the three binaries must agree on the statement, the refusals and the formats, and
// keeping the suites parallel is how a divergence shows up as a failing test rather than as
// a smoke-run surprise.
import { strict as assert } from "node:assert";
import test from "node:test";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  validateLoginRequest,
  fetchLoginRequest,
  postLoginAnswer,
  renderStatement,
  renderLedger,
  describeKeySource,
  describePage,
  configuredAudience,
  formatDuration,
  formatRfc3339Utc,
  seedFromHexFile,
  loginHttpError,
  proveLogin,
  run,
  type LoginIo,
  type LoginRequest,
  type LoginSource,
} from "../src/cmd/login.js";
import { sealAndWrite } from "../src/cmd/key_store.js";
import { encodeKey, getPublicKey } from "@bitspark/archon";
import { deriveAudience, verifyLogin, type LoginRequest as SchemeRequest } from "@bitspark/archon-sdk";

const hexToBytes = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/../g)!.map((b) => Number.parseInt(b, 16)));

const BROWSER = "ed25519:7a91b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f";

function validRequest(): LoginRequest {
  return {
    id: "8f3c",
    nonce: "ab".repeat(16),
    browser: BROWSER,
    scope: ["read:projects", "read:campaigns"],
    valid_for: 28800,
    expires: "2026-09-10T18:04:00Z",
  };
}

// The audience rule is the security boundary of this command: the only thing standing
// between a phished invocation URL and a proof made out to the wrong service.
test("derives the audience", () => {
  const cases: [string, string, string][] = [
    ["https://prover.core.example.dev/login/8f3c", "https://prover.core.example.dev", "8f3c"],
    ["https://prover.core.example.dev/api/login/8f3c", "https://prover.core.example.dev/api", "8f3c"],
    ["https://h.example/a/b/c/login/ab12", "https://h.example/a/b/c", "ab12"],
    ["ws://h.example/login/1a", "http://h.example", "1a"],
    ["wss://h.example/api/login/1a", "https://h.example/api", "1a"],
    ["HTTPS://h.example/login/1a", "https://h.example", "1a"],
    ["https://Prover.Core.Example.DEV/login/1a", "https://prover.core.example.dev", "1a"],
    ["http://localhost:8080/api/login/1a", "http://localhost:8080/api", "1a"],
    ["https://h.example/API/login/1a", "https://h.example/API", "1a"],
  ];
  for (const [url, audience, id] of cases) {
    const got = deriveAudience(url);
    assert.equal(got.audience, audience, `audience for ${url}`);
    // The scheme returns the id DECODED; this lane carries it as hex on the wire.
    assert.equal(Buffer.from(got.id).toString("hex"), id, `id for ${url}`);
  }
});

// Each of these must NOT yield an audience. A guess would be worse than a refusal: it
// would silently sign for something the person did not read.
test("refuses URLs that are not invocations", () => {
  for (const url of [
    "https://h.example/api/8f3c",
    "https://h.example/signin/8f3c",
    "https://h.example/login",
    "https://h.example/",
    "ftp://h.example/login/1a",
    "file:///login/1a",
    "https://h.example/login/1?next=evil",
    "https://h.example/login/1#x",
    "not-a-url",
    // A TRAILING SLASH IS NOW A REFUSAL, and this lane used to ACCEPT it and trim it.
    // docs/login.md §2.1 makes it an empty segment (oracle: trailing-slash-rejected). The
    // test was encoding a normalisation — which is what moving this into the scheme was
    // meant to stop — so it flipped rather than the scheme bending to it.
    "https://prover.core.example.dev/api/login/8f3c/",
    // Userinfo is refused, not normalised: the three parsers disagree about it, and the
    // disagreement is the phished-invocation shape the rule exists to stop.
    "https://user:pass@h.example/api/login/8f3c",
    "https://user@h.example/login/8f3c",
    // The id is BYTES carried as lowercase hex (docs/login.md §3.1, §4).
    "https://h.example/login/a%20b",
    "https://h.example/login/a%2Fb",
    "https://h.example/login/a b",
    "https://h.example/login/8F3C",
    "https://h.example/login/8f3",
    "https://h.example/login/zzzz",
    "https://h.example/login/a",
  ]) {
    assert.throws(() => deriveAudience(url), `accepted ${url}`);
  }
});

test("accepts a valid request", () => {
  validateLoginRequest(validRequest(), "8f3c");
});

test("refuses malformed requests", () => {
  const cases: [string, (r: LoginRequest) => void][] = [
    ["id mismatch", (r) => { r.id = "other"; }],
    ["nonce not hex", (r) => { r.nonce = "zzzz"; }],
    ["nonce too short", (r) => { r.nonce = "ab".repeat(15); }],
    ["browser not key text", (r) => { r.browser = "7a91"; }],
    ["empty scope entry", (r) => { r.scope = [""]; }],
    ["valid_for zero", (r) => { r.valid_for = 0; }],
  ];
  for (const [name, breakIt] of cases) {
    const r = validRequest();
    breakIt(r);
    assert.throws(() => validateLoginRequest(r, "8f3c"), `accepted ${name}`);
  }
});

// A scope entry is printed verbatim to a terminal. An escape sequence there can erase or
// repaint the statement the person is about to approve.
test("refuses control characters in scope", () => {
  for (const bad of ["read:\u001b[2Jprojects", "read:\nprojects", "read:\rprojects", "read:\u0000p", "read:\u007fp"]) {
    const r = validRequest();
    r.scope = [bad];
    assert.throws(() => validateLoginRequest(r, "8f3c"), `accepted ${JSON.stringify(bad)}`);
  }
});

// The statement is the contract with the person AND the cross-lane pin: these exact bytes
// must come out of all three binaries.
test("renders the statement", () => {
  const now = 1789034640; // 2026-09-10T10:04:00Z
  const got = renderStatement("https://prover.core.example.dev/api", validRequest(), now, "the seed file /keys/julia");
  const want =
    `https://prover.core.example.dev/api asks you to let browser key ${BROWSER} act as you:\n` +
    "  read:projects\n" +
    "  read:campaigns\n" +
    "for 8h0m0s, until 2026-09-10T18:04:00Z\n" +
    "signing with the seed file /keys/julia\n";
  assert.equal(got, want);
});

// An empty scope is VALID (docs/login.md §3.1) and must still say so on screen.
test("states an empty scope rather than showing a blank", () => {
  const r = validRequest();
  r.scope = [];
  const got = renderStatement("https://h.example", r, 0, "the seed given on the command line");
  assert.match(got, /no scope entries/, "an empty scope must be stated");
});

// Default ports are omitted (docs/login.md §2): the server binds its configured audience,
// which has no :443 in it, so keeping the port binds a different string.
test("omits default ports and keeps others", () => {
  const cases: [string, string][] = [
    ["https://h.example:443/api/login/8f3c", "https://h.example/api"],
    ["http://h.example:80/api/login/8f3c", "http://h.example/api"],
    ["https://h.example:8443/login/8f3c", "https://h.example:8443"],
    ["http://localhost:8080/api/login/8f3c", "http://localhost:8080/api"],
    ["http://[::1]:8080/login/8f3c", "http://[::1]:8080"],
    ["https://[::1]:443/login/8f3c", "https://[::1]"],
    ["wss://h.example:443/login/8f3c", "https://h.example"],
  ];
  for (const [url, audience] of cases) assert.equal(deriveAudience(url).audience, audience, url);
});

// A percent-escape in the BASE path must survive as written.
test("keeps the escaped base path", () => {
  const got = deriveAudience("https://h.example/a%2Fb/login/8f3c");
  assert.equal(got.audience, "https://h.example/a%2Fb");
  assert.equal(Buffer.from(got.id).toString("hex"), "8f3c");
});

test("formats durations", () => {
  const cases: [number, string][] = [
    [28800, "8h0m0s"], [3600, "1h0m0s"], [3661, "1h1m1s"],
    [300, "5m0s"], [90, "1m30s"], [45, "45s"], [1, "1s"],
  ];
  for (const [seconds, want] of cases) assert.equal(formatDuration(seconds), want, `${seconds}s`);
});

test("formats timestamps", () => {
  const cases: [number, string][] = [
    [0, "1970-01-01T00:00:00Z"],
    [1789063440, "2026-09-10T18:04:00Z"],
    [1709164800, "2024-02-29T00:00:00Z"],
    [1735689599, "2024-12-31T23:59:59Z"],
  ];
  for (const [unix, want] of cases) assert.equal(formatRfc3339Utc(unix), want, `unix ${unix}`);
});

test("reads both seed file shapes", () => {
  const seed = "11".repeat(32);
  assert.equal(seedFromHexFile(`${seed}\n`).length, 32);
  const got = seedFromHexFile(seed + "22".repeat(32));
  assert.equal(got.length, 32);
  assert.equal(got[0], 0x11, "took the wrong half of the private key");
  for (const bad of ["", "zz", "11".repeat(31)]) {
    assert.throws(() => seedFromHexFile(bad), `accepted ${JSON.stringify(bad)}`);
  }
});

test("surfaces RFC 8628 errors", () => {
  assert.match(loginHttpError(400, '{"error":"expired_token"}'), /expired/);
  assert.match(loginHttpError(403, '{"error":"access_denied"}'), /refused/);
  assert.match(loginHttpError(500, "not json"), /500/);
});

// The seam is wired (sdk/ts/login, archon#19). The proof must VERIFY under the scheme's
// own verifier: this lane converts wire values to scheme values, and a conversion bug is
// exactly what would otherwise pass as a plausible-looking signature.
test("the proof verifies under the scheme", () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
  const audience = "https://prover.core.example.dev/api";
  const r = validRequest();

  const { proof, principal } = proveLogin(seed, audience, r);
  assert.match(principal, /^ed25519:/);

  const scheme: SchemeRequest = {
    id: hexToBytes(r.id),
    nonce: Uint8Array.from(r.nonce.match(/../g)!.map((b) => Number.parseInt(b, 16))),
    browser: Uint8Array.from(r.browser.slice("ed25519:".length).match(/../g)!.map((b) => Number.parseInt(b, 16))),
    scope: r.scope,
    validFor: r.valid_for,
  };
  const pub = getPublicKey(seed);
  assert.ok(verifyLogin(pub, audience, scheme, proof), "the scheme does not verify this lane's proof");
  // And it must be bound to THIS audience: a proof that verifies elsewhere is the whole
  // hazard the derived-audience rule exists to prevent.
  assert.ok(!verifyLogin(pub, "https://evil.example", scheme, proof), "the proof verified against a different audience");

  // THE ID IS BOUND AS DECODED BYTES, NOT AS THE ASCII OF ITS HEX TEXT. This assertion
  // exists because the lane got it wrong and the earlier stub test did not notice: it built
  // its expected request the same wrong way, so both sides agreed with each other and
  // neither agreed with the server.
  const ascii: SchemeRequest = { ...scheme, id: new TextEncoder().encode(r.id) };
  assert.ok(!verifyLogin(pub, audience, ascii, proof), "the proof verified against an id bound as ASCII hex text");
});

// The whole flow against a stub service, which is the case seat:cca asked each lane to
// carry in its unit tests. (The smoke run was pre-network until the store's consumer needed
// a server; it now hosts one itself — see cli/smoke.mjs — and verifies against the oracle's
// key, never a lane's.) It exercises the join the unit tests above each cover only half of:
// what the service sends, through validation and conversion, into a proof the SCHEME
// accepts — and the id is deliberately one that URL-encoding would mangle, because the
// scheme binds the id as opaque bytes and a re-encode on the way in would bind the wrong
// ones.
test("end to end against a stub service", async () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 7;

  const wire = validRequest();
  let posted: Record<string, string> | undefined;
  let getPath: string | undefined;

  const server = createServer((req, res) => {
    if (req.method === "GET") {
      getPath = req.url;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(wire));
      return;
    }
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      posted = JSON.parse(body) as Record<string, string>;
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  try {
    const { audience, id: idBytes } = deriveAudience(`http://127.0.0.1:${port}/api/login/${wire.id}`);
    const id = Buffer.from(idBytes).toString("hex");
    assert.equal(audience, `http://127.0.0.1:${port}/api`, "audience must come from the URL, not the wire");

    const got = await fetchLoginRequest(audience, id);
    validateLoginRequest(got, id);

    const { proof, principal } = proveLogin(seed, audience, got);
    await postLoginAnswer(audience, id, { principal, possession: "aa", authority: "" });

    assert.equal(getPath, `/api/login/${wire.id}`, "the id goes back on the wire unchanged");
    assert.equal(posted?.principal, principal);

    // The proof the service received must verify for THIS audience and no other.
    const scheme: SchemeRequest = {
      id: hexToBytes(got.id),
      nonce: Uint8Array.from(got.nonce.match(/../g)!.map((b) => Number.parseInt(b, 16))),
      browser: Uint8Array.from(got.browser.slice("ed25519:".length).match(/../g)!.map((b) => Number.parseInt(b, 16))),
      scope: got.scope,
      validFor: got.valid_for,
    };
    const pub = getPublicKey(seed);
    assert.ok(verifyLogin(pub, audience, scheme, proof), "the scheme rejected the proof from the full flow");
    assert.ok(!verifyLogin(pub, "https://evil.example", scheme, proof), "the proof was not bound to its audience");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

// THE CROSS-LANE STATEMENT FIXTURE. This is where the three lanes are held together: all
// three suites read the SAME file and assert their renderer reproduces it byte for byte.
// (cli/smoke.mjs pins one rendered statement too, from the store-key login it runs against
// the server it hosts; this fixture is what pins every OTHER source line, with no network.)
test("statement matches the shared fixture", () => {
  // Resolved from the process cwd (cli/ts, where npm test runs) rather than from
  // import.meta.url: the compiled test lives under dist/test/, so a URL-relative path would
  // encode the build layout and break the moment tsconfig's rootDir moves.
  const raw = readFileSync("../testdata/login-statement.json", "utf8");
  const doc = JSON.parse(raw) as {
    cases: { name: string; audience: string; keySource: string; nowUnix: number; request: LoginRequest; statement: string }[];
  };
  assert.ok(doc.cases.length > 0, "the shared fixture holds no cases — a fixture nobody can fail is not a pin");
  for (const c of doc.cases) {
    const got = renderStatement(c.audience, c.request, c.nowUnix, c.keySource);
    assert.equal(got, c.statement, `statement differs from the shared fixture for case ${JSON.stringify(c.name)}`);
  }
});

// The fixture pins describeKeySource's OUTPUT for whichever source a case names; this pins
// the branch selection itself — and that a store key is named by its NAME, never a
// principal, whether --key chose it or the default pointer did.
test("describes the key source by its name, never a principal", () => {
  const cases: [LoginSource, string][] = [
    [{ storeKey: "julia" }, "the store key julia"],
    [{ seedFile: "/keys/julia" }, "the seed file /keys/julia"],
    [{ keyFile: "k.pem" }, "the key file k.pem"],
    [{ seedHex: "ab" }, "the seed given on the command line"],
    [{}, "an unspecified key"],
  ];
  for (const [src, want] of cases) assert.equal(describeKeySource(src), want, JSON.stringify(src));
});

// Runs the command with its output collected through run's injected writer, and its error
// returned rather than thrown. NEVER by patching process.stdout.write: under `node --test`
// this file is a child that reports each test's events to the runner over its own stdout,
// flushed lazily — a patch swallowed the queued events of the three tests that had just
// finished, and they vanished from the run's count without a skip or a failure. Pinning
// what a person would have SEEN is the point of the test below, so the seam is explicit.
async function runCollecting(args: string[]): Promise<{ out: string; error: Error | undefined }> {
  const chunks: string[] = [];
  let error: Error | undefined;
  try {
    await run(args, (text) => {
      chunks.push(text);
    });
  } catch (e) {
    error = e instanceof Error ? e : new Error(String(e));
  }
  return { out: chunks.join(""), error };
}

// THE STORE'S CONSUMER, end to end: a key SEALED into a temp store, the real `run` driven
// with --key and --yes against a stub service that verifies the proof with the scheme
// against the sealed seed's own public key. This is the row of ADR 0007 §A's table that was
// "not yet true" until this test could pass.
//
// `--yes` short-circuits before confirm() is ever constructed, so nothing here touches
// stdin; with ARCHON_KEY_PASSWORD set, readPassword returns before the prompt path too.
// The stub records every request BEFORE it answers, and each scenario says how many it
// expects, because WHERE a refusal lands is the point: a bad name and a missing default are
// refused before any request; a wrong password after the GET but before any POST — the
// unlock comes after show-and-confirm, and a failed unlock never posts.
test("logs in from a sealed store key", async () => {
  const home = mkdtempSync(join(tmpdir(), "archon-login-key-"));
  const savedHome = process.env["ARCHON_HOME"];
  const savedPassword = process.env["ARCHON_KEY_PASSWORD"];
  const PASSWORD = "a password with a space";
  process.env["ARCHON_HOME"] = home;
  process.env["ARCHON_KEY_PASSWORD"] = PASSWORD;

  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 9;
  const pub = getPublicKey(seed);
  const principal = encodeKey(pub);
  sealAndWrite(join(home, "keys", "julia"), seed, PASSWORD);

  const wire = validRequest();
  const seen: { method: string; verified: boolean }[] = [];
  const server = createServer((req, res) => {
    if (req.method === "GET") {
      seen.push({ method: "GET", verified: false });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(wire));
      return;
    }
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const answer = JSON.parse(body) as { principal: string; possession: string };
      const scheme: SchemeRequest = {
        id: hexToBytes(wire.id),
        nonce: hexToBytes(wire.nonce),
        browser: hexToBytes(wire.browser.slice("ed25519:".length)),
        scope: wire.scope,
        validFor: wire.valid_for,
      };
      // The audience is this server's own address, read from the request, so the handler
      // shares nothing with the test body.
      const audience = `http://${req.headers.host}/api`;
      const verified = answer.principal === principal && verifyLogin(pub, audience, scheme, hexToBytes(answer.possession));
      seen.push({ method: "POST", verified });
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}/api/login/${wire.id}`;
  const pointer = join(home, "default");

  try {
    // --key unlocks the sealed key and the proof verifies.
    let r = await runCollecting([url, "--key", "julia", "--yes"]);
    assert.equal(r.error, undefined, r.error?.message);
    assert.deepEqual(seen, [{ method: "GET", verified: false }, { method: "POST", verified: true }],
      "the service must have verified a proof for the sealed key's principal");
    assert.match(r.out, /signing with the store key julia\n/, "the statement did not name the store key");
    assert.ok(r.out.endsWith(`signed as ${principal}. the browser is in.\n`), `the outcome line is wrong:\n${r.out}`);

    // No source flag falls back to the store's default; the statement names the NAME the
    // pointer resolved to, exactly as --key would.
    writeFileSync(pointer, "julia\n");
    r = await runCollecting([url, "--yes"]);
    unlinkSync(pointer);
    assert.equal(r.error, undefined, r.error?.message);
    assert.equal(seen.length, 4);
    assert.ok(seen[3]?.verified, "the default key did not produce a verified proof");
    assert.match(r.out, /signing with the store key julia\n/, "the statement did not name the default key");

    // No source flag and no default: refused before any request, in the store's wording.
    r = await runCollecting([url, "--yes"]);
    assert.match(r.error?.message ?? "", /no default key is set/);
    assert.equal(seen.length, 4);

    // A name not in the store: refused before any request, in the store's wording.
    r = await runCollecting([url, "--key", "nobody", "--yes"]);
    assert.match(r.error?.message ?? "", /no key named "nobody" in archon's store/);
    assert.equal(seen.length, 4);

    // A wrong password: refused after the statement and before any answer.
    process.env["ARCHON_KEY_PASSWORD"] = "not the password";
    r = await runCollecting([url, "--key", "julia", "--yes"]);
    process.env["ARCHON_KEY_PASSWORD"] = PASSWORD;
    assert.match(r.error?.message ?? "", /wrong password/);
    assert.match(r.out, /signing with the store key julia\n/, "the statement was not shown before the unlock");
    assert.equal(seen.length, 5, "the GET happened, nothing was posted");
    assert.equal(seen[4]?.method, "GET");

    // Two sources: refused before any request.
    r = await runCollecting([url, "--key", "julia", "--seed", "11".repeat(32), "--yes"]);
    assert.match(r.error?.message ?? "", /mutually exclusive/);
    assert.equal(seen.length, 5);

    // --password-fd beside a seed file is refused.
    r = await runCollecting([url, "--seed", "11".repeat(32), "--password-fd", "3", "--yes"]);
    assert.match(r.error?.message ?? "", /applies only to a store key/);
    assert.equal(seen.length, 5);

    // --password-fd 0 without --yes is refused.
    r = await runCollecting([url, "--key", "julia", "--password-fd", "0"]);
    assert.match(r.error?.message ?? "", /pass --yes/);
    assert.equal(seen.length, 5);

    // A missing authority file: refused before any request. It used to be refused AFTER the
    // person had read the statement and said yes — a refusal belongs before the question.
    r = await runCollecting([url, "--key", "julia", "--authority-file", join(home, "no-such-file"), "--yes"]);
    assert.match(r.error?.message ?? "", /ENOENT|no such file/i);
    assert.equal(seen.length, 5);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (savedHome === undefined) delete process.env["ARCHON_HOME"]; else process.env["ARCHON_HOME"] = savedHome;
    if (savedPassword === undefined) delete process.env["ARCHON_KEY_PASSWORD"]; else process.env["ARCHON_KEY_PASSWORD"] = savedPassword;
    rmSync(home, { recursive: true, force: true });
  }
});

// ---- THE OFFERS FORM (docs/login.md §4.1) ------------------------------------------------

// THE LEDGER FIXTURE (§4.1 rule 4): the offers form prints, AFTER answering, the same fields
// the confirmed form shows before signing, and all three lanes must print the ledger
// byte-identically too. Same shared file, second section.
test("ledger matches the shared fixture", () => {
  const doc = JSON.parse(readFileSync("../testdata/login-statement.json", "utf8")) as {
    offer_cases: { name: string; audience: string; keySource: string; nowUnix: number; request: LoginRequest; verdict: string; ledger: string }[];
  };
  assert.ok(doc.offer_cases.length > 0, "the shared fixture holds no offer_cases — a fixture nobody can fail is not a pin");
  for (const c of doc.offer_cases) {
    const refused = c.verdict === "accepted" ? undefined : c.verdict.replace(/^refused:/, "");
    assert.ok(c.verdict === "accepted" || c.verdict.startsWith("refused:"), `verdict ${c.verdict}`);
    const got = renderLedger(c.audience, c.request, c.nowUnix, c.keySource, refused);
    assert.equal(got, c.ledger, `ledger differs from the shared fixture for case ${JSON.stringify(c.name)}`);
  }
});

// The page address is PRINTED AND MARKED, never opened (§4.1 rule 1; ADR 0007 §C.7 (6)):
// "on the service's own origin" is a byte-exact comparison of scheme and host with the
// audience's, so a differently spelled origin fails closed.
test("describes the page by origin", () => {
  const audience = "https://dawn.example/api";
  const on = " (on the service's own origin)";
  const off = " (NOT on the service's origin — do not open it)";
  const cases: [string, string][] = [
    ["https://dawn.example/login", on],
    ["https://dawn.example/login#abc", on],
    ["https://dawn.example", on],
    ["https://dawn.example.evil/login", off],
    ["https://evil.example/login", off],
    ["HTTPS://dawn.example/login", off],
    ["http://dawn.example/login", off],
    ["/login", off],
  ];
  for (const [page, mark] of cases) assert.equal(describePage(audience, page), `page: ${page}${mark}`, page);
  // The port is part of the origin.
  assert.ok(describePage("http://127.0.0.1:8080/api", "http://127.0.0.1:8080/login").endsWith(on));
  assert.ok(describePage("http://127.0.0.1:8080/api", "http://127.0.0.1:8081/login").endsWith(off));
});

// §4.1 rule 1, the flag half: a fixed point of §2.1's grammar, refused otherwise naming the
// spelling the service would bind. (The ARCHON_AUDIENCE half lives in the e2e test below,
// which owns the environment.)
test("configures the audience", () => {
  assert.equal(configuredAudience("http://localhost:8080"), "http://localhost:8080");
  for (const bad of ["https://Dawn.example/api", "https://dawn.example/api/", "https://dawn.example:443/api", "wss://dawn.example/api", "not an audience"]) {
    assert.throws(() => configuredAudience(bad), `accepted ${bad}`);
  }
  assert.throws(() => configuredAudience("https://Dawn.example/api"), /"https:\/\/dawn\.example\/api"/, "the refusal must name the derived spelling");
});

/** How the stub alters the request the CLI reads, to prove rule 2 — the prover's own
 *  re-check — fires on every shape of "differs". */
type Alter = (r: LoginRequest) => void;

/** The offers stub's script and log. */
interface OfferStub {
  offers: Map<string, { scope: string[]; validFor: number }>;
  requests: string[];
  polls: number;
  pollPlan: number[];
  takenAt: number;
  interval: number;
  expiresIn: number;
  page: string | undefined;
  echoValidForDelta: number;
  alter: Alter | undefined;
  refuse: string | undefined;
  posted: Record<string, string> | undefined;
  verified: boolean;
}

function freshStub(): OfferStub {
  return {
    offers: new Map(), requests: [], polls: 0, pollPlan: [], takenAt: 2, interval: 2, expiresIn: 300,
    page: undefined, echoValidForDelta: 0, alter: undefined, refuse: undefined, posted: undefined, verified: false,
  };
}

// THE OFFERS FORM, end to end, from a sealed store key: the real `run` with no URL against a
// stub playing the SERVICE's four routes, scripted per scenario, the answer verified with the
// scheme against the sealed key's own public key. The clock is pinned so the ledger is
// byte-exact, and the sleeps are RECORDED rather than slept, because the pacing is the prover's
// own (ADR 0007 §C.7, #39) and therefore this lane's to pin: one interval before the first
// poll, one between polls. stdout comes through run's injected writer and stderr through the
// injected LoginIo — never by patching process streams (see runCollecting).
test("offers from a sealed store key", async () => {
  const home = mkdtempSync(join(tmpdir(), "archon-login-offer-"));
  const saved = { home: process.env["ARCHON_HOME"], password: process.env["ARCHON_KEY_PASSWORD"], audience: process.env["ARCHON_AUDIENCE"] };
  const PASSWORD = "a password with a space";
  process.env["ARCHON_HOME"] = home;
  process.env["ARCHON_KEY_PASSWORD"] = PASSWORD;
  delete process.env["ARCHON_AUDIENCE"];

  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 9;
  const pub = getPublicKey(seed);
  const principal = encodeKey(pub);
  sealAndWrite(join(home, "keys", "julia"), seed, PASSWORD);
  const browserSeed = new Uint8Array(32);
  for (let i = 0; i < browserSeed.length; i++) browserSeed[i] = 0x40 + i;
  const K = encodeKey(getPublicKey(browserSeed));
  const ID = "8f3c";

  let stub = freshStub();
  const readBody = (req: import("node:http").IncomingMessage): Promise<string> =>
    new Promise((resolve) => {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => resolve(body));
    });
  const server = createServer((req, res) => {
    void (async () => {
      const path = req.url ?? "";
      stub.requests.push(`${req.method} ${path}`);
      const json = (status: number, body: unknown): void => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      };
      const audience = `http://${req.headers.host}/api`;
      if (req.method === "POST" && path === "/api/login/offers") {
        const body = JSON.parse(await readBody(req)) as { code: string; scope: string[]; valid_for: number };
        stub.offers.set(body.code, { scope: body.scope, validFor: body.valid_for });
        const resp: Record<string, unknown> = {
          code: body.code, scope: body.scope, valid_for: body.valid_for + stub.echoValidForDelta,
          expires_in: stub.expiresIn, interval: stub.interval,
        };
        if (stub.page !== undefined) resp["page"] = `${stub.page}#${body.code}`;
        json(201, resp);
      } else if (req.method === "GET" && path.startsWith("/api/login/offers/")) {
        const code = path.slice("/api/login/offers/".length);
        stub.polls += 1;
        const scripted = stub.pollPlan[stub.polls - 1] ?? 0;
        if (scripted !== 0) { json(scripted, { error: scripted === 429 ? "slow_down" : "expired_token" }); return; }
        const offer = stub.offers.get(code);
        if (offer === undefined) { json(404, { error: "expired_token" }); return; }
        const request = stub.takenAt > 0 && stub.polls >= stub.takenAt ? ID : null;
        json(200, { code, scope: offer.scope, valid_for: offer.validFor, request, expires: "2026-09-10T10:09:00Z" });
      } else if (req.method === "GET" && path === `/api/login/${ID}`) {
        const offer = [...stub.offers.values()][0] ?? { scope: [], validFor: 0 };
        const r: LoginRequest = { id: ID, nonce: "ab".repeat(16), browser: K, scope: [...offer.scope], valid_for: offer.validFor, expires: "" };
        if (stub.alter !== undefined) stub.alter(r);
        json(200, r);
      } else if (req.method === "POST" && path === `/api/login/${ID}/answer`) {
        const answer = JSON.parse(await readBody(req)) as Record<string, string>;
        stub.posted = answer;
        const offer = [...stub.offers.values()][0] ?? { scope: [], validFor: 0 };
        const scheme: SchemeRequest = { id: hexToBytes(ID), nonce: hexToBytes("ab".repeat(16)), browser: getPublicKey(browserSeed), scope: offer.scope, validFor: offer.validFor };
        stub.verified = answer["principal"] === principal && verifyLogin(pub, audience, scheme, hexToBytes(answer["possession"] ?? ""));
        if (stub.refuse !== undefined) { json(403, { error: stub.refuse }); return; }
        res.writeHead(204);
        res.end();
      } else {
        json(404, { error: "expired_token" });
      }
    })().catch((e) => { res.writeHead(500); res.end(String(e)); });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const origin = `http://127.0.0.1:${port}`;
  const audience = `${origin}/api`;

  // One run of the form against a freshly scripted stub, with everything it wrote and every
  // sleep it asked for handed back.
  const go = async (args: string[], script: (s: OfferStub) => void = () => {}) => {
    stub = freshStub();
    script(stub);
    const out: string[] = [];
    const err: string[] = [];
    const sleeps: number[] = [];
    const io: LoginIo = {
      writeErr: (t) => { err.push(t); },
      sleep: async (s) => { sleeps.push(s); },
      now: () => 1789034640, // 2026-09-10T10:04:00Z, so the ledger is byte-exact
    };
    let error: Error | undefined;
    try {
      await run(args, (t) => { out.push(t); }, io);
    } catch (e) {
      error = e instanceof Error ? e : new Error(String(e));
    }
    return { error, out: out.join(""), err: err.join(""), sleeps };
  };
  const base = ["--audience", audience, "--scope", "read:projects", "--scope", "read:campaigns", "--valid-for", "28800", "--key", "julia"];
  const ledger = (verdict: string): string =>
    `you offered ${audience} to let browser key ${K} act as you:\n  read:projects\n  read:campaigns\nfor 8h0m0s, until 2026-09-10T18:04:00Z\nsigned with the store key julia\n${verdict}`;
  const theCode = (): string => {
    assert.equal(stub.offers.size, 1, "exactly one offer must be registered");
    return [...stub.offers.keys()][0]!;
  };

  try {
    // Offers, waits for the page, answers only the request that took the offer.
    let r = await go(base, (s) => { s.page = `${origin}/login`; });
    assert.equal(r.error, undefined, r.error?.message);
    const code = theCode();
    assert.equal(code.length, 32, "the code has 32 hex characters");
    assert.equal(r.out, ledger("the service accepted the login. the browser is in.\n"));
    assert.ok(!r.out.includes(code), "the code was printed on stdout — stdout may be a log");
    for (const want of [
      `offer registered at ${audience}\n`,
      `code: ${code}\n`,
      `page: ${origin}/login#${code} (on the service's own origin)\n`,
      "waiting for the page to take the offer, up to 300s\n",
    ]) assert.ok(r.err.includes(want), `stderr lacks ${JSON.stringify(want)}:\n${r.err}`);
    assert.deepEqual(r.sleeps, [2, 2], "one interval before each of the two polls");
    assert.deepEqual(stub.requests, ["POST /api/login/offers", `GET /api/login/offers/${code}`, `GET /api/login/offers/${code}`, `GET /api/login/${ID}`, `POST /api/login/${ID}/answer`]);
    assert.ok(stub.verified, "the service did not verify a proof for the sealed key's principal");
    assert.equal(stub.posted?.["principal"], principal);

    // A request that differs from the offer is refused, and nothing is signed (rule 2).
    const alterations: [string, Alter][] = [
      ["a changed entry", (q) => { q.scope[1] = "read:campaign"; }],
      ["a reordered entry", (q) => { q.scope.reverse(); }],
      ["an extra entry", (q) => { q.scope.push("write:projects"); }],
      ["a dropped entry", (q) => { q.scope.pop(); }],
      ["a changed validity", (q) => { q.valid_for += 1; }],
    ];
    for (const [name, alter] of alterations) {
      r = await go(base, (s) => { s.alter = alter; });
      assert.match(r.error?.message ?? "", /differs from the offer/, name);
      assert.equal(r.out, "", `${name}: a refused login printed a ledger`);
      assert.equal(stub.posted, undefined, `${name}: an answer was posted`);
    }

    // --yes is refused before any request.
    r = await go([...base, "--yes"]);
    assert.match(r.error?.message ?? "", /drop --yes/);
    assert.equal(stub.requests.length, 0);

    // No audience anywhere: refused before any request, naming both sources.
    r = await go(base.slice(2));
    assert.match(r.error?.message ?? "", /ARCHON_AUDIENCE/);
    assert.equal(stub.requests.length, 0);

    // A non-canonical --audience is refused naming the derived spelling.
    r = await go(["--audience", audience.toUpperCase(), ...base.slice(2)]);
    assert.match(r.error?.message ?? "", /not canonical/);
    r = await go(["--audience", `${audience}/`, ...base.slice(2)]);
    assert.match(r.error?.message ?? "", /not valid/);
    assert.equal(stub.requests.length, 0);

    // ARCHON_AUDIENCE is the configured default.
    process.env["ARCHON_AUDIENCE"] = audience;
    r = await go(base.slice(2));
    delete process.env["ARCHON_AUDIENCE"];
    assert.equal(r.error, undefined, r.error?.message);
    assert.ok(r.out.startsWith(`you offered ${audience} `) && stub.verified, "the environment's audience was not used");

    // A page not on the service's origin is marked, and nothing is opened.
    r = await go(base, (s) => { s.page = "https://evil.example/login"; });
    assert.equal(r.error, undefined, r.error?.message);
    assert.ok(r.err.includes(`page: https://evil.example/login#${theCode()} (NOT on the service's origin — do not open it)\n`), r.err);

    // A refusal by the service is recorded in the ledger, and the command still fails.
    r = await go(base, (s) => { s.refuse = "invalid_grant"; });
    assert.match(r.error?.message ?? "", /refused the login \(invalid_grant\)/);
    assert.equal(r.out, ledger("the service refused the login (invalid_grant). the browser is not in.\n"));

    // An offer the page never took.
    r = await go(base, (s) => { s.pollPlan = [404]; });
    assert.match(r.error?.message ?? "", /expired before the page took it/);
    assert.equal(r.out, "");
    assert.equal(stub.posted, undefined);

    // A 429 is sleep-and-retry, never an error.
    r = await go(base, (s) => { s.pollPlan = [429]; s.takenAt = 3; });
    assert.equal(r.error, undefined, r.error?.message);
    assert.deepEqual([r.sleeps.length, stub.polls], [3, 3], "one sleep before each of three polls");

    // An echo that differs from the offer is refused before any poll.
    r = await go(base, (s) => { s.echoValidForDelta = 1; });
    assert.match(r.error?.message ?? "", /altered the offer/);
    assert.equal(stub.polls, 0, "polls after an altered echo");

    // --valid-for is required, and is a whole positive number of seconds.
    r = await go(["--audience", audience, "--scope", "read:projects", "--key", "julia"]);
    assert.match(r.error?.message ?? "", /required/);
    for (const bad of ["0", "-5", "8h", "1.5"]) {
      r = await go(["--audience", audience, "--scope", "read:projects", "--valid-for", bad, "--key", "julia"]);
      assert.ok(r.error !== undefined, `accepted --valid-for ${bad}`);
    }
    assert.equal(stub.requests.length, 0);

    // A scope entry that could lie on screen is refused before any request.
    r = await go(["--audience", audience, "--scope", "read:\u001b[2Jx", "--valid-for", "60", "--key", "julia"]);
    assert.match(r.error?.message ?? "", /control character/);
    r = await go(["--audience", audience, "--scope", "", "--valid-for", "60", "--key", "julia"]);
    assert.ok(r.error !== undefined, "an empty --scope value was accepted");
    assert.equal(stub.requests.length, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    for (const [name, value] of [["ARCHON_HOME", saved.home], ["ARCHON_KEY_PASSWORD", saved.password], ["ARCHON_AUDIENCE", saved.audience]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(home, { recursive: true, force: true });
  }
});
