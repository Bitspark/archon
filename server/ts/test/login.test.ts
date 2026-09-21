// The TypeScript lane's suite, deliberately the same cases as the Go and Rust lanes': the
// three server lanes must agree, and keeping the suites parallel is how a divergence shows up
// as a failing test rather than as a surprise in production.
//
// Every case plays the browser and the CLI against the handler with the real sdk. The clock
// and the entropy are injected, so nothing sleeps and nothing flakes.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { getPublicKey } from "@bitspark/archon";
import { encodeKey } from "@bitspark/archon";
import { LOGIN_MAX_FIELD_SIZE, proveCollect, proveLogin, verifyLogin, type LoginRequest } from "@bitspark/archon-sdk";

import { COLLECT_HEADER, DEFAULT_INTERVAL_SECONDS, DEFAULT_TTL_SECONDS, Handler, type AdmitAuthority, type Entropy } from "../src/login.js";
import { authoritySpan, checkCode, checkScopeEntry, fromHex, stripMount, toHex } from "../src/json.js";

const AUDIENCE = "https://dawn.example/api";

/** The address a service configures for the offers form (§4.1); only the tests that need the
 *  optional `page` key set it, so both shapes are on the wire. */
const PAGE = "https://dawn.example/login";

/** The host in a request URL is NEVER read by the handler — the audience is configuration
 *  (Finding 1) — so the suite uses a host that is deliberately not the audience's. */
const ORIGIN = "http://localhost:9999";

function seedFor(b: number): Uint8Array {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = (b + i) & 0xff;
  return seed;
}

/** Distinct, predictable bytes per call, so an id and a nonce are never accidentally equal. */
function countingEntropy(): Entropy {
  let n = 0;
  return (size: number) => {
    n += 1;
    return new Uint8Array(size).fill(n & 0xff);
  };
}

interface Harness {
  handler: Handler;
  now: { seconds: number };
}

function makeHandler(admit?: AdmitAuthority, mount?: string, page?: string): Harness {
  const now = { seconds: 1_789_034_640 };
  const handler = new Handler({
    audience: AUDIENCE,
    ...(mount === undefined ? {} : { mount }),
    ...(admit === undefined ? {} : { admit }),
    ...(page === undefined ? {} : { page }),
    clock: () => now.seconds,
    entropy: countingEntropy(),
  });
  return { handler, now };
}

function request(method: string, path: string, body?: string, headers?: Record<string, string>): Request {
  const init: RequestInit = { method, ...(headers === undefined ? {} : { headers }) };
  if (body !== undefined) init.body = body;
  return new Request(`${ORIGIN}${path}`, init);
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (text.length === 0) return {};
  return JSON.parse(text) as Record<string, unknown>;
}

/** Opens a login and returns the id plus the scheme request the CLI would prove over. */
async function begin(
  h: Handler,
  browserSeed: Uint8Array,
  scope: string[],
  validFor: number,
  prefix = "",
): Promise<{ id: string; req: LoginRequest }> {
  const browser = getPublicKey(browserSeed);
  const body = JSON.stringify({ browser: encodeKey(browser), scope, valid_for: validFor });
  const response = await h.handle(request("POST", `${prefix}/`, body));
  assert.equal(response.status, 201, `begin: ${await response.clone().text()}`);
  const opened = await bodyOf(response);
  const id = opened["id"] as string;
  return {
    id,
    req: { id: fromHex(id), nonce: fromHex(opened["nonce"] as string), browser, scope, validFor },
  };
}

function answerBody(personSeed: Uint8Array, proof: Uint8Array, authority?: unknown): string {
  const payload: Record<string, unknown> = {
    principal: encodeKey(getPublicKey(personSeed)),
    possession: toHex(proof),
  };
  if (authority !== undefined) payload["authority"] = authority;
  return JSON.stringify(payload);
}

/** A well-formed code — 16 bytes as 32 lowercase hex characters — distinct per byte, so two
 *  tests never share one by accident. */
function codeFor(b: number): string {
  return b.toString(16).padStart(2, "0").repeat(16);
}

function offerBody(code: string, scope: string[], validFor: number): string {
  return JSON.stringify({ code, scope, valid_for: validFor });
}

/** §4's begin body with the one member §4.1 adds. */
function beginOnBody(code: string, browser: Uint8Array, scope: string[], validFor: number): string {
  return JSON.stringify({ browser: encodeKey(browser), scope, valid_for: validFor, offer: code });
}

/** An entropy whose draws are COUNTED, so a test can assert that a refused begin built
 *  nothing — the id and the nonce would be the first things built. */
function countedEntropy(): { entropy: Entropy; drawn: () => number } {
  let n = 0;
  return {
    entropy: (size: number) => {
      n += 1;
      return new Uint8Array(size).fill(n & 0xff);
    },
    drawn: () => n,
  };
}

// THE WHOLE PROTOCOL, browser and CLI played against the handler with the real sdk.
test("end to end", async () => {
  let seen: { browser: Uint8Array; principal: Uint8Array; authority: string } | undefined;
  const { handler } = makeHandler((browser, principal, authority) => {
    seen = { browser, principal, authority: new TextDecoder().decode(authority) };
  });

  const browserSeed = seedFor(1);
  const personSeed = seedFor(100);
  const { id, req } = await begin(handler, browserSeed, ["read:projects", "read:campaigns"], 28800);

  const read = await bodyOf(await handler.handle(request("GET", `/${id}`)));
  assert.equal(read["audience"], undefined, "an audience must never be on the wire");
  assert.equal(read["id"], id);

  const proof = proveLogin(personSeed, AUDIENCE, req);
  const answered = await handler.handle(
    request("POST", `/${id}/answer`, answerBody(personSeed, proof, { grants: ["read:projects"] })),
  );
  assert.equal(answered.status, 204, `answer: ${await answered.clone().text()}`);

  assert.ok(seen !== undefined, "the law was never consulted");
  assert.deepEqual(seen.browser, getPublicKey(browserSeed));
  assert.deepEqual(seen.principal, getPublicKey(personSeed));
  assert.equal(seen.authority, '{"grants":["read:projects"]}', "the authority reached the law altered");

  const collect = toHex(proveCollect(browserSeed, AUDIENCE, req));
  const collected = await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect }));
  assert.equal(collected.status, 200, `collect: ${await collected.clone().text()}`);
  const got = await bodyOf(collected);
  assert.equal(got["principal"], encodeKey(getPublicKey(personSeed)));
  assert.equal(got["possession"], toHex(proof));
  assert.deepEqual(got["authority"], { grants: ["read:projects"] });

  const again = await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect }));
  assert.equal(again.status, 404, "the answer is handed over ONCE");
});

test("a proof-only service needs no authority", async () => {
  const { handler } = makeHandler();
  const personSeed = seedFor(200);
  const { id, req } = await begin(handler, seedFor(2), [], 60);

  // An empty scope is a LIST, never null — a client should not need a special case.
  const read = await bodyOf(await handler.handle(request("GET", `/${id}`)));
  assert.deepEqual(read["scope"], []);

  const proof = proveLogin(personSeed, AUDIENCE, req);
  const answered = await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proof)));
  assert.equal(answered.status, 204);

  // And the browser gets no `authority` key at all, rather than a null one.
  const collect = toHex(proveCollect(seedFor(2), AUDIENCE, req));
  const got = await bodyOf(await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect })));
  assert.equal("authority" in got, false);
});

test("a proof by the wrong key is refused and nothing is stored", async () => {
  const { handler } = makeHandler();
  const personSeed = seedFor(30);
  const { id, req } = await begin(handler, seedFor(3), ["read:projects"], 3600);

  const imposter = proveLogin(seedFor(77), AUDIENCE, req);
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, imposter)))).status, 403);

  // The request must still be answerable by the real holder: a refused answer that consumed
  // the request would be a denial of service by anyone who saw the id.
  const good = proveLogin(personSeed, AUDIENCE, req);
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, good)))).status, 204);
});

test("a proof for another audience is refused", async () => {
  const { handler } = makeHandler();
  const personSeed = seedFor(40);
  const { id, req } = await begin(handler, seedFor(4), ["read:projects"], 3600);
  // The same request, proved against a different service: the phishing case the derived
  // audience rule exists for, seen from the server's side.
  const proof = proveLogin(personSeed, "https://evil.example", req);
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proof)))).status, 403);
});

test("a proof over a wider scope is refused", async () => {
  const { handler } = makeHandler();
  const personSeed = seedFor(50);
  const { id, req } = await begin(handler, seedFor(5), ["read:projects"], 3600);
  const wider: LoginRequest = { ...req, scope: [...req.scope, "publish:everything"] };
  const proof = proveLogin(personSeed, AUDIENCE, wider);
  assert.equal(
    (await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proof)))).status,
    403,
    "the scope is bound, so a delegation wider than the CLI printed cannot verify",
  );
});

test("the law can refuse, and then nothing is stored", async () => {
  const { handler } = makeHandler(() => {
    throw new Error("the law says no");
  });
  const browserSeed = seedFor(6);
  const personSeed = seedFor(60);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
  const proof = proveLogin(personSeed, AUDIENCE, req);
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proof, { nope: true })))).status, 403);

  // The browser must still be told "pending", not handed a refused answer.
  const collect = toHex(proveCollect(browserSeed, AUDIENCE, req));
  const polled = await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect }));
  assert.equal(polled.status, 202, "collect after a refused answer must be authorization_pending");
});

test("a request is consumed by its first verified answer", async () => {
  const { handler } = makeHandler();
  const personSeed = seedFor(70);
  const { id, req } = await begin(handler, seedFor(7), ["read:projects"], 3600);
  const body = answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req));
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, body))).status, 204);
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, body))).status, 409);
});

test("a stranger cannot collect", async () => {
  const { handler } = makeHandler();
  const browserSeed = seedFor(8);
  const personSeed = seedFor(80);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
  const proof = proveLogin(personSeed, AUDIENCE, req);
  await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proof)));

  // The scheme will not prove_collect with a seed the request does not name, so the only way
  // to build this attack at all is to prove over a request naming the stranger — which is
  // exactly what an attacker with their own key has.
  const strangerSeed = seedFor(9);
  const theirs: LoginRequest = { ...req, browser: getPublicKey(strangerSeed) };
  const stranger = toHex(proveCollect(strangerSeed, AUDIENCE, theirs));
  assert.equal((await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: stranger }))).status, 403);

  // A login proof is not a collect proof: the roles are distinct (§3.3).
  assert.equal(
    (await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: toHex(proof) }))).status,
    403,
  );
  // And no header at all.
  assert.equal((await handler.handle(request("GET", `/${id}/answer`))).status, 403);
});

test("polling faster than the interval is slowed down", async () => {
  const { handler, now } = makeHandler();
  const browserSeed = seedFor(10);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
  const headers = { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) };

  assert.equal((await handler.handle(request("GET", `/${id}/answer`, undefined, headers))).status, 202);
  assert.equal((await handler.handle(request("GET", `/${id}/answer`, undefined, headers))).status, 429);
  now.seconds += DEFAULT_INTERVAL_SECONDS;
  assert.equal((await handler.handle(request("GET", `/${id}/answer`, undefined, headers))).status, 202);
});

// caa's finding, carried from the Go lane rather than rediscovered here. The timer advances
// only for a poll whose collect proof VERIFIED — otherwise a stranger polling junk keeps the
// real browser at 429 forever, and slow_down becomes a denial of service handed to anyone who
// saw the id.
test("an unverified poll does not hold the browser in slow_down", async () => {
  const { handler } = makeHandler();
  const browserSeed = seedFor(11);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);

  const junk = toHex(new Uint8Array(64));
  for (let i = 0; i < 5; i++) {
    assert.equal(
      (await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: junk }))).status,
      403,
      `junk poll ${i}`,
    );
  }
  const real = { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) };
  assert.equal(
    (await handler.handle(request("GET", `/${id}/answer`, undefined, real))).status,
    202,
    "the real browser after five junk polls",
  );
});

test("everything about an expired request is 404", async () => {
  const { handler, now } = makeHandler();
  const personSeed = seedFor(120);
  const { id, req } = await begin(handler, seedFor(12), ["read:projects"], 3600);
  now.seconds += DEFAULT_TTL_SECONDS + 1;

  assert.equal((await handler.handle(request("GET", `/${id}`))).status, 404);
  const answered = await handler.handle(
    request("POST", `/${id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req))),
  );
  assert.equal(answered.status, 404);
  assert.equal((await bodyOf(answered))["error"], "expired_token");
});

test("an unknown id is indistinguishable from an expired one", async () => {
  const { handler } = makeHandler();
  const response = await handler.handle(request("GET", `/${"ab".repeat(16)}`));
  assert.equal(response.status, 404);
  assert.equal((await bodyOf(response))["error"], "expired_token");
});

// The door: what begin refuses before a request exists at all.
test("begin refusals", async () => {
  const key = encodeKey(getPublicKey(seedFor(13)));
  const cases: [string, string][] = [
    ["browser is not key text", JSON.stringify({ browser: "7a91", scope: ["a"], valid_for: 60 })],
    ["valid_for is zero", JSON.stringify({ browser: key, scope: ["a"], valid_for: 0 })],
    ["valid_for is not an integer", JSON.stringify({ browser: key, scope: ["a"], valid_for: 1.5 })],
    ["a scope entry is empty", JSON.stringify({ browser: key, scope: [""], valid_for: 60 })],
    ["a scope entry is not a string", JSON.stringify({ browser: key, scope: [7], valid_for: 60 })],
    ["a control character", JSON.stringify({ browser: key, scope: ["read:\u001b[2Jx"], valid_for: 60 })],
    ["a lone surrogate", `{"browser":"${key}","scope":["read:\\ud800"],"valid_for":60}`],
    ["an unknown field", JSON.stringify({ browser: key, scope: ["a"], valid_for: 60, audience: "https://evil.example" })],
    // The camelCase spelling a TypeScript caller reaches for is REFUSED: accepting it here
    // would let them write a client that go and rs reject. One wire, three lanes.
    ["the camelCase spelling", JSON.stringify({ browser: key, scope: ["a"], validFor: 60 })],
    ["not json at all", "{"],
    ["a json array", "[]"],
  ];
  for (const [name, body] of cases) {
    const { handler } = makeHandler();
    assert.equal((await handler.handle(request("POST", "/", body))).status, 400, name);
  }
});

// The audience is configuration, and a misconfiguration is a startup error an operator can
// read. Each of these DERIVES (by §2.1) to something other than itself, so a handler
// configured with one would bind a string the CLI never produces.
test("the constructor refuses an audience that is not canonical", () => {
  for (const bad of [
    "",
    "https://dawn.example/api/",
    "https://Dawn.Example/api",
    "https://dawn.example:443/api",
    "wss://dawn.example/api",
    "HTTPS://dawn.example/api",
    "https://dawn.example/api?x=1",
    "dawn.example/api",
  ]) {
    assert.throws(() => new Handler({ audience: bad }), `accepted audience ${JSON.stringify(bad)}`);
  }
  // The error must NAME the spelling the CLI will derive, so the fix is in the message.
  assert.throws(
    () => new Handler({ audience: "https://Dawn.Example/api" }),
    /https:\/\/dawn\.example\/api/,
  );
  assert.doesNotThrow(() => new Handler({ audience: AUDIENCE }));
});

// THE MOUNT RULE, tested on the function rather than only through the handler.
//
// Through `handle` this rule is nearly invisible: a path that should be refused here goes on
// to miss the id lookup and produce the same 404 anyway, so a handler-level test passes
// whether the rule is present or not. That is not a guess -- the guard was removed and the
// suite stayed green, which is how this test came to exist.
test("the mount is stripped exactly", () => {
  assert.equal(stripMount("/api/login", "/api/login"), "");
  assert.equal(stripMount("/api/login/ab12", "/api/login"), "/ab12");
  assert.equal(stripMount("/api/login/ab12/answer", "/api/login"), "/ab12/answer");
  // A neighbouring path that merely starts with the same letters is NOT ours: it belongs to
  // whatever else the service routes, and a handler that swallowed it would be taking someone
  // else's URL.
  assert.equal(stripMount("/api/loginX/ab12", "/api/login"), undefined);
  assert.equal(stripMount("/api/login2", "/api/login"), undefined);
  assert.equal(stripMount("/elsewhere", "/api/login"), undefined);
  // A trailing slash on the mount is the same mount.
  assert.equal(stripMount("/api/login/ab12", "/api/login/"), "/ab12");
  // No mount: every path is ours, unchanged.
  assert.equal(stripMount("/ab12/answer", ""), "/ab12/answer");
});

test("a mounted handler serves its own paths and refuses the rest", async () => {
  const { handler } = makeHandler(undefined, "/api/login");
  const { id } = await begin(handler, seedFor(15), ["read:projects"], 60, "/api/login");
  assert.equal((await handler.handle(request("GET", `/api/login/${id}`))).status, 200);
  // A neighbouring path that merely starts with the same letters is NOT ours, and neither is
  // one outside the mount.
  assert.equal((await handler.handle(request("GET", `/api/loginX/${id}`))).status, 404);
  assert.equal((await handler.handle(request("GET", `/elsewhere/${id}`))).status, 404);
  // A query string is not part of the path: no route reads one.
  assert.equal((await handler.handle(request("GET", `/api/login/${id}?from=email`))).status, 200);
});

// Sweep is optional tidiness, not correctness — records expire on read regardless. The test
// says which, so nobody later "fixes" the absence of a background task.
test("sweep is optional", async () => {
  const { handler, now } = makeHandler();
  await begin(handler, seedFor(16), ["read:projects"], 60);
  assert.equal(handler.sweep(), 0, "swept a live record");
  now.seconds += DEFAULT_TTL_SECONDS + 1;
  assert.equal(handler.sweep(), 1);
});

// A PENDING LAW MUST NOT STALL THE HANDLER. `AdmitAuthority` is the service's own code and may
// await a database or a network. In go and rs the rule is "do not hold the store's mutex
// across it"; here there is no mutex, and the equivalent claim is that another request served
// while one is inside the law completes on its own.
test("a pending law does not block another request", async () => {
  let enteredResolve: (() => void) | undefined;
  const enteredLaw = new Promise<void>((resolve) => {
    enteredResolve = resolve;
  });
  let release: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  let first = true;
  const { handler } = makeHandler(async () => {
    // Only the FIRST admitter waits.
    if (first) {
      first = false;
      enteredResolve?.();
      await gate;
    }
  });

  const browserSeed = seedFor(14);
  const personSeed = seedFor(140);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
  const answering = handler.handle(
    request("POST", `/${id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req))),
  );
  await enteredLaw;

  // The law is now inside and pending. A read must still complete.
  const read = await handler.handle(request("GET", `/${id}`));
  assert.equal(read.status, 200, "a read did not complete while the law was pending");

  release?.();
  assert.equal((await answering).status, 204);
});

// TWO CLIs ANSWERING ONE LOGIN, the second landing while the first is still inside the law.
//
// This is the case the RE-CHECK after the await exists for, and the only case that reaches it:
// a sequential second answer is caught by the earlier check, so without an interleaving that
// branch is dead code a refactor could quietly delete. In this lane the interleaving is not a
// rare race — an `await` GUARANTEES it — which is why the Rust lane's version of this test is
// carried here from the start rather than added after something went wrong.
test("a second answer during verification loses cleanly", async () => {
  let enteredResolve: (() => void) | undefined;
  const enteredLaw = new Promise<void>((resolve) => {
    enteredResolve = resolve;
  });
  let release: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  let first = true;
  const { handler } = makeHandler(async () => {
    if (first) {
      first = false;
      enteredResolve?.();
      await gate;
    }
  });

  const browserSeed = seedFor(23);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);

  // The binding does not name the principal (§3.2), so two different key holders can each make
  // a genuine proof for one request. Both are real; only one can win.
  const slowSeed = seedFor(230);
  const fastSeed = seedFor(231);
  const slow = handler.handle(
    request("POST", `/${id}/answer`, answerBody(slowSeed, proveLogin(slowSeed, AUDIENCE, req))),
  );
  await enteredLaw;

  const fast = await handler.handle(
    request("POST", `/${id}/answer`, answerBody(fastSeed, proveLogin(fastSeed, AUDIENCE, req))),
  );
  assert.equal(fast.status, 204, "the second CLI, arriving while the first is being admitted, wins outright");

  release?.();
  assert.equal((await slow).status, 409, "the answer that lost the race must be refused, not stored over the winner");

  const collect = toHex(proveCollect(browserSeed, AUDIENCE, req));
  const collected = await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect }));
  assert.equal(collected.status, 200);
  assert.equal(
    (await bodyOf(collected))["principal"],
    encodeKey(getPublicKey(fastSeed)),
    "the browser must get the answer that won the race",
  );
});

// THE CROSS-LANE WIRE FIXTURE, the same file the Go and Rust lanes read. A cross-lane smoke
// run is impractical for a server (each lane needs its own socket and runtime), so this is
// where go, rs and ts are held to one wire format. It pins KEYS and their absence, not values:
// an id and a nonce are random by construction, and pinning them would pin the entropy.
interface WireFixture {
  responses: Record<string, { status: number; keys: string[]; optional_keys?: string[]; forbidden_keys: string[] }>;
  errors: { keys: string[]; codes: Record<string, { status: number; error: string }> };
  authority_roundtrip: { payload: string };
  offer_mismatch: {
    offer: { scope: string[]; valid_for: number };
    cases: { name: string; scope: string[]; valid_for: number; status: number; error: string }[];
  };
  malformed_bodies: {
    cases: {
      name: string;
      route: string;
      append_to_a_valid_body: string;
      status: number;
      error: string;
      base_status: number;
    }[];
  };
}

/** Resolved from the process cwd (server/ts, where npm test runs) rather than from
 *  import.meta.url: the compiled test lives under dist/test/, so a URL-relative path would
 *  encode the build layout and break the moment tsconfig's rootDir moves. */
function fixture(): WireFixture {
  return JSON.parse(readFileSync("../testdata/login-wire.json", "utf8")) as WireFixture;
}

test("wire shapes match the shared fixture", async () => {
  const { responses } = fixture();
  assert.ok(Object.keys(responses).length > 0, "a fixture nobody can fail is not a pin");

  // A handler WITH a page configured, so the offer response's optional `page` key is on the
  // wire and the fixture's optional_keys is exercised rather than satisfied by absence.
  const { handler } = makeHandler(undefined, undefined, PAGE);
  const browserSeed = seedFor(17);
  const personSeed = seedFor(170);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
  const code = codeFor(0x08);

  const emitted: Record<string, Response> = {
    begin: await handler.handle(
      request("POST", "/", JSON.stringify({ browser: encodeKey(getPublicKey(seedFor(18))), scope: ["read:projects"], valid_for: 3600 })),
    ),
    read: await handler.handle(request("GET", `/${id}`)),
    answer: await handler.handle(
      request("POST", `/${id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req))),
    ),
    collect: await handler.handle(
      request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) }),
    ),
    // And the offers form (§4.1): the prover offers, the page begins on the offer, the prover
    // reads the offer back — the two routes and the one member the fixture pins.
    offer: await handler.handle(request("POST", "/offers", offerBody(code, ["read:projects"], 3600))),
    begin_on_offer: await handler.handle(
      request("POST", "/", beginOnBody(code, getPublicKey(seedFor(9)), ["read:projects"], 3600)),
    ),
    offer_read: await handler.handle(request("GET", `/offers/${code}`)),
  };

  for (const [route, want] of Object.entries(responses)) {
    const got = emitted[route];
    assert.ok(got !== undefined, `the fixture pins route ${JSON.stringify(route)}, untested here`);
    assert.equal(got.status, want.status, `status for ${route}: ${await got.clone().text()}`);
    const body = await bodyOf(got);
    if (want.keys.length === 0) {
      assert.deepEqual(body, {}, `the fixture says no body for ${route}`);
      continue;
    }
    for (const key of want.keys) {
      assert.ok(key in body, `${route}: missing key ${JSON.stringify(key)}`);
    }
    for (const key of want.forbidden_keys) {
      assert.equal(key in body, false, `${route}: key ${JSON.stringify(key)} must NOT be on the wire`);
    }
    const allowed = new Set([...want.keys, ...(want.optional_keys ?? [])]);
    for (const key of Object.keys(body)) {
      assert.ok(allowed.has(key), `${route}: unexpected key ${JSON.stringify(key)} — the fixture does not allow it`);
    }
  }
});

// EVERY ERROR CODE THE FIXTURE PINS, each driven by the situation that produces it — never by
// building a Response by hand. A code listed in a file three lanes read, that no lane actually
// emits, is a lie in the one place they all trust; the count assertion at the end is what
// keeps this from drifting into a subset.
test("every pinned error code is emitted", async () => {
  const { errors } = fixture();
  const got: Record<string, Response> = {};

  const { handler } = makeHandler();
  got["begin_malformed"] = await handler.handle(request("POST", "/", "{"));
  got["read_unknown_or_expired"] = await handler.handle(request("GET", `/${"ab".repeat(16)}`));

  const browserSeed = seedFor(20);
  const personSeed = seedFor(210);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
  const good = answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req));

  got["answer_malformed"] = await handler.handle(request("POST", `/${id}/answer`, "{"));
  got["answer_proof_refused"] = await handler.handle(
    request("POST", `/${id}/answer`, answerBody(personSeed, proveLogin(seedFor(211), AUDIENCE, req))),
  );

  // Two polls back to back: the first is pending, the second is too fast.
  const headers = { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) };
  got["collect_pending"] = await handler.handle(request("GET", `/${id}/answer`, undefined, headers));
  got["collect_too_fast"] = await handler.handle(request("GET", `/${id}/answer`, undefined, headers));
  got["collect_proof_refused"] = await handler.handle(request("GET", `/${id}/answer`));

  assert.equal((await handler.handle(request("POST", `/${id}/answer`, good))).status, 204);
  got["answer_already_answered"] = await handler.handle(request("POST", `/${id}/answer`, good));

  // A service whose law refuses.
  const refusing = makeHandler(() => {
    throw new Error("no");
  });
  const second = await begin(refusing.handler, seedFor(21), ["read:projects"], 3600);
  got["answer_authority_refused"] = await refusing.handler.handle(
    request("POST", `/${second.id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, second.req))),
  );

  // And a request that ran out of time, approached from both sides.
  const timed = makeHandler();
  const browser3 = seedFor(22);
  const third = await begin(timed.handler, browser3, ["read:projects"], 3600);
  const collect3 = toHex(proveCollect(browser3, AUDIENCE, third.req));
  timed.now.seconds += DEFAULT_TTL_SECONDS + 1;
  got["answer_expired"] = await timed.handler.handle(
    request("POST", `/${third.id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, third.req))),
  );
  got["collect_expired"] = await timed.handler.handle(
    request("GET", `/${third.id}/answer`, undefined, { [COLLECT_HEADER]: collect3 }),
  );

  // The offers form (§4.1). Where the spec says the answers are indistinguishable, one fixture
  // entry is driven several ways and every drive must equal the first, so a lane cannot tell
  // an unknown code from an expired or a malformed one even by accident.
  const scope = ["read:projects"];
  const browserKey = getPublicKey(seedFor(23));
  got["offer_malformed"] = await handler.handle(request("POST", "/offers", offerBody(codeFor(0xc1).slice(0, 30), scope, 3600)));
  const code = codeFor(0xc2);
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, scope, 3600)))).status, 201);
  got["offer_code_taken"] = await handler.handle(request("POST", "/offers", offerBody(code, scope, 3600)));
  got["begin_offer_mismatch"] = await handler.handle(request("POST", "/", beginOnBody(code, browserKey, ["read:campaigns"], 3600)));
  assert.equal((await handler.handle(request("POST", "/", beginOnBody(code, browserKey, scope, 3600)))).status, 201);
  got["begin_offer_taken"] = await handler.handle(request("POST", "/", beginOnBody(code, browserKey, scope, 3600)));
  const expired = makeHandler();
  const stale = codeFor(0xc3);
  assert.equal((await expired.handler.handle(request("POST", "/offers", offerBody(stale, scope, 3600)))).status, 201);
  expired.now.seconds += DEFAULT_TTL_SECONDS + 1;
  const alike = async (name: string, drives: Response[]): Promise<void> => {
    const first = drives[0]!;
    const firstSeen = `${first.status} ${await first.clone().text()}`;
    for (const [i, drive] of drives.entries()) {
      if (i === 0) continue;
      assert.equal(
        `${drive.status} ${await drive.clone().text()}`,
        firstSeen,
        `${name}: drive ${i} differs from drive 0 — the spec says indistinguishable`,
      );
    }
    got[name] = first;
  };
  await alike("offer_unknown_or_expired", [
    await handler.handle(request("GET", `/offers/${codeFor(0xc4)}`)),
    await expired.handler.handle(request("GET", `/offers/${stale}`)),
    await handler.handle(request("GET", `/offers/${code.toUpperCase()}`)),
  ]);
  await alike("begin_offer_unknown_or_expired", [
    await handler.handle(request("POST", "/", beginOnBody(codeFor(0xc4), browserKey, scope, 3600))),
    await expired.handler.handle(request("POST", "/", beginOnBody(stale, browserKey, scope, 3600))),
    await handler.handle(request("POST", "/", beginOnBody(code.slice(0, 30), browserKey, scope, 3600))),
  ]);

  const pinned = Object.keys(errors.codes).filter((name) => !name.startsWith("_"));
  for (const name of pinned) {
    const want = errors.codes[name];
    const response = got[name];
    assert.ok(want !== undefined && response !== undefined, `the fixture pins error ${name}, which no case here drives`);
    assert.equal(response.status, want.status, `status for ${name}`);
    const body = await bodyOf(response);
    assert.equal(body["error"], want.error, `code for ${name}`);
    // The body carries the code and NOTHING else: no description, no echoed id, so a stranger
    // probing ids learns nothing from the difference between them.
    for (const key of Object.keys(body)) {
      assert.ok(errors.keys.includes(key), `${name}: an error body carries ${JSON.stringify(key)}`);
    }
  }
  assert.equal(Object.keys(got).length, pinned.length, "a case driven here that the fixture does not pin");
});

// THE DOOR CHECKS, tested on the function rather than through the handler.
//
// Through `handle` these are invisible: the scheme's own `loginBinding` refuses the same
// strings, so begin answers 400 either way and a handler-level test cannot tell which check
// fired. Removing them and watching the suite stay green is how that was found.
//
// They still belong at the door. The scheme refuses when a proof is MADE, which is AFTER the
// person has read the statement, so a request carrying a string that could repaint the
// terminal would already have been shown. Checking here means it never exists to be shown.
test("a scope entry that could lie on screen is refused at the door", () => {
  assert.throws(() => checkScopeEntry(""), /empty/);
  // ESC [ 2 J is "clear the screen" — the whole reason this check exists.
  assert.throws(() => checkScopeEntry("read:\u001b[2Jx"), /control character/);
  assert.throws(() => checkScopeEntry("read:\u0000"), /control character/);
  assert.throws(() => checkScopeEntry("read:\u007f"), /control character/);
  assert.throws(() => checkScopeEntry("read:\u000d\u000aX-Evil: 1"), /control character/);
  // A lone surrogate is a string JavaScript holds happily and UTF-8 cannot represent. Rust
  // needs no such check — its String cannot hold one — which is exactly why go and ts must.
  assert.throws(() => checkScopeEntry("read:\ud800"), /not valid UTF-8/);
  assert.throws(() => checkScopeEntry("read:\udc00x"), /not valid UTF-8/);
  // A PAIRED surrogate is ordinary text and must pass: refusing every astral character would
  // be a different bug wearing the same clothes.
  assert.doesNotThrow(() => checkScopeEntry("read:\ud83d\ude80"));
  assert.doesNotThrow(() => checkScopeEntry("read:projects"));
});

// THE AUTHORITY IS OPAQUE BYTES (ADR 0007 §B), and this is the pin that says so with VALUES
// rather than with keys. caa found the defect: two of the three lanes re-serialised the
// payload, so one answer produced three different payloads.
//
// This probe is chosen so every way of rebuilding it shows up:
//
//   9007199254740993  does not fit a double — a parse/stringify round trip returns ...992
//   1.10              a float round trip normalises it to 1.1
//   \\u00e9            a parse decodes the escape to the character
//   z before a        an object round trip reorders keys in some lanes
//
// A law that SIGNS its payload, or carries a 64-bit id, gets a different answer per lane if
// any of that happens. So the bytes are carried, never rebuilt.
//
// The payload comes from the SHARED fixture rather than from a constant only this lane
// can see: go and rs assert the same bytes from the same file, which is what makes this
// a cross-lane pin instead of three lanes each believing their own copy.
const PROBE = fixture().authority_roundtrip.payload;

test("the authority is carried as bytes, not re-encoded", async () => {
  // The premise, measured rather than assumed: a round trip really does damage this
  // payload. A reader should be able to see why the test exists.
  assert.notEqual(
    JSON.stringify(JSON.parse(PROBE)),
    PROBE,
    "the probe must be a payload a round trip damages",
  );

  let seen: string | undefined;
  const { handler } = makeHandler((_browser, _principal, authority) => {
    seen = new TextDecoder().decode(authority);
  });

  const browserSeed = seedFor(31);
  const personSeed = seedFor(310);
  const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);

  // Built as TEXT so the test controls the exact bytes on the wire.
  const proof = proveLogin(personSeed, AUDIENCE, req);
  const body =
    `{"principal":${JSON.stringify(encodeKey(getPublicKey(personSeed)))},` +
    `"possession":${JSON.stringify(toHex(proof))},"authority":${PROBE}}`;
  const answered = await handler.handle(request("POST", `/${id}/answer`, body));
  assert.equal(answered.status, 204, await answered.clone().text());

  assert.equal(seen, PROBE, "the law was handed something other than the bytes the CLI sent");

  const collect = toHex(proveCollect(browserSeed, AUDIENCE, req));
  const collected = await handler.handle(
    request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect }),
  );
  assert.equal(collected.status, 200);
  // `no-store` is not decoration: the body carries a possession proof, and a cache holding it
  // is exactly what must not happen. Asserted because this route hand-builds its body.
  assert.equal(collected.headers.get("content-type"), "application/json");
  assert.equal(collected.headers.get("cache-control"), "no-store");
  const raw = await collected.text();
  assert.ok(
    raw.endsWith(`,"authority":${PROBE}}`),
    `the browser received a rebuilt authority: ${raw}`,
  );

  // Every kind of damage a round trip does, named separately, so a regression says WHICH
  // one came back. The last two are caa's second probe -- Go's encoder compacts a
  // RawMessage AND HTML-escapes it, and a payload without whitespace or & could see
  // neither. This lane passes them for free, and carries them so it keeps doing so.
  for (const [what, want] of [
    ["the 64-bit integer changed", "9007199254740993"],
    ["the trailing zero was normalised away", "1.10"],
    ["the escape was decoded", '\\u00e9'],
    ["the insignificant whitespace was compacted away", '{"z":1, "a"'],
    ["the ampersand did not survive", "?a=1&b=2"],
    ["the angle brackets did not survive", "<b>"],
  ] as [string, string][]) {
    assert.ok(raw.includes(want), `${what}: ${JSON.stringify(want)} not in ${raw}`);
  }
  for (const escaped of ['\\u0026', '\\u003c', '\\u003e']) {
    assert.equal(raw.includes(escaped), false, `the payload was HTML-escaped (${escaped}): ${raw}`);
  }
  assert.ok(raw.indexOf('"z"') < raw.indexOf('"a"'), "the keys were reordered");
});

// A member whose value is `null` is a different answer from no member at all (§3.4), and
// a span makes that distinction for free: "null" is a span, absent is undefined.
test("an authority of null is different from no authority at all", async () => {
  const cases: [string, string, boolean][] = [
    ["a null authority is echoed as null", ',"authority":null', true],
    ["an absent authority yields no key", "", false],
  ];
  for (const [name, authority, expected] of cases) {
    const { handler } = makeHandler();
    const browserSeed = seedFor(32);
    const personSeed = seedFor(320);
    const { id, req } = await begin(handler, browserSeed, ["read:projects"], 3600);
    const proof = proveLogin(personSeed, AUDIENCE, req);
    const body =
      `{"principal":${JSON.stringify(encodeKey(getPublicKey(personSeed)))},` +
      `"possession":${JSON.stringify(toHex(proof))}${authority}}`;
    assert.equal((await handler.handle(request("POST", `/${id}/answer`, body))).status, 204, name);
    const collect = toHex(proveCollect(browserSeed, AUDIENCE, req));
    const collected = await handler.handle(
      request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: collect }),
    );
    const raw = await collected.text();
    assert.equal(raw.includes('"authority"'), expected, name);
  }
});

// The scanner measures values of every JSON type, since an authority is whatever the
// service's law says it is. The nasty cases are the ones where a structural character
// appears INSIDE a string: a scanner that counted braces would walk off the end.
test("the authority scanner measures every JSON shape", () => {
  const spanOf = (authority: string): string | undefined =>
    authoritySpan(`{"principal":"x","authority":${authority},"possession":"y"}`);
  const values = [
    "null",
    "true",
    "-0.0e+3",
    '"a string with a \\" quote and a \\\\ backslash"',
    '{"nested":{"deep":[1,2,{"x":[]}]},"brace":"}"}',
    '[1,[2,[3]],"],"]',
    "{}",
    "[]",
  ];
  for (const value of values) {
    assert.equal(spanOf(value), value, `span for ${value}`);
  }
  // Absent is undefined, not empty.
  assert.equal(authoritySpan(`{"principal":"x"}`), undefined);
  assert.equal(authoritySpan("{}"), undefined);
  // Whitespace around the value is not part of it.
  assert.equal(authoritySpan(`{ "authority" : {"a": 1} }`), `{"a": 1}`);
});

// The malformed-body cases the three lanes must answer ALIKE, from the shared fixture.
//
// Each case is members APPENDED to an otherwise-valid body, and the test proves that framing
// by sending the SAME body without them afterwards and requiring `base_status`. So a case
// here cannot pass because the request was refused for some unrelated reason — which is
// exactly how the door-check tests fooled themselves before.
test("malformed bodies are refused alike", async () => {
  const cases = fixture().malformed_bodies.cases;
  assert.ok(cases.length > 0, "a pin nobody can fail is not a pin");

  for (const c of cases) {
    assert.ok(
      c.append_to_a_valid_body.length > 0,
      `${c.name}: appends nothing, so it distinguishes nothing`,
    );
    const { handler } = makeHandler();
    const browserSeed = seedFor(51);
    const personSeed = seedFor(220);

    let path: string;
    let open: string;
    if (c.route === "begin") {
      path = "/";
      open =
        `{"browser":${JSON.stringify(encodeKey(getPublicKey(browserSeed)))},` +
        '"scope":["read:projects"],"valid_for":3600';
    } else if (c.route === "answer") {
      const opened = await begin(handler, browserSeed, ["read:projects"], 3600);
      const proof = proveLogin(personSeed, AUDIENCE, opened.req);
      path = `/${opened.id}/answer`;
      open =
        `{"principal":${JSON.stringify(encodeKey(getPublicKey(personSeed)))},` +
        `"possession":${JSON.stringify(toHex(proof))}`;
    } else if (c.route === "offer") {
      // The third route a body enters by (§4.1). The base body's 201 is what proves the
      // refusal above was for the repeated member and not for the code.
      path = "/offers";
      open = `{"code":${JSON.stringify(codeFor(0x77))},"scope":["read:projects"],"valid_for":3600`;
    } else {
      throw new Error(`the fixture names a route this suite does not drive: ${c.route}`);
    }

    const refused = await handler.handle(
      request("POST", path, `${open}${c.append_to_a_valid_body}}`),
    );
    assert.equal(refused.status, c.status, `${c.name}: ${await refused.clone().text()}`);
    assert.equal((await bodyOf(refused))["error"], c.error, c.name);

    // The framing: the same body WITHOUT the appended members is accepted. If this fails,
    // the case above proved nothing about what it names.
    const landed = await handler.handle(request("POST", path, `${open}}`));
    assert.equal(
      landed.status,
      c.base_status,
      `${c.name}: the base body must be accepted, else the case proves nothing: ${await landed.clone().text()}`,
    );
  }
});

// ---- THE OFFERS FORM (docs/login.md §4.1) ------------------------------------------------
//
// The prover starts, the page finishes. Two routes and one member; the binding and the proofs
// are the same, so every case below ends in the same sdk calls the page-started form ends in.
// Names and cases mirror the Go and Rust suites.

test("offers end to end", async () => {
  const { handler } = makeHandler(undefined, undefined, PAGE);
  const browserSeed = seedFor(60);
  const personSeed = seedFor(160);
  const browser = getPublicKey(browserSeed);
  const scope = ["read:projects", "read:campaigns"];
  const code = codeFor(0xa1);

  // The prover offers what it is willing to delegate, to a key it does not know yet.
  const offered = await handler.handle(request("POST", "/offers", offerBody(code, scope, 28800)));
  assert.equal(offered.status, 201, await offered.clone().text());
  const offer = await bodyOf(offered);
  assert.equal(offer["code"], code);
  // The code rides in the page's FRAGMENT — the part of an address a browser never sends to
  // any server — so the page's script reads it and no log does (§4.1 "The code").
  assert.equal(offer["page"], `${PAGE}#${code}`, "the code must ride in the page's fragment");
  assert.equal(offer["expires_in"], DEFAULT_TTL_SECONDS);
  assert.equal(offer["interval"], DEFAULT_INTERVAL_SECONDS);
  assert.equal("audience" in offer, false, "an audience on the wire — Finding 1 applies to this route too");

  // The page reads the offer: open, nothing taken yet.
  const read = await bodyOf(await handler.handle(request("GET", `/offers/${code}`)));
  assert.equal(read["request"], null, "an open offer must say request: null");
  assert.deepEqual(read["scope"], scope);

  // The page begins on the offer with EXACTLY what was offered.
  const begun = await handler.handle(request("POST", "/", beginOnBody(code, browser, scope, 28800)));
  assert.equal(begun.status, 201, await begun.clone().text());
  const opened = await bodyOf(begun);
  assert.equal("offer" in opened, false, "begin's response must not echo the offer — one shape for begin");
  const id = opened["id"] as string;

  // The prover polls: taken, and by that request.
  const polled = await bodyOf(await handler.handle(request("GET", `/offers/${code}`)));
  assert.equal(polled["request"], id);

  // The prover reads the request the offer names. The CLI re-checks scope and validity itself
  // (§4.1 rule 2); here the server's word is checked to be the offer's.
  const requested = await bodyOf(await handler.handle(request("GET", `/${id}`)));
  assert.equal(requested["browser"], encodeKey(browser));
  assert.equal(requested["valid_for"], 28800);
  assert.deepEqual(requested["scope"], scope);

  // ...it answers with the sdk, the page collects, and the proof verifies — §4 unchanged.
  const req: LoginRequest = { id: fromHex(id), nonce: fromHex(requested["nonce"] as string), browser, scope, validFor: 28800 };
  const answered = await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req))));
  assert.equal(answered.status, 204, await answered.clone().text());
  const collected = await handler.handle(
    request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) }),
  );
  assert.equal(collected.status, 200, await collected.clone().text());
  const answer = await bodyOf(collected);
  assert.equal(answer["principal"], encodeKey(getPublicKey(personSeed)));
  assert.ok(verifyLogin(getPublicKey(personSeed), AUDIENCE, req, fromHex(answer["possession"] as string)), "the collected answer is not the person's verified proof");

  // ...and the offer died with its request (§4.1 "State").
  const gone = await handler.handle(request("GET", `/offers/${code}`));
  assert.equal(gone.status, 404, "after collection the offer must be gone");
  assert.equal((await bodyOf(gone))["error"], "expired_token");
});

// THE offer_mismatch FAMILY from the shared fixture: a request naming an offer whose scope or
// validity differ IN ANY WAY is refused before anything is stored and before any key is
// involved. "Nothing stored" and "no key involved" are asserted, not assumed: a refused begin
// draws no entropy (the id and nonce would be the first thing built), and the offer is still
// open afterwards. Then the FRAMING: the exact offer is accepted, and accepted once.
test("a mismatched request is refused before anything is stored", async () => {
  const family = fixture().offer_mismatch;
  assert.ok(family.cases.length > 0, "a pin nobody can fail is not a pin");
  const counted = countedEntropy();
  const handler = new Handler({ audience: AUDIENCE, clock: () => 1_789_034_640, entropy: counted.entropy });
  const browser = getPublicKey(seedFor(61));
  const code = codeFor(0xa2);
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, family.offer.scope, family.offer.valid_for)))).status, 201);
  const drawn = counted.drawn();

  for (const c of family.cases) {
    const refused = await handler.handle(request("POST", "/", beginOnBody(code, browser, c.scope, c.valid_for)));
    assert.equal(refused.status, c.status, `${c.name}: ${await refused.clone().text()}`);
    assert.equal((await bodyOf(refused))["error"], c.error, c.name);
    assert.equal(counted.drawn(), drawn, `${c.name}: a refused begin drew entropy — a request was built before the offer was checked`);
    const read = await bodyOf(await handler.handle(request("GET", `/offers/${code}`)));
    assert.equal(read["request"], null, `${c.name}: a refused begin took the offer`);
  }

  // A begin that passes the offer check but fails LATER must not take the offer either: the
  // take happens with the store, in one synchronous span, and a body refused after the check
  // never reaches it.
  const late = await handler.handle(
    request("POST", "/", JSON.stringify({ browser: "not a key", scope: family.offer.scope, valid_for: family.offer.valid_for, offer: code })),
  );
  assert.equal(late.status, 400, "a malformed browser key on an exact offer");
  assert.equal((await bodyOf(await handler.handle(request("GET", `/offers/${code}`))))["request"], null, "a begin refused after the offer check took the offer");

  // THE FRAMING: the exact offer is accepted — else the cases above proved nothing — and the
  // same request a second time is refused as taken (one offer, one request).
  const exact = await handler.handle(request("POST", "/", beginOnBody(code, browser, family.offer.scope, family.offer.valid_for)));
  assert.equal(exact.status, 201, `the exact offer must be accepted, else the family proves nothing: ${await exact.clone().text()}`);
  const again = await handler.handle(request("POST", "/", beginOnBody(code, browser, family.offer.scope, family.offer.valid_for)));
  assert.equal(again.status, 409, "a second request on a taken offer");
  assert.equal((await bodyOf(again))["error"], "invalid_request");
});

test("one offer, one request", async () => {
  const { handler, now } = makeHandler();
  const browser = getPublicKey(seedFor(62));
  const scope = ["read:projects"];
  const code = codeFor(0xa3);

  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, scope, 3600)))).status, 201);
  // One code, one offer: a second registration under a LIVE code is a conflict.
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, scope, 3600)))).status, 409, "a second offer under a live code");
  // One offer, one request: the first matching request takes it, the next is refused, and
  // the poll keeps naming the first.
  const begun = await handler.handle(request("POST", "/", beginOnBody(code, browser, scope, 3600)));
  assert.equal(begun.status, 201, await begun.clone().text());
  const first = (await bodyOf(begun))["id"];
  assert.equal(
    (await handler.handle(request("POST", "/", beginOnBody(code, getPublicKey(seedFor(63)), scope, 3600)))).status,
    409,
    "a second request on a taken offer",
  );
  assert.equal((await bodyOf(await handler.handle(request("GET", `/offers/${code}`))))["request"], first, "the offer must keep naming the first request");

  // Past its TTL the offer is dead — and so is its request — and the code is FREE again: a new
  // registration replaces the dead one rather than colliding with it.
  now.seconds += DEFAULT_TTL_SECONDS + 1;
  assert.equal((await handler.handle(request("GET", `/offers/${code}`))).status, 404);
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, scope, 3600)))).status, 201, "re-registering a dead code");
});

// Unknown, expired and MALFORMED codes are one answer, on both routes a code can name an offer
// by: a registered code is always well-formed, so a malformed one is unknown by construction,
// and a stranger probing learns nothing from the difference. Only the offer route itself says
// 400 to a malformed code — that one is the prover's own mistake, and the prover is who is told.
test("an unknown, expired or malformed code is 404 alike", async () => {
  const { handler, now } = makeHandler();
  const browser = getPublicKey(seedFor(64));
  const good = codeFor(0xab);
  const codes: [string, string][] = [
    ["unknown", codeFor(0xee)],
    ["not hex", `zz${good.slice(2)}`],
    ["odd length", good.slice(0, 31)],
    ["too short", good.slice(0, 30)],
    ["uppercase", good.toUpperCase()],
  ];
  for (const [name, code] of codes) {
    const read = await handler.handle(request("GET", `/offers/${code}`));
    assert.equal(read.status, 404, `${name}: read`);
    assert.equal((await bodyOf(read))["error"], "expired_token", `${name}: read`);
    const begun = await handler.handle(request("POST", "/", beginOnBody(code, browser, ["read:projects"], 3600)));
    assert.equal(begun.status, 404, `${name}: begin`);
    assert.equal((await bodyOf(begun))["error"], "expired_token", `${name}: begin`);
  }

  // An expired one, from both sides.
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(good, ["read:projects"], 3600)))).status, 201);
  now.seconds += DEFAULT_TTL_SECONDS + 1;
  assert.equal((await handler.handle(request("GET", `/offers/${good}`))).status, 404, "expired: read");
  assert.equal((await handler.handle(request("POST", "/", beginOnBody(good, browser, ["read:projects"], 3600)))).status, 404, "expired: begin");

  // Whereas the prover registering a malformed code is told so: 400, nothing registered.
  for (const [name, code] of codes.slice(1)) {
    const refused = await handler.handle(request("POST", "/offers", offerBody(code, ["read:projects"], 3600)));
    assert.equal(refused.status, 400, `${name}: offer`);
    assert.equal((await bodyOf(refused))["error"], "invalid_request", `${name}: offer`);
  }
});

// An offer dies with its request (§4.1 "State"), and the store knows it without anything
// running at collection time: liveness consults the record the offer points at.
test("an offer dies with its request", async () => {
  const { handler, now } = makeHandler();
  const browserSeed = seedFor(65);
  const personSeed = seedFor(165);
  const browser = getPublicKey(browserSeed);
  const scope = ["read:projects"];

  // Collected: the request is handed over once and dropped, and the offer goes with it.
  const code = codeFor(0xa5);
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, scope, 3600)))).status, 201);
  const begun = await handler.handle(request("POST", "/", beginOnBody(code, browser, scope, 3600)));
  assert.equal(begun.status, 201);
  const opened = await bodyOf(begun);
  const id = opened["id"] as string;
  const req: LoginRequest = { id: fromHex(id), nonce: fromHex(opened["nonce"] as string), browser, scope, validFor: 3600 };
  assert.equal((await handler.handle(request("POST", `/${id}/answer`, answerBody(personSeed, proveLogin(personSeed, AUDIENCE, req))))).status, 204);
  assert.equal(
    (await handler.handle(request("GET", `/${id}/answer`, undefined, { [COLLECT_HEADER]: toHex(proveCollect(browserSeed, AUDIENCE, req)) }))).status,
    200,
  );
  // Not read first: sweep must see the orphan on its own, not because a read dropped it.
  assert.equal(handler.sweep(), 1, "sweep after collection: the orphaned offer");
  assert.equal((await handler.handle(request("GET", `/offers/${code}`))).status, 404, "the collected login's offer");

  // Never taken and past its TTL: swept as well, counted once.
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(codeFor(0xa6), scope, 3600)))).status, 201);
  assert.equal(handler.sweep(), 0, "swept a live offer");
  now.seconds += DEFAULT_TTL_SECONDS + 1;
  assert.equal(handler.sweep(), 1, "sweep past the TTL");
});

// Everything that would make an offer impossible to begin on is refused at the offer route,
// where the prover hears it — not at the page's begin, where only the page would.
test("offer refusals at the door", async () => {
  const { handler } = makeHandler();
  const refused = async (what: string, response: Response): Promise<void> => {
    assert.equal(response.status, 400, `${what}: ${await response.clone().text()}`);
    assert.equal((await bodyOf(response))["error"], "invalid_request", what);
  };
  await refused("an unparseable body", await handler.handle(request("POST", "/offers", "{")));
  await refused(
    "an unknown member",
    await handler.handle(request("POST", "/offers", `{"code":"${codeFor(0xb1)}","scope":["read:projects"],"valid_for":3600,"audience":"https://evil.example"}`)),
  );
  await refused("a validity of zero", await handler.handle(request("POST", "/offers", offerBody(codeFor(0xb2), ["read:projects"], 0))));
  // ESC [ 2 J is "clear the screen" — the whole reason the door check exists.
  await refused("a scope entry that could lie on screen", await handler.handle(request("POST", "/offers", offerBody(codeFor(0xb3), ["read:\u001b[2Jx"], 3600))));
  await refused("an empty scope entry", await handler.handle(request("POST", "/offers", offerBody(codeFor(0xb4), [""], 3600))));
  // A scope that cannot BIND (an entry over the binding's u16 field) is refused now, not at the
  // page's begin, where an offer nobody could ever begin on would sit until it expired.
  await refused(
    "a scope that cannot bind",
    await handler.handle(request("POST", "/offers", offerBody(codeFor(0xb5), ["a".repeat(LOGIN_MAX_FIELD_SIZE + 1)], 3600))),
  );
  // None of the refused codes exists afterwards.
  for (const b of [0xb1, 0xb2, 0xb3, 0xb4, 0xb5]) {
    assert.equal((await handler.handle(request("GET", `/offers/${codeFor(b)}`))).status, 404, `a refused offer ${b.toString(16)} exists`);
  }
  // Methods: the offer route is POST, the read route is GET, and nothing else.
  assert.equal((await handler.handle(request("GET", "/offers"))).status, 405);
  assert.equal((await handler.handle(request("POST", `/offers/${codeFor(0xb6)}`))).status, 405);

  // The page's fragment is where the code goes, so a configured page with one is refused where
  // the operator can read it.
  assert.throws(() => new Handler({ audience: AUDIENCE, page: `${PAGE}#already` }), /fragment/);
  // And a handler WITHOUT a page emits no page key — the fixture calls it optional, and optional
  // means absent when unconfigured, never null or empty.
  const got = await bodyOf(await handler.handle(request("POST", "/offers", offerBody(codeFor(0xb7), ["read:projects"], 3600))));
  assert.equal("page" in got, false, `a handler with no page configured emitted page = ${String(got["page"])}`);
});

// THE OFFER ROUTE IS NOT PACED (ADR 0007 §C.7, amendment #39). §4's collect is polled by one
// party with a proof; this route is read by the page AND polled by the prover, and one
// reference time would let the prover's period lock the page out on every retry. There is
// also nothing here to protect — no proof to verify, no answer to hand over; a stranger with
// the code already has everything the route returns. The prover paces itself by the
// advertised interval. This test is the regression guard for that ruling: ten reads at one
// instant all answer 200, and the offer stays open.
test("the offer route is not paced", async () => {
  const { handler } = makeHandler();
  const code = codeFor(0xa7);
  assert.equal((await handler.handle(request("POST", "/offers", offerBody(code, ["read:projects"], 3600)))).status, 201);
  for (let i = 0; i < 10; i++) {
    const polled = await handler.handle(request("GET", `/offers/${code}`));
    assert.equal(polled.status, 200, `poll ${i} — the offer route must not be paced: ${await polled.clone().text()}`);
    assert.equal((await bodyOf(polled))["request"], null, `poll ${i}: the offer was taken by nobody`);
  }
});

// THE CODE PREDICATE, one function behind three routes (offer 400, begin's `offer` and the
// poll 404). Tested on the function so the shape rule is visible: through the routes a
// malformed code and an unknown one answer alike by design.
test("a code is lowercase hex of even length and at least sixteen bytes", () => {
  const good = "ab".repeat(16);
  assert.doesNotThrow(() => checkCode(good));
  assert.doesNotThrow(() => checkCode("ab".repeat(24)), "longer is fine");
  assert.throws(() => checkCode(good.slice(0, 30)), /at least/, "too short");
  assert.throws(() => checkCode(good.slice(0, 31)), /even length/, "odd length");
  assert.throws(() => checkCode(good.toUpperCase()), /lowercase/, "uppercase");
  assert.throws(() => checkCode(`zz${good.slice(2)}`), /lowercase/, "not hex");
  assert.throws(() => checkCode(""), /at least/, "empty");
});
