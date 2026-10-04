// ADR 0010 §8's failure tests for the TypeScript lane, deliberately the same cases as the Go
// lane's (server/go/request/request_test.go), through node:http itself: a real server, requests
// written on a raw TCP socket byte for byte (the request line exactly as given, which no client
// library would guarantee), and an application that records whether it ran. Every refusal is
// checked twice: the status, and that the application never saw the request.
//
// Each case runs twice, once per way in: "raw" (readNodeRequest + authenticateRaw, the request as
// received) and "fetch" (a node-to-fetch bridge, as frameworks build one, in front of `guard`).

import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { randomBytes } from "node:crypto";

import { getPublicKey, sign, signInDomain } from "@bitspark/archon";
import { prepareRequest, REQUEST_DOMAIN, signRequest, type RequestToSign } from "@bitspark/archon-sdk";

import {
  MemoryReplayStore,
  readNodeRequest,
  REQUEST_MAX_BODY_BYTES,
  RequestRefusal,
  RequestVerifier,
  type AuthenticatedRequest,
  type ReplayStore,
} from "../src/request.js";

const AUDIENCE = "https://dawn.example/api";
const SEED = new Uint8Array(32).fill(0x44);
const OTHER_SEED = new Uint8Array(32).fill(0x55);
const T0 = 1_789_034_640;
const BODY = new TextEncoder().encode('{"name":"thing"}');

type Mode = "raw" | "fetch";
const MODES: readonly Mode[] = ["raw", "fetch"];

interface Seen {
  auth: AuthenticatedRequest;
  body: Uint8Array;
  target: string;
}

interface Harness {
  port: number;
  clock: { at: number };
  hits: () => number;
  last: () => Seen | undefined;
}

const servers: Server[] = [];
test.after(() => {
  for (const s of servers) {
    s.closeAllConnections();
    s.close();
  }
});

async function harness(mode: Mode, store: ReplayStore): Promise<Harness> {
  const clock = { at: T0 + 5 };
  const verifier = new RequestVerifier({
    policy: { audience: AUDIENCE, declared: ["idempotency-key"], maxLifetime: 300, skew: 30 },
    store,
    clock: () => clock.at,
  });
  let hits = 0;
  let last: Seen | undefined;
  const app = (seen: Seen): void => {
    hits++;
    last = seen;
  };

  const raw = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const request = await readNodeRequest(req);
      const auth = await verifier.authenticateRaw(request);
      app({ auth, body: request.body, target: request.requestTarget });
      res.writeHead(204).end();
    } catch (e) {
      res.writeHead(e instanceof RequestRefusal ? e.status : 500).end(String(e));
    }
  };

  const guarded = verifier.guard(async (request, auth) => {
    const url = new URL(request.url);
    app({ auth, body: new Uint8Array(await request.arrayBuffer()), target: url.pathname + url.search });
    return new Response(null, { status: 204 });
  });
  const fetch = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const headers = new Headers();
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) headers.append(req.rawHeaders[i]!, req.rawHeaders[i + 1]!);
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const bodiless = req.method === "GET" || req.method === "HEAD";
    const request = new Request(new URL(req.url ?? "/", "http://localhost"), {
      method: req.method ?? "GET",
      headers,
      body: bodiless ? null : new Uint8Array(Buffer.concat(chunks)),
    });
    const response = await guarded(request);
    res.writeHead(response.status).end(Buffer.from(await response.arrayBuffer()));
  };

  const server = createServer((req, res) => void (mode === "raw" ? raw : fetch)(req, res));
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, clock, hits: () => hits, last: () => last };
}

interface Signed {
  method: string;
  target: string;
  body: Uint8Array;
  headers: Array<[string, string]>;
  /** Send the body chunked, with these trailer fields. */
  trailers?: Array<[string, string]>;
}

function signed(method: string, target: string, body: Uint8Array, edit?: (input: RequestToSign) => void): Signed {
  const input: RequestToSign = {
    method,
    audience: AUDIENCE,
    requestTarget: target,
    body,
    contentType: "application/json",
    declared: [["idempotency-key", "k-1"]],
    created: T0,
    expires: T0 + 60,
    nonce: randomBytes(16),
  };
  edit?.(input);
  const { headers: h } = signRequest(SEED, input);
  const headers: Array<[string, string]> = [
    ["Archon-Audience", h["archon-audience"]],
    ["Content-Digest", h["content-digest"]],
    ["Signature-Input", h["signature-input"]],
    ["Signature", h.signature],
  ];
  if (input.contentType !== undefined) headers.push(["Content-Type", input.contentType]);
  for (const [n, v] of input.declared) headers.push([n, v]);
  return { method, target, body, headers };
}

function without(headers: Array<[string, string]>, name: string): Array<[string, string]> {
  return headers.filter(([n]) => n.toLowerCase() !== name.toLowerCase());
}

function replace(headers: Array<[string, string]>, name: string, value: string): Array<[string, string]> {
  return [...without(headers, name), [name, value]];
}

/** Write the request on a raw TCP connection and return the response status. */
function send(h: Harness, s: Signed): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = connect(h.port, "127.0.0.1");
    const received: Buffer[] = [];
    const status = (): number | undefined => {
      const m = /^HTTP\/1\.1 (\d{3}) /.exec(Buffer.concat(received).toString("latin1"));
      return m === null ? undefined : Number(m[1]);
    };
    socket.on("data", (chunk: Buffer) => received.push(chunk));
    socket.on("close", () => {
      const got = status();
      if (got === undefined) reject(new Error(`no response: ${Buffer.concat(received).toString("latin1")}`));
      else resolve(got);
    });
    socket.on("error", () => {});
    let head = `${s.method} ${s.target} HTTP/1.1\r\nHost: dawn.example\r\nConnection: close\r\n`;
    for (const [n, v] of s.headers) head += `${n}: ${v}\r\n`;
    if (s.trailers === undefined) {
      head += `Content-Length: ${s.body.length}\r\n\r\n`;
      socket.end(Buffer.concat([Buffer.from(head, "latin1"), s.body]));
      return;
    }
    head += `Transfer-Encoding: chunked\r\nTrailer: ${s.trailers.map(([n]) => n).join(", ")}\r\n\r\n`;
    let tail = "0\r\n";
    for (const [n, v] of s.trailers) tail += `${n}: ${v}\r\n`;
    tail += "\r\n";
    socket.end(
      Buffer.concat([
        Buffer.from(head + `${s.body.length.toString(16)}\r\n`, "latin1"),
        s.body,
        Buffer.from("\r\n" + tail, "latin1"),
      ]),
    );
  });
}

const fresh = (): MemoryReplayStore => new MemoryReplayStore(T0 - 3600);

for (const mode of MODES) {
  test(`${mode}: an authenticated request reaches the application with what was verified`, async () => {
    const h = await harness(mode, fresh());
    assert.equal(await send(h, signed("POST", "/api/v1/things?x=1", BODY)), 204);
    assert.equal(h.hits(), 1);
    const seen = h.last()!;
    assert.deepEqual(seen.auth.principal, getPublicKey(SEED));
    assert.equal(seen.auth.targetUri, "https://dawn.example/api/v1/things?x=1");
    assert.equal(seen.target, "/api/v1/things?x=1");
    assert.deepEqual(seen.body, BODY);
  });

  const cases: Array<{ name: string; make: () => Signed; want: number }> = [
    {
      name: "wrong-key signer: keyid names one key, another signed",
      make: () => {
        const s = signed("POST", "/api/v1/things", BODY);
        const input: RequestToSign = {
          method: "POST", audience: AUDIENCE, requestTarget: "/api/v1/things", body: BODY, contentType: "application/json",
          declared: [["idempotency-key", "k-1"]], created: T0, expires: T0 + 60, nonce: randomBytes(16),
        };
        const p = prepareRequest(getPublicKey(SEED), input);
        const wrong = signInDomain(OTHER_SEED, REQUEST_DOMAIN, p.signing.message);
        s.headers = replace(replace(s.headers, "Signature-Input", p.headers["signature-input"]), "Signature",
          `archon=:${Buffer.from(wrong).toString("base64")}:`);
        return s;
      },
      want: 401,
    },
    {
      name: "dropped-context signer: a raw signature over the base",
      make: () => {
        const s = signed("POST", "/api/v1/things", BODY);
        const input: RequestToSign = {
          method: "POST", audience: AUDIENCE, requestTarget: "/api/v1/things", body: BODY, contentType: "application/json",
          declared: [["idempotency-key", "k-1"]], created: T0, expires: T0 + 60, nonce: randomBytes(16),
        };
        const p = prepareRequest(getPublicKey(SEED), input);
        const raw = sign(p.signing.message, SEED);
        s.headers = replace(replace(s.headers, "Signature-Input", p.headers["signature-input"]), "Signature",
          `archon=:${Buffer.from(raw).toString("base64")}:`);
        return s;
      },
      want: 401,
    },
    {
      name: "path ambiguity: signed with an escape, sent decoded",
      make: () => ({ ...signed("POST", "/api/a%2Fb", BODY), target: "/api/a/b" }),
      want: 401,
    },
    {
      name: "query ambiguity: parameters reordered",
      make: () => ({ ...signed("POST", "/api/v1/things?a=1&b=2", BODY), target: "/api/v1/things?b=2&a=1" }),
      want: 401,
    },
    {
      name: "modified body",
      make: () => ({ ...signed("POST", "/api/v1/things", BODY), body: new TextEncoder().encode('{"name":"other"}') }),
      want: 401,
    },
    {
      name: "emptied body",
      make: () => ({ ...signed("POST", "/api/v1/things", BODY), body: new Uint8Array(0) }),
      want: 401,
    },
    {
      name: "missing covered header",
      make: () => {
        const s = signed("POST", "/api/v1/things", BODY);
        return { ...s, headers: without(s.headers, "Idempotency-Key") };
      },
      want: 401,
    },
    {
      // A fetch Headers object joins the two lines into "k-1, k-1": a value nobody signed.
      name: "duplicated covered header",
      make: () => {
        const s = signed("POST", "/api/v1/things", BODY);
        return { ...s, headers: [...s.headers, ["Idempotency-Key", "k-1"]] };
      },
      want: 401,
    },
    {
      name: "a content coding",
      make: () => {
        const s = signed("POST", "/api/v1/things", BODY);
        return { ...s, headers: [...s.headers, ["Content-Encoding", "identity"]] };
      },
      want: 400,
    },
    {
      name: "a target the URL parser rewrites, signed as sent",
      make: () => ({ ...signed("POST", "/api/./v1/things", BODY), target: "/api/./v1/things" }),
      // raw: verified as received and admitted — the signer signed this exact spelling. fetch: the
      // URL parser resolved it to /api/v1/things, which is not what was signed.
      want: mode === "raw" ? 204 : 401,
    },
  ];
  for (const c of cases) {
    test(`${mode}: ${c.name}`, async () => {
      const h = await harness(mode, fresh());
      assert.equal(await send(h, c.make()), c.want);
      assert.equal(h.hits(), c.want === 204 ? 1 : 0, "the application ran");
    });
  }

  test(`${mode}: expiry bounds`, async () => {
    // created T0, expires T0+60, skew 30: acceptable on [T0−30, T0+90).
    for (const [at, want] of [
      [T0 - 30, 204],
      [T0 - 31, 401],
      [T0 + 89, 204],
      [T0 + 90, 401],
    ] as const) {
      const h = await harness(mode, fresh());
      h.clock.at = at;
      assert.equal(await send(h, signed("POST", "/api/v1/things", BODY)), want, `at T0${at - T0 >= 0 ? "+" : ""}${at - T0}`);
    }
  });

  test(`${mode}: concurrent copies of one proof admit one`, async () => {
    const h = await harness(mode, fresh());
    const s = signed("POST", "/api/v1/things", BODY);
    const statuses = await Promise.all(Array.from({ length: 24 }, () => send(h, s)));
    assert.equal(statuses.filter((st) => st === 204).length, 1);
    assert.ok(statuses.every((st) => st === 204 || st === 401), `statuses ${statuses.join(",")}`);
    assert.equal(h.hits(), 1);
  });

  test(`${mode}: an unavailable replay store fails closed`, async () => {
    for (const store of [
      { insertIfAbsent: () => "unavailable" as const },
      {
        insertIfAbsent: async (): Promise<"inserted"> => {
          throw new Error("the store is down");
        },
      },
    ]) {
      const h = await harness(mode, store);
      assert.equal(await send(h, signed("POST", "/api/v1/things", BODY)), 503);
      assert.equal(h.hits(), 0, "the application ran while the replay store was down");
    }
  });

  test(`${mode}: failover to another verifier sharing the store still admits once`, async () => {
    const shared = fresh();
    const first = await harness(mode, shared);
    const second = await harness(mode, shared);
    const s = signed("POST", "/api/v1/things", BODY);
    assert.equal(await send(first, s), 204);
    assert.equal(await send(second, s), 401, "the second verifier admitted the same proof");
  });

  test(`${mode}: a restarted process refuses proofs it cannot know about`, async () => {
    // The process restarts at T0+10: a proof created at T0 (open from T0−30) may have been
    // accepted before the restart, so the new incarnation refuses it; a proof opened after the
    // restart is admitted.
    const h = await harness(mode, new MemoryReplayStore(T0 + 10));
    h.clock.at = T0 + 20;
    assert.equal(await send(h, signed("POST", "/api/v1/things", BODY)), 503);
    const later = signed("POST", "/api/v1/things", BODY, (input) => {
      input.created = T0 + 40;
      input.expires = T0 + 100;
    });
    h.clock.at = T0 + 45;
    assert.equal(await send(h, later), 204);
  });

  test(`${mode}: an oversized body is refused, not truncated`, async () => {
    const h = await harness(mode, fresh());
    const big = new Uint8Array(REQUEST_MAX_BODY_BYTES + 1).fill(0x61);
    assert.equal(await send(h, signed("POST", "/api/v1/things", big)), 413);
    assert.equal(h.hits(), 0);
  });
}

test("raw: a trailer field is refused", async () => {
  const h = await harness("raw", fresh());
  const s = { ...signed("POST", "/api/v1/things", BODY), trailers: [["Idempotency-Key", "k-2"]] as Array<[string, string]> };
  assert.equal(await send(h, s), 400);
  assert.equal(h.hits(), 0);
});

test("fetch: the verified target is the normalised one the application routes on", async () => {
  // Signed over /api/v1/things and sent as a dot-segment spelling of it: the fetch application
  // only ever sees /api/v1/things, which is exactly what was signed and verified.
  const h = await harness("fetch", fresh());
  const s = { ...signed("POST", "/api/v1/things", BODY), target: "/api/x/../v1/things" };
  assert.equal(await send(h, s), 204);
  assert.equal(h.last()!.target, "/api/v1/things");
  assert.equal(h.last()!.auth.targetUri, "https://dawn.example/api/v1/things");
});

// The body bound, below HTTP: each reader enforces it itself, and authenticateRaw again for a
// caller that builds a RawRequest by hand — so no one of them can be pinned through a server
// alone, where the next would still answer 413.
const verifier = (): RequestVerifier =>
  new RequestVerifier({
    policy: { audience: AUDIENCE, declared: [], maxLifetime: 300, skew: 30 },
    store: fresh(),
    clock: () => T0,
  });
const status = (e: unknown): number | undefined => (e instanceof RequestRefusal ? e.status : undefined);

test("authenticateRaw refuses an oversized body handed to it directly", async () => {
  const big = new Uint8Array(REQUEST_MAX_BODY_BYTES + 1);
  await assert.rejects(verifier().authenticateRaw({ method: "POST", requestTarget: "/api", headers: [], body: big }), (e) => status(e) === 413);
});

test("readNodeRequest refuses past the limit, having read to the end", async () => {
  let drained = false;
  const req = {
    method: "POST",
    url: "/api",
    rawHeaders: [],
    rawTrailers: [],
    async *[Symbol.asyncIterator]() {
      yield new Uint8Array(REQUEST_MAX_BODY_BYTES);
      yield new Uint8Array(1);
      yield new Uint8Array(4096);
      drained = true;
    },
  };
  await assert.rejects(readNodeRequest(req), (e) => status(e) === 413);
  assert.ok(drained, "the reader abandoned the stream, which would reset the connection");
});

test("fetch: a long body is refused without being read to its end", async () => {
  let pulls = 0;
  let cancelled = false;
  const chunk = 64 * 1024;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (++pulls > 64) controller.close();
      else controller.enqueue(new Uint8Array(chunk));
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("http://localhost/api", { method: "POST", body: stream, duplex: "half" } as RequestInit);
  await assert.rejects(verifier().authenticate(request), (e) => status(e) === 413);
  assert.ok(pulls <= REQUEST_MAX_BODY_BYTES / chunk + 2, `${pulls} chunks pulled`);
  assert.ok(cancelled, "the body stream was left open");
});

test("MemoryReplayStore: the restart policy, presence, and a caller-driven sweep", () => {
  const store = new MemoryReplayStore(T0);
  const key = { profile: "archon-request/1", audience: AUDIENCE, principal: "k", nonce: "00" };
  assert.equal(store.insertIfAbsent({ key, from: T0 - 1, until: T0 + 90 }), "unavailable");
  assert.equal(store.insertIfAbsent({ key, from: T0, until: T0 + 90 }), "inserted");
  assert.equal(store.insertIfAbsent({ key, from: T0, until: T0 + 90 }), "alreadyPresent");
  assert.equal(store.sweep(T0 + 89), 0);
  assert.equal(store.insertIfAbsent({ key, from: T0, until: T0 + 90 }), "alreadyPresent");
  assert.equal(store.sweep(T0 + 90), 1);
  assert.equal(store.insertIfAbsent({ key, from: T0, until: T0 + 90 }), "inserted");
});
