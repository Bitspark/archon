// ADR 0010 §8's enrollment failure tests for the TypeScript lane — substitution and replay —
// deliberately the same cases as the Go lane's (server/go/enroll/enroll_test.go), through
// node:http itself. archon defines no enrollment route, so the test plays the service: a route
// that takes its session from a cookie, reads {"transaction","proof"} and calls `complete`, in
// front of an integration that keeps records and associations in memory, its check-and-consume
// done in one synchronous step. Every refusal is checked twice: the status, and that no
// association was recorded.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { getPublicKey } from "@bitspark/archon";
import { proveEnroll, type EnrollRequest } from "@bitspark/archon-sdk";

import {
  ENROLL_DEFAULT_TTL_SECONDS,
  Enroller,
  EnrollmentRefusal,
  type EnrollmentChallenge,
  type EnrollmentIntegration,
  type EnrollmentOutcome,
  type EnrollmentRecord,
} from "../src/enroll.js";

const AUDIENCE = "https://dawn.example/api";
const KEY_SEED = new Uint8Array(32).fill(0x61);
const OTHER_SEED = new Uint8Array(32).fill(0x62);
const NEW_KEY = getPublicKey(KEY_SEED);
const T0 = 1_789_034_640;
const INTENT = new TextEncoder().encode("acct-1 add-key restrictions=none");

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

interface Association {
  account: string;
  key: string;
  purpose: string;
}

/** The integration: records, consumed marks and associations. Its `complete` checks and
 *  consumes in one synchronous step, which is what makes it atomic in one JavaScript process. */
class Service implements EnrollmentIntegration {
  readonly records = new Map<string, EnrollmentRecord>();
  readonly consumed = new Set<string>();
  readonly associations: Association[] = [];
  loadDown = false;
  completeDown = false;
  completeThrows = false;
  wrongRecord = false;

  persist(r: EnrollmentRecord): void {
    this.records.set(hex(r.transaction), r);
  }

  async load(transaction: Uint8Array): Promise<EnrollmentRecord | undefined> {
    await Promise.resolve();
    if (this.loadDown) throw new Error("the database is down");
    const r = this.records.get(hex(transaction));
    if (r !== undefined && this.wrongRecord) {
      for (const other of this.records.values()) if (hex(other.transaction) !== hex(transaction)) return other;
    }
    return r;
  }

  async complete(r: EnrollmentRecord): Promise<EnrollmentOutcome> {
    await Promise.resolve();
    if (this.completeThrows) throw new Error("the transaction aborted");
    if (this.completeDown) return "unavailable";
    if (this.consumed.has(hex(r.transaction))) return "notPending";
    this.consumed.add(hex(r.transaction));
    this.associations.push({ account: text(r.account), key: hex(r.newKey), purpose: r.purpose });
    return "completed";
  }
}

interface Harness {
  port: number;
  enroller: Enroller;
  svc: Service;
  clock: { at: number };
}

const servers: Server[] = [];
test.after(() => {
  for (const s of servers) {
    s.closeAllConnections();
    s.close();
  }
});

async function harness(): Promise<Harness> {
  const svc = new Service();
  const clock = { at: T0 };
  let n = 0;
  const enroller = new Enroller({
    audience: AUDIENCE,
    integration: svc,
    clock: () => clock.at,
    entropy: (size) => new Uint8Array(size).fill(++n),
  });
  const server = createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/enroll/complete") {
      res.writeHead(404).end();
      return;
    }
    const session = /(?:^|;\s*)session=([^;]*)/.exec(req.headers.cookie ?? "")?.[1];
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    let body: { transaction?: unknown; proof?: unknown };
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      res.writeHead(400).end();
      return;
    }
    if (typeof body.transaction !== "string" || typeof body.proof !== "string") {
      res.writeHead(400).end();
      return;
    }
    try {
      await enroller.complete(
        Buffer.from(body.transaction, "hex"),
        Buffer.from(body.proof, "hex"),
        new TextEncoder().encode(session ?? ""),
      );
      res.writeHead(204).end();
    } catch (e) {
      res.writeHead(e instanceof EnrollmentRefusal ? e.status : 500).end(String(e));
    }
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, enroller, svc, clock };
}

/** The service's begin route, after it validated the session: prepare, persist, challenge. */
async function begin(h: Harness, session: string, key = NEW_KEY): Promise<EnrollmentChallenge> {
  const { record, challenge } = await h.enroller.prepare({
    authorization: new TextEncoder().encode(session),
    account: new TextEncoder().encode("acct-1"),
    purpose: "add-key",
    newKey: key,
    intent: INTENT,
  });
  h.svc.persist(record);
  return challenge;
}

/** The client: the proof by `seed` over the challenge, with `edit` applied to what it signs. */
function prove(seed: Uint8Array, ch: EnrollmentChallenge, edit?: (r: EnrollRequest, a: { audience: string }) => void): Uint8Array {
  const req: EnrollRequest = {
    nonce: ch.nonce,
    transaction: ch.transaction,
    purpose: ch.purpose,
    newKey: getPublicKey(seed),
    intentDigest: ch.intentDigest,
  };
  const a = { audience: ch.audience };
  edit?.(req, a);
  return proveEnroll(seed, a.audience, req);
}

function complete(h: Harness, session: string, transaction: Uint8Array, proof: Uint8Array): Promise<number> {
  const body = JSON.stringify({ transaction: hex(transaction), proof: hex(proof) });
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port: h.port,
        method: "POST",
        path: "/enroll/complete",
        headers: { "content-type": "application/json", ...(session === "" ? {} : { cookie: `session=${session}` }) },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

test("an enrollment completes once, with the record's association", async () => {
  const h = await harness();
  const ch = await begin(h, "s1");
  assert.equal(await complete(h, "s1", ch.transaction, prove(KEY_SEED, ch)), 204);
  assert.deepEqual(h.svc.associations, [{ account: "acct-1", key: hex(NEW_KEY), purpose: "add-key" }]);
  assert.equal(ch.audience, AUDIENCE);
  assert.equal(hex(ch.intentDigest), createHash("sha256").update(INTENT).digest("hex"));
  assert.ok(ch.nonce.length >= 16);
  assert.equal(ch.expires, T0 + ENROLL_DEFAULT_TTL_SECONDS);
});

test("there is no possession-alone mode", () => {
  assert.throws(() => new Enroller({ audience: AUDIENCE } as unknown as ConstructorParameters<typeof Enroller>[0]), /integration is required/);
  assert.throws(() => new Enroller({ audience: "", integration: new Service() }));
});

const substitutions: Array<{ name: string; run: (h: Harness) => Promise<number>; want: number }> = [
  {
    name: "another key proves for the record's key",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "s1", ch.transaction, prove(OTHER_SEED, ch));
    },
    want: 401,
  },
  {
    name: "another transaction's proof",
    run: async (h) => {
      const first = await begin(h, "s1");
      const second = await begin(h, "s1");
      return complete(h, "s1", first.transaction, prove(KEY_SEED, second));
    },
    want: 401,
  },
  {
    name: "a proof over another purpose",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "s1", ch.transaction, prove(KEY_SEED, ch, (r) => void (r.purpose = "recover")));
    },
    want: 401,
  },
  {
    name: "a proof for another audience",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "s1", ch.transaction, prove(KEY_SEED, ch, (_, a) => void (a.audience = "https://evil.example/api")));
    },
    want: 401,
  },
  {
    name: "a proof over another intent",
    run: async (h) => {
      const ch = await begin(h, "s1");
      const other = createHash("sha256").update("acct-2 add-key").digest();
      return complete(h, "s1", ch.transaction, prove(KEY_SEED, ch, (r) => void (r.intentDigest = new Uint8Array(other))));
    },
    want: 401,
  },
  {
    name: "a proof over another nonce",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "s1", ch.transaction, prove(KEY_SEED, ch, (r) => void (r.nonce = new Uint8Array(16).fill(0xee))));
    },
    want: 401,
  },
  {
    name: "another session completes",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "s2", ch.transaction, prove(KEY_SEED, ch));
    },
    want: 403,
  },
  {
    name: "no session completes",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "", ch.transaction, prove(KEY_SEED, ch));
    },
    want: 403,
  },
  {
    name: "an unknown transaction",
    run: async (h) => {
      const ch = await begin(h, "s1");
      return complete(h, "s1", new Uint8Array(16).fill(0x77), prove(KEY_SEED, ch));
    },
    want: 404,
  },
];
for (const c of substitutions) {
  test(`nothing can be substituted: ${c.name}`, async () => {
    const h = await harness();
    assert.equal(await c.run(h), c.want);
    assert.equal(h.svc.associations.length, 0, "an association was recorded");
  });
}

test("a record with no authorization completes for no one", async () => {
  // prepare refuses to build one; a record the integration holds without one is still never
  // completed, least of all by a request that carries no session either.
  const h = await harness();
  const ch = await begin(h, "s1");
  const r = h.svc.records.get(hex(ch.transaction))!;
  h.svc.persist({ ...r, authorization: new Uint8Array(0) });
  assert.equal(await complete(h, "", ch.transaction, prove(KEY_SEED, ch)), 403);
  assert.equal(h.svc.associations.length, 0);
});

test("a completed enrollment cannot be replayed", async () => {
  const h = await harness();
  const ch = await begin(h, "s1");
  const proof = prove(KEY_SEED, ch);
  assert.equal(await complete(h, "s1", ch.transaction, proof), 204);
  assert.equal(await complete(h, "s1", ch.transaction, proof), 409);
  // The same proof against a fresh transaction for the same key and session: its nonce and
  // transaction are not the ones the proof covers.
  const fresh = await begin(h, "s1");
  assert.equal(await complete(h, "s1", fresh.transaction, proof), 401);
  assert.equal(h.svc.associations.length, 1);
});

test("concurrent completions record one", async () => {
  const h = await harness();
  const ch = await begin(h, "s1");
  const proof = prove(KEY_SEED, ch);
  const statuses = await Promise.all(Array.from({ length: 24 }, () => complete(h, "s1", ch.transaction, proof)));
  assert.equal(statuses.filter((s) => s === 204).length, 1, `statuses ${statuses.join(",")}`);
  assert.ok(statuses.every((s) => s === 204 || s === 409), `statuses ${statuses.join(",")}`);
  assert.equal(h.svc.associations.length, 1);
});

test("an expired enrollment is gone", async () => {
  for (const [at, want] of [
    [T0 + ENROLL_DEFAULT_TTL_SECONDS - 1, 204],
    [T0 + ENROLL_DEFAULT_TTL_SECONDS, 404],
  ] as const) {
    const h = await harness();
    const ch = await begin(h, "s1");
    h.clock.at = at;
    assert.equal(await complete(h, "s1", ch.transaction, prove(KEY_SEED, ch)), want, `at T0+${at - T0}`);
  }
});

test("an integration that cannot answer fails closed", async () => {
  for (const fault of [
    (s: Service) => void (s.loadDown = true),
    (s: Service) => void (s.completeDown = true),
    (s: Service) => void (s.completeThrows = true),
    (s: Service) => void (s.wrongRecord = true),
  ]) {
    const h = await harness();
    const ch = await begin(h, "s1");
    await begin(h, "s1"); // a second record, for wrongRecord to return
    fault(h.svc);
    assert.equal(await complete(h, "s1", ch.transaction, prove(KEY_SEED, ch)), 503);
    assert.equal(h.svc.associations.length, 0);
  }
});

test("prepare refuses what could not complete", async () => {
  const h = await harness();
  const good = {
    authorization: new TextEncoder().encode("s1"),
    account: new TextEncoder().encode("acct-1"),
    purpose: "add-key",
    newKey: NEW_KEY,
    intent: INTENT,
  };
  for (const [name, edit] of [
    ["no authorization", { authorization: new Uint8Array(0) }],
    ["no account", { account: new Uint8Array(0) }],
    ["a short key", { newKey: NEW_KEY.slice(0, 31) }],
    ["no purpose", { purpose: "" }],
    ["a control character", { purpose: "add\nkey" }],
  ] as const) {
    await assert.rejects(h.enroller.prepare({ ...good, ...edit }), Error, name);
  }
  await h.enroller.prepare(good);
});
