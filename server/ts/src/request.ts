// The server's half of request authentication (ADR 0010 §5–§6; docs/request.md §7 steps 8–9,
// version 1, fixed by ADR 0010's status note of 4 October 2026).
//
// The sdk's verifyRequest checks a proof: one spelling, the coverage, the audience echo, the
// digest, freshness and the signature. It does not remember. This module adds what only a
// server can: the HTTP extraction, the clock, and the REPLAY STORE — the one operation that makes
// a proof usable at most once:
//
//   insertIfAbsent({key: (profile, audience, principal, nonce), from, until}) → inserted | alreadyPresent | unavailable
//
// A request reaches the application only as an Authenticated, and only after a proof verified
// AND its identifier was inserted. `alreadyPresent` is a replay; `unavailable` FAILS CLOSED — a
// store that cannot answer, or throws, is never permission to skip the check.
//
// Two ways in, because a fetch-style Request has already lost the request line:
//
// - `authenticateRaw` takes the request as received. `readNodeRequest` builds one from
//   node:http's IncomingMessage — its raw `url` and `rawHeaders` — so a Node server verifies
//   exactly what arrived, as the Go and Rust lanes do.
// - `authenticate` (and `guard`) take a fetch Request, and verify against its URL's pathname and
//   search. The WHATWG URL parser has normalised those (dot segments resolved, `\` read as `/`,
//   some characters percent-encoded), and a Headers object has joined repeated fields with ", ".
//   That normalised request is the only one a fetch application ever sees and routes on, so it is
//   the one verified: what authentication checked and what authorization evaluates stay the same
//   request. A proof signed over any other spelling is refused.
//
// Like the login handler, nothing here opens a socket, starts a timer or depends on a framework.
import { REQUEST_TAG, verifyRequest, type RequestPolicy, type VerifiedRequest } from "@bitspark/archon-sdk";

/** The largest body a verifier reads to recompute the digest. A larger one is refused, never
 *  truncated: a digest over part of a body verifies nothing. */
export const REQUEST_MAX_BODY_BYTES = 1 << 20;

export type ReplayOutcome = "inserted" | "alreadyPresent" | "unavailable";

/** What a replay store remembers. Never the signature bytes: a signature is one spelling of a
 *  proof, the identifier is the proof's. */
export interface ReplayKey {
  /** REQUEST_TAG. */
  profile: string;
  audience: string;
  /** The canonical key text. */
  principal: string;
  /** Hex. */
  nonce: string;
}

/** One insertion: the key, and the window in which any verifier could accept the proof — `from`
 *  is created − δ, `until` is expires + δ, both in seconds since the epoch. A store retains the
 *  key at least until `until`; `from` is what lets a store that lost its memory refuse proofs it
 *  might have seen. */
export interface ReplayEntry {
  key: ReplayKey;
  from: number;
  until: number;
}

/**
 * Makes a proof usable at most once. Requirements (ADR 0010 §5): one winner across every
 * verifier in the acceptance scope — concurrent inserts of one key return "inserted" at most
 * once; a key retained at least until its `until`, when no verifier can still accept the proof;
 * and a store that cannot guarantee both answers "unavailable" rather than "inserted".
 */
export interface ReplayStore {
  insertIfAbsent(entry: ReplayEntry): ReplayOutcome | Promise<ReplayOutcome>;
}

/**
 * The reference ReplayStore: one process, in memory. It is correct for exactly one verifier
 * process, and its RESTART POLICY is what makes it correct across a restart at all (ADR 0010 §5:
 * losing accepted identifiers reopens old proofs).
 *
 * A proof is acceptable from `entry.from` (created − δ). A process started at `start` cannot know
 * what an earlier process accepted, so it admits only proofs whose window opened at or after
 * `start`, and answers "unavailable" for anything older — waiting out, rather than guessing about,
 * the proofs a previous incarnation could have seen. A deployment with more than one verifier, or
 * that cannot afford the wait, supplies a shared store with the same contract.
 */
export class MemoryReplayStore implements ReplayStore {
  readonly #seen = new Map<string, number>();

  /** `start`: when this incarnation began, in seconds since the epoch. */
  constructor(readonly start: number) {}

  insertIfAbsent(entry: ReplayEntry): ReplayOutcome {
    if (entry.from < this.start) return "unavailable";
    const k = JSON.stringify([entry.key.profile, entry.key.audience, entry.key.principal, entry.key.nonce]);
    if (this.#seen.has(k)) return "alreadyPresent";
    this.#seen.set(k, entry.until);
    return "inserted";
  }

  /** Forgets every identifier whose `until` is not after `now`, and returns how many. Optional
   *  and caller-driven: nothing here starts a timer, and retaining a key longer is always safe. */
  sweep(now: number): number {
    let n = 0;
    for (const [k, until] of this.#seen) {
      if (until <= now) {
        this.#seen.delete(k);
        n++;
      }
    }
    return n;
  }
}

/** A request that verified and was admitted by the replay store: the principal, and the request
 *  descriptor authentication verified. Authorization evaluates this, not a re-parse (ADR 0010 §6). */
export type Authenticated = VerifiedRequest;

/** Why a request was not authenticated, with the HTTP status to answer: 400 for a request the
 *  profile does not accept as transported, 401 for one that does not authenticate, 413 for an
 *  oversized body, 503 when the replay store is unavailable. */
export class RequestRefusal extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** A request as received: the method, the raw request-target, every header field in order, the
 *  body after transfer framing, and the trailer fields (any is refused in v1). */
export interface RawRequest {
  method: string;
  requestTarget: string;
  headers: ReadonlyArray<readonly [string, string]>;
  body: Uint8Array;
  trailers?: ReadonlyArray<readonly [string, string]>;
}

/** The shape of node:http's IncomingMessage that `readNodeRequest` reads — structural, so this
 *  package depends on no server. */
export interface NodeRequestLike extends AsyncIterable<Uint8Array | string> {
  method?: string | undefined;
  url?: string | undefined;
  rawHeaders: string[];
  rawTrailers: string[];
}

function pairs(flat: readonly string[]): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (let i = 0; i + 1 < flat.length; i += 2) out.push([flat[i]!, flat[i + 1]!]);
  return out;
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

function tooLarge(): RequestRefusal {
  return new RequestRefusal(413, "request: the body is over the verifier's limit");
}

/** Read a node:http request as received: its raw request-target, its raw header lines, its body
 *  (refused, not truncated, past REQUEST_MAX_BODY_BYTES) and its trailers.
 *
 *  Past the limit it keeps no more bytes but reads on to the end, as node:http itself drains an
 *  unread body: abandoning the stream would destroy the socket, and the client would get a reset
 *  instead of the 413. The server's request timeout bounds how long that can take. */
export async function readNodeRequest(req: NodeRequestLike): Promise<RawRequest> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of req) {
    const bytes = typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk;
    total += bytes.length;
    if (total > REQUEST_MAX_BODY_BYTES) {
      chunks.length = 0;
      continue;
    }
    chunks.push(bytes);
  }
  if (total > REQUEST_MAX_BODY_BYTES) throw tooLarge();
  return {
    method: req.method ?? "",
    requestTarget: req.url ?? "",
    headers: pairs(req.rawHeaders),
    body: concat(chunks, total),
    trailers: pairs(req.rawTrailers),
  };
}

async function readBounded(body: ReadableStream<Uint8Array> | null): Promise<Uint8Array<ArrayBuffer>> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > REQUEST_MAX_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }
  return concat(chunks, total);
}

export interface VerifierConfig {
  policy: RequestPolicy;
  store: ReplayStore;
  /** Seconds since the epoch; defaults to the system clock. */
  clock?: () => number;
}

/** Authenticates requests under one policy against one replay store. */
export class RequestVerifier {
  readonly #policy: RequestPolicy;
  readonly #store: ReplayStore;
  readonly #clock: () => number;

  constructor(config: VerifierConfig) {
    this.#policy = config.policy;
    this.#store = config.store;
    this.#clock = config.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Authenticate a request as received. Throws a RequestRefusal. */
  async authenticateRaw(raw: RawRequest): Promise<Authenticated> {
    if (raw.body.length > REQUEST_MAX_BODY_BYTES) throw tooLarge();
    // v1 accepts no content coding and no trailers (ADR 0010 §4): the digest is over the content
    // as received, and a coded body would make "as received" ambiguous.
    if (raw.headers.some(([n]) => n.toLowerCase() === "content-encoding") || (raw.trailers?.length ?? 0) > 0) {
      throw new RequestRefusal(400, "request: content codings and trailers are not accepted in v1");
    }
    let verified: VerifiedRequest;
    try {
      verified = verifyRequest(this.#policy, this.#clock(), {
        method: raw.method,
        requestTarget: raw.requestTarget,
        headers: raw.headers,
        body: raw.body,
      });
    } catch (e) {
      throw new RequestRefusal(401, e instanceof Error ? e.message : String(e));
    }
    // Only now, after the proof and its freshness verified (ADR 0010 §5: verify before
    // inserting), is the identifier remembered — until no verifier can still accept it.
    let outcome: ReplayOutcome;
    try {
      outcome = await this.#store.insertIfAbsent({
        key: {
          profile: REQUEST_TAG,
          audience: this.#policy.audience,
          principal: verified.keyText,
          nonce: Array.from(verified.nonce, (b) => b.toString(16).padStart(2, "0")).join(""),
        },
        from: verified.created - this.#policy.skew,
        until: verified.expires + this.#policy.skew,
      });
    } catch {
      outcome = "unavailable";
    }
    if (outcome === "inserted") return verified;
    if (outcome === "alreadyPresent") throw new RequestRefusal(401, "request: replayed");
    throw new RequestRefusal(503, "request: the replay store is unavailable");
  }

  /** Authenticate a fetch Request — the normalised request a fetch application routes on — and
   *  return the body it read alongside. Throws a RequestRefusal. */
  async authenticate(request: Request): Promise<{ auth: Authenticated; body: Uint8Array<ArrayBuffer> }> {
    const body = await readBounded(request.body);
    const url = new URL(request.url);
    const auth = await this.authenticateRaw({
      method: request.method,
      requestTarget: url.pathname + url.search,
      headers: [...request.headers],
      body,
    });
    return { auth, body };
  }

  /** The fetch-style middleware: authenticate every request before `next` sees it. A refused
   *  request never reaches `next`; it is answered with the refusal's status and a one-line reason.
   *  `next` gets a fresh Request carrying the body that was verified. */
  guard(next: (request: Request, auth: Authenticated) => Response | Promise<Response>): (request: Request) => Promise<Response> {
    return async (request) => {
      let verified: { auth: Authenticated; body: Uint8Array<ArrayBuffer> };
      try {
        verified = await this.authenticate(request);
      } catch (e) {
        const status = e instanceof RequestRefusal ? e.status : 401;
        return new Response(`${e instanceof Error ? e.message : String(e)}\n`, {
          status,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
      const bodiless = request.method === "GET" || request.method === "HEAD";
      const forward = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body: bodiless ? null : verified.body,
        signal: request.signal,
      });
      return next(forward, verified.auth);
    };
  }
}
