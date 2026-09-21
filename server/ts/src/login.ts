// The service side of the archon login protocol (docs/login.md §4 and §4.1): the four routes a
// browser and a CLI need to rendezvous, and the two by which the CLI may start instead (an
// offer, read and taken by the page), so a service adopts proof-of-possession sign-in by
// mounting a handler rather than by building a session system.
//
// FETCH-STYLE, WHICH IS THIS LANE'S WHOLE ADAPTER STORY. `handle` is
// `(Request) => Promise<Response>` over the Web platform's own types, so the same handler
// mounts in Node 18+, Deno, Bun, Cloudflare Workers and any framework that speaks fetch —
// without this package depending on any of them. Express and friends need about ten lines of
// glue, which belongs beside this package rather than inside it (`examples/serve.ts` is the
// node:http version).
//
// Three things this package deliberately is not (ADR 0007 §B):
//
//   - Not a server. It opens no socket and starts no timer.
//   - Not a law. The authority payload is opaque bytes, interpreted only inside the
//     AdmitAuthority the service supplies. archon ships no implementation of one.
//   - Not a store. One in-memory record per pending login, dropped at expiry or on collection.
//
// THE AUDIENCE IS CONFIGURED, NEVER READ FROM THE WIRE. Every binding is recomputed from the
// string the service configured. That is the WebAuthn rule and review Finding 1: a relying
// party's identity comes from its own configuration, not from a value an attacker can put in
// a message. No code path here reads an audience from a request.
//
// The scheme itself — the binding layout, the domain, the proofs — is @bitspark/archon-sdk's
// and is consumed, never reimplemented: a binding written twice is a binding that drifts.

import { decodeKey, encodeKey } from "@bitspark/archon";
import { deriveAudience, loginBinding, LOGIN_ROLE_LOGIN, verifyCollect, verifyLogin, type LoginRequest } from "@bitspark/archon-sdk";

import { checkCode, checkScopeEntry, fromHex, parseBody, rfc3339, stripMount, toHex } from "./json.js";

/** The RFC 8628 / RFC 6749 codes §4 adopts verbatim. Their bearer-token result is not ours,
 *  but their vocabulary is, so a client that already speaks device flow behaves well. */
const ERR_INVALID_REQUEST = "invalid_request";
const ERR_INVALID_GRANT = "invalid_grant";
const ERR_EXPIRED_TOKEN = "expired_token";
const ERR_PENDING = "authorization_pending";
const ERR_SLOW_DOWN = "slow_down";

/** The header carrying the browser's collect proof. Exported because a browser client has to
 *  spell it, and one spelling in one place is how the two halves stay agreed. */
export const COLLECT_HEADER = "archon-collect";

/** Five minutes, from §4. */
export const DEFAULT_TTL_SECONDS = 300;
/** Five seconds, from §4. */
export const DEFAULT_INTERVAL_SECONDS = 5;

/** The floor on both the generated id and the generated nonce. §3.1 requires it of the nonce
 *  and recommends it for the id; this package applies it to both, since an id a stranger can
 *  guess is the address of a pending login. */
const MIN_ENTROPY = 16;

/**
 * Interprets the authority payload — the ONLY place one is interpreted, and archon ships no
 * implementation. THROWING refuses the answer with `403 invalid_grant` and stores nothing.
 * Omitting it means the proof alone suffices, which is right for a service whose law needs
 * nothing beyond "this key holder was here and approved this scope".
 *
 * It may be async, and the handler awaits it. See the note on `answer` for why every check it
 * depends on is repeated afterwards.
 */
export type AdmitAuthority = (
  browser: Uint8Array,
  principal: Uint8Array,
  authority: Uint8Array,
) => void | Promise<void>;

/** Seconds since the Unix epoch. A config field rather than a call to `Date.now()`, which is
 *  the sdk's rule and the reason the suite never sleeps. */
export type Clock = () => number;

/** Fills `n` bytes. A config field for the same reason as `Clock`: a test predicts it,
 *  production draws from the platform's CSPRNG. */
export type Entropy = (n: number) => Uint8Array;

/** What a service supplies. Only the audience is required. */
export interface Config {
  /** The service's public identity, and a fixed point of §2.1 — see the constructor. */
  audience: string;
  /** The path prefix the routes live under, e.g. `/api/login`. Default: none. */
  mount?: string;
  admit?: AdmitAuthority;
  /** The address a person opens to finish a login the CLI started (§4.1 — the offers form).
   *  Optional. When set, an offer's response carries `<page>#<code>`: the code travels in the
   *  FRAGMENT, which a browser never sends to any server, so it reaches the page's script and
   *  no log. A page that already carries a fragment is refused by the constructor. The CLI
   *  prints the address and never opens it (§4.1 rule 1). */
  page?: string;
  /** How long a pending login lives — and how long an open offer lives. */
  ttlSeconds?: number;
  intervalSeconds?: number;
  clock?: Clock;
  entropy?: Entropy;
}

/** What the CLI posted and the browser collects, held verbatim between the two. */
interface Answer {
  principal: string;
  possession: string;
  /** OPAQUE BYTES: the exact source text of the CLI's `authority` member, never a re-encoding
   *  of a parsed value. undefined means the member was absent, which is a different answer
   *  from a member whose value is `null` (§3.4) — that one has the span "null". */
  authority: string | undefined;
}

/** One pending login. Written once at begin; only `answered` and `lastPoll` ever change, and
 *  NEITHER ENTERS A BINDING. */
interface Record_ {
  id: Uint8Array;
  nonce: Uint8Array;
  browser: Uint8Array;
  scope: string[];
  validFor: number;
  expires: number;
  answered: Answer | undefined;
  lastPoll: number | undefined;
}

/** One registered offer (§4.1): what a prover is willing to delegate, to a key it does not
 *  know yet. It carries no key and no proof — what it carries is the code's confidentiality
 *  until it is taken. Written once at registration; only `request` changes, once, when the
 *  first matching request takes it. */
interface Offer {
  /** Lowercase hex — the map key and the URL segment; ≥ 16 bytes of the prover's entropy. */
  code: string;
  scope: string[];
  validFor: number;
  expires: number;
  /** The hex id of the request that took this offer, or undefined while it is open. An offer
   *  dies with its request (§4.1 "State"): once that record is gone — collected or expired —
   *  the offer is gone too, which `#liveOffer` enforces on read like every expiry. */
  request: string | undefined;
}

/** §4.1's "differs in any way", stated once: the same number of entries, each equal to its
 *  counterpart IN ORDER, and the same validity. A set comparison would let a page reorder
 *  what the person typed; a length comparison would let it swap an entry. */
function matchesOffer(offer: Offer, scope: string[], validFor: number): boolean {
  return validFor === offer.validFor && scope.length === offer.scope.length && scope.every((s, i) => s === offer.scope[i]);
}

const JSON_HEADERS = { "content-type": "application/json", "cache-control": "no-store" };

/** The error body of §4: exactly `{"error": "<code>"}` and nothing else. No description, no
 *  echoed id — a client that guessed an id learns only that it is not pending, which is the
 *  same thing it learns for an id that never existed. */
function fail(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: code }), { status, headers: JSON_HEADERS });
}

function ok(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/** `checkCode` as a predicate, for the two routes that answer a malformed code with 404. */
function isCode(code: string): boolean {
  try {
    checkCode(code);
    return true;
  } catch {
    return false;
  }
}

function toRequest(record: Record_): LoginRequest {
  return {
    id: record.id,
    nonce: record.nonce,
    browser: record.browser,
    scope: record.scope,
    validFor: record.validFor,
  };
}

export class Handler {
  readonly audience: string;
  readonly mount: string;
  readonly page: string | undefined;
  readonly ttlSeconds: number;
  readonly intervalSeconds: number;
  readonly #admit: AdmitAuthority | undefined;
  readonly #clock: Clock;
  readonly #entropy: Entropy;
  readonly #records = new Map<string, Record_>();
  readonly #offers = new Map<string, Offer>();

  /**
   * Builds a handler, or throws explaining why the configuration cannot work.
   *
   * THE AUDIENCE MUST BE A FIXED POINT OF THE §2.1 GRAMMAR, and that is checked with the
   * grammar itself rather than with a list of rules restated here. `https://Dawn.example/api`,
   * `…:443` and `wss://…` each DERIVE to something else, so a handler configured with one
   * would bind the spelling in the config file while the CLI bound the derived one, and every
   * proof would fail with nothing on either side saying why. Feeding the audience back through
   * `deriveAudience` asks the only question that matters: is this the string the CLI will
   * produce?
   *
   * The `/login/00` is the shortest invocation URL the grammar admits — a minimum-length id —
   * and exists only to make the audience parseable as one.
   */
  constructor(config: Config) {
    if (config.audience.length === 0) {
      throw new Error("login: an audience is required — the handler binds to it and never reads one from the wire");
    }
    let derived: string;
    try {
      derived = deriveAudience(`${config.audience}/login/00`).audience;
    } catch (cause) {
      throw new Error(
        `login: audience ${JSON.stringify(config.audience)} is not valid: ${String(cause)} (docs/login.md §2.1)`,
      );
    }
    if (derived !== config.audience) {
      throw new Error(
        `login: audience ${JSON.stringify(config.audience)} is not canonical — the CLI will derive ` +
          `${JSON.stringify(derived)} and bind THAT, so every proof would fail. ` +
          `Configure ${JSON.stringify(derived)} (docs/login.md §2.1)`,
      );
    }
    // The code goes in the page's fragment (§4.1), so a page that already has one is a
    // configuration mistake — refused here, where the operator can read it, rather than
    // producing an address with two fragments that no browser parses the way anyone meant.
    if (config.page !== undefined && config.page.includes("#")) {
      throw new Error(
        `login: page ${JSON.stringify(config.page)} carries a fragment — the offer's code goes there (docs/login.md §4.1)`,
      );
    }
    this.audience = config.audience;
    this.mount = (config.mount ?? "").replace(/\/+$/, "");
    this.page = config.page;
    this.ttlSeconds = config.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    this.intervalSeconds = config.intervalSeconds ?? DEFAULT_INTERVAL_SECONDS;
    this.#admit = config.admit;
    this.#clock = config.clock ?? (() => Math.floor(Date.now() / 1000));
    this.#entropy = config.entropy ?? ((n) => crypto.getRandomValues(new Uint8Array(n)));
  }

  /**
   * The four shapes of §4 and the two of §4.1, relative to the mount:
   *
   *   POST   ""               begin       the browser opens a request ("offer" names an offer)
   *   POST   "/offers"        offer       the CLI registers what it will delegate, under its code
   *   GET    "/offers/<code>" read offer  the page reads it once; the CLI polls it until taken
   *   GET    "/<id>"          read        the CLI reads what it is being asked to sign
   *   POST   "/<id>/answer"   answer      the CLI delivers the proof
   *   GET    "/<id>/answer"   collect     the browser takes the answer, once
   *
   * The `offers` segment is matched before the id routes. There is no ambiguity to resolve —
   * an id is hex and `offers` is not — but the order says which family owns the segment.
   */
  async handle(request: Request): Promise<Response> {
    const path = stripMount(new URL(request.url).pathname, this.mount);
    if (path === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    const parts = path.split("/").filter((p) => p.length > 0);
    const method = request.method.toUpperCase();

    if (parts.length === 0) {
      return method === "POST" ? this.#begin(request) : fail(405, ERR_INVALID_REQUEST);
    }
    if (parts[0] === "offers") {
      if (parts.length === 1) return method === "POST" ? this.#offer(request) : fail(405, ERR_INVALID_REQUEST);
      if (parts.length === 2) return method === "GET" ? this.#readOffer(parts[1] as string) : fail(405, ERR_INVALID_REQUEST);
      return fail(404, ERR_EXPIRED_TOKEN);
    }
    const id = parts[0] as string;
    if (parts.length === 1) {
      return method === "GET" ? this.#read(id) : fail(405, ERR_INVALID_REQUEST);
    }
    if (parts.length === 2 && parts[1] === "answer") {
      if (method === "POST") return this.#answer(request, id);
      if (method === "GET") return this.#collect(request, id);
      return fail(405, ERR_INVALID_REQUEST);
    }
    return fail(404, ERR_EXPIRED_TOKEN);
  }

  /** Drops expired records and dead offers and reports how many went. Optional: both also
   *  expire on read, so a handler that is never swept is correct, just less tidy. This package
   *  starts no timer of its own — a long-lived service calls this from its own maintenance
   *  loop. */
  sweep(): number {
    const now = this.#clock();
    let dropped = 0;
    for (const [key, record] of this.#records) {
      if (now >= record.expires) {
        this.#records.delete(key);
        dropped += 1;
      }
    }
    // Offers after records, so an offer whose request just went is seen as orphaned.
    for (const [code, offer] of this.#offers) {
      if (!this.#offerIsLive(offer, now)) {
        this.#offers.delete(code);
        dropped += 1;
      }
    }
    return dropped;
  }

  /** Creates a pending record: the server's id and nonce, the browser's key, the scope and
   *  validity it asked for. The nonce is the SERVER's, never the browser's — a nonce a caller
   *  chooses is a nonce a caller can replay (§3.1).
   *
   *  On an offer, the request must be what the prover offered — scope entry for entry, in
   *  order, and validity equal — and the offer must be open. That is checked FIRST, before the
   *  browser key is decoded and before any entropy is drawn (§4.1: refused before anything is
   *  stored, before any key is involved), and again when the request is stored and the offer
   *  taken — with NO `await` between the check and the take, which is this lane's critical
   *  section (see `#takeOffer`). */
  async #begin(request: Request): Promise<Response> {
    let body: Record<string, unknown>;
    try {
      ({ body } = parseBody(await request.arrayBuffer(), ["browser", "scope", "valid_for", "offer"]));
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }

    // `valid_for`, and ONLY that spelling. A `validFor` alias here would be comfortable for a
    // TypeScript caller and would let them write a client that go and rs refuse -- the exact
    // cross-lane divergence the shared wire fixture exists to prevent. One wire, three lanes.
    const validFor = body["valid_for"];
    const browserText = body["browser"];
    const scopeRaw = body["scope"] ?? [];
    if (typeof browserText !== "string" || !Array.isArray(scopeRaw)) return fail(400, ERR_INVALID_REQUEST);
    if (typeof validFor !== "number" || !Number.isInteger(validFor) || validFor <= 0 || validFor > 0xffffffff) {
      return fail(400, ERR_INVALID_REQUEST);
    }
    const scope: string[] = [];
    for (const entry of scopeRaw as unknown[]) {
      if (typeof entry !== "string") return fail(400, ERR_INVALID_REQUEST);
      try {
        checkScopeEntry(entry);
      } catch {
        return fail(400, ERR_INVALID_REQUEST);
      }
      scope.push(entry);
    }
    // THE OFFER IS CHECKED HERE — before the browser key is decoded, before any entropy is
    // drawn (§4.1: refused before anything is stored, before any key is involved).
    let offerCode: string | undefined;
    if ("offer" in body) {
      const code = body["offer"];
      // A member that is present must be a code STRING: null or any other type is a malformed
      // body (400), the same answer go and rs give — refused, not read as "no offer" (the
      // page-started form leaves the member out) and not mistaken for an unknown code.
      if (typeof code !== "string") return fail(400, ERR_INVALID_REQUEST);
      // A malformed code is an UNKNOWN one: a registered code is always well-formed, so this
      // names nothing, and the answer is the poll route's 404 — not a 400 that would tell a
      // prober which of its guesses were at least the right shape.
      if (!isCode(code)) return fail(404, ERR_EXPIRED_TOKEN);
      const refused = this.#checkOffer(code, scope, validFor);
      if (refused !== undefined) return refused;
      offerCode = code;
    }
    let browser: Uint8Array;
    try {
      browser = decodeKey(browserText);
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }

    const record: Record_ = {
      id: this.#entropy(MIN_ENTROPY),
      nonce: this.#entropy(MIN_ENTROPY),
      browser,
      scope,
      validFor,
      expires: this.#clock() + this.ttlSeconds,
      answered: undefined,
      lastPoll: undefined,
    };
    // A request that cannot produce a binding must not be handed out: the CLI would fetch it,
    // show it, and fail at signing time with nothing to explain.
    try {
      loginBinding(LOGIN_ROLE_LOGIN, this.audience, toRequest(record));
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }

    const idHex = toHex(record.id);
    if (offerCode !== undefined) {
      const refused = this.#takeOffer(offerCode, idHex, record);
      if (refused !== undefined) return refused;
    } else {
      this.#records.set(idHex, record);
    }
    // The same body whether or not an offer was named: the offer is not echoed, so a browser
    // client needs one shape for begin (pinned as begin_on_offer in login-wire.json).
    return ok(201, {
      id: idHex,
      nonce: toHex(record.nonce),
      browser: browserText,
      scope,
      valid_for: validFor,
      expires_in: this.ttlSeconds,
      interval: this.intervalSeconds,
      verification_uri: `${this.audience}/login/${idHex}`,
    });
  }

  /** §4.1's refusals for a request naming an offer, or undefined when it may go on: unknown,
   *  expired or orphaned → 404 (one answer, indistinguishable); taken → 409 (one offer, one
   *  request); differing from the offer in any way → 400. `#begin` asks twice — before
   *  building the request and again when storing it. */
  #checkOffer(code: string, scope: string[], validFor: number): Response | undefined {
    const offer = this.#liveOffer(code);
    if (offer === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    if (offer.request !== undefined) return fail(409, ERR_INVALID_REQUEST);
    if (!matchesOffer(offer, scope, validFor)) return fail(400, ERR_INVALID_REQUEST);
    return undefined;
  }

  /** Stores the request AND marks the offer taken, repeating every check first and with NO
   *  `await` between check and take — in this lane that span is the critical section, and it
   *  is what makes "exactly one of two pages beginning on one code wins" a fact rather than a
   *  likelihood. The offer may have been taken, or died, while the request was being built. */
  #takeOffer(code: string, idHex: string, record: Record_): Response | undefined {
    const refused = this.#checkOffer(code, record.scope, record.validFor);
    if (refused !== undefined) return refused;
    this.#records.set(idHex, record);
    const offer = this.#offers.get(code);
    if (offer !== undefined) offer.request = idHex;
    return undefined;
  }

  /** Registers what a prover is willing to delegate, under a code the PROVER minted. The
   *  server draws no entropy here: the code is the prover's own, which is what lets the prover
   *  know it before anyone else does and print it on its own terminal (§4.1 "The code").
   *
   *  Everything that would make the offer impossible to begin on is refused now, at the door,
   *  rather than at the page's begin — where the refusal would reach the page and not the
   *  person who typed the offer: a malformed code, a validity of zero, a scope entry the CLI
   *  could not display, and a scope that cannot bind at all. */
  async #offer(request: Request): Promise<Response> {
    let body: Record<string, unknown>;
    try {
      ({ body } = parseBody(await request.arrayBuffer(), ["code", "scope", "valid_for"]));
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }
    const code = body["code"];
    const validFor = body["valid_for"];
    const scopeRaw = body["scope"] ?? [];
    if (typeof code !== "string" || !isCode(code) || !Array.isArray(scopeRaw)) return fail(400, ERR_INVALID_REQUEST);
    if (typeof validFor !== "number" || !Number.isInteger(validFor) || validFor <= 0 || validFor > 0xffffffff) {
      return fail(400, ERR_INVALID_REQUEST);
    }
    const scope: string[] = [];
    for (const entry of scopeRaw as unknown[]) {
      if (typeof entry !== "string") return fail(400, ERR_INVALID_REQUEST);
      try {
        checkScopeEntry(entry);
      } catch {
        return fail(400, ERR_INVALID_REQUEST);
      }
      scope.push(entry);
    }
    // THE SCOPE MUST BIND. A binding needs a key and an id the offer does not have yet, so the
    // probe uses placeholders of the right size: what is being asked is only whether THESE
    // scope entries and THIS validity fit the binding's fields (§3.2), which no key changes. An
    // offer that passes here can always be begun on; one that failed would have sat open until
    // it expired, every begin on it refused for a reason the page cannot see.
    try {
      loginBinding(LOGIN_ROLE_LOGIN, this.audience, {
        id: new Uint8Array(MIN_ENTROPY),
        nonce: new Uint8Array(MIN_ENTROPY),
        browser: new Uint8Array(32),
        scope,
        validFor,
      });
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }

    // One code, one offer: a LIVE offer under this code already is a conflict. The prover
    // minted the code from 16 bytes of its own entropy, so this is a broken prover or a
    // replay, never a collision worth retrying silently. A dead offer under the code is simply
    // replaced — the code is free again.
    if (this.#liveOffer(code) !== undefined) return fail(409, ERR_INVALID_REQUEST);
    const now = this.#clock();
    this.#offers.set(code, { code, scope, validFor, expires: now + this.ttlSeconds, request: undefined });

    const response: Record<string, unknown> = {
      code,
      scope,
      valid_for: validFor,
      expires_in: this.ttlSeconds,
      interval: this.intervalSeconds,
    };
    // The code rides in the fragment, which a browser keeps to itself: the page's script reads
    // it, no server and no log ever sees it (§4.1 "The code").
    if (this.page !== undefined) response["page"] = `${this.page}#${code}`;
    return ok(201, response);
  }

  /** Read once by the page — to learn what it is being offered — and polled by the prover
   *  until `request` names the request that took the offer (§4.1).
   *
   *  There is deliberately NO pacing on this route (ADR 0007 §C.7, amendment #39). Two parties
   *  poll it, and one reference time would let the prover's period lock the page out on every
   *  retry; and there is nothing here to protect — no proof to verify, no answer to hand over.
   *  A stranger who holds the code already has everything this route returns. The prover paces
   *  itself by the `interval` the offer response advertised.
   *
   *  A malformed code is 404, the same as an unknown one: a registered code is always
   *  well-formed, so a malformed one is unknown by construction. */
  #readOffer(code: string): Response {
    if (!isCode(code)) return fail(404, ERR_EXPIRED_TOKEN);
    const offer = this.#liveOffer(code);
    if (offer === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    return ok(200, {
      code: offer.code,
      scope: offer.scope,
      valid_for: offer.validFor,
      // null until taken, then the id — the shape a poller switches on.
      request: offer.request ?? null,
      expires: rfc3339(offer.expires),
    });
  }

  /** The one definition of a live offer: unexpired, and — if a request has taken it — that
   *  request still present and unexpired. "Dies with its request" (§4.1) is enforced here, on
   *  every read, rather than by anything that runs when a request is collected: an offer that
   *  consults the record it points at can never disagree with it. */
  #offerIsLive(offer: Offer, now: number): boolean {
    if (now >= offer.expires) return false;
    if (offer.request === undefined) return true;
    const record = this.#records.get(offer.request);
    return record !== undefined && now < record.expires;
  }

  /** The live offer under `code`, or undefined if it never existed, expired, or died with its
   *  request — one answer on the wire, so a stranger probing codes learns nothing. */
  #liveOffer(code: string): Offer | undefined {
    const offer = this.#offers.get(code);
    if (offer === undefined) return undefined;
    if (!this.#offerIsLive(offer, this.#clock())) {
      this.#offers.delete(code);
      return undefined;
    }
    return offer;
  }

  /** What the CLI fetches. It answers with the request and NOT with the audience: there is no
   *  audience field in this response by design, because a CLI that would read one is a CLI
   *  that can be told to sign for someone else (Finding 1). */
  #read(idHex: string): Response {
    const record = this.#live(idHex);
    if (record === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    return ok(200, {
      id: idHex,
      nonce: toHex(record.nonce),
      browser: encodeKey(record.browser),
      scope: record.scope,
      valid_for: record.validFor,
      expires: rfc3339(record.expires),
    });
  }

  /**
   * Verifies BEFORE storing, which is the whole point of the route (§4).
   *
   * THE AWAIT IS THE HAZARD. `AdmitAuthority` is the SERVICE's code and may be async — a
   * database, a network call — and JavaScript hands the runtime to every other pending request
   * at that `await`. So the state this decision rests on is RE-CHECKED afterwards: a second
   * CLI answering the same login while the first was being admitted is ordinary (a person with
   * two terminals), and the loser must get 409 rather than overwrite an answer the browser may
   * already have collected.
   *
   * The three server lanes reach the same rule from opposite directions: go and rs must keep
   * the law OUT of the store's mutex so one slow law cannot decide the throughput of every
   * login; here there is no mutex to hold, and the danger is the interleaving that an `await`
   * makes certain rather than merely possible.
   */
  async #answer(request: Request, idHex: string): Promise<Response> {
    let body: Record<string, unknown>;
    let authority: string | undefined;
    try {
      const parsed = parseBody(await request.arrayBuffer(), ["principal", "possession", "authority"]);
      body = parsed.body;
      // The authority is carried as the bytes the CLI sent, never rebuilt from the parse.
      // See `authoritySpan`: JSON.parse + JSON.stringify silently rewrites large integers,
      // trailing zeros, escapes and key order.
      authority = parsed.members.get("authority");
      if (authority === undefined && Object.prototype.hasOwnProperty.call(body, "authority")) {
        // The parser saw a member the scanner did not. They read the same bytes, so this is
        // not a request problem — but guessing which one is right is how a payload gets
        // rebuilt behind the law's back. Refuse instead.
        return fail(400, ERR_INVALID_REQUEST);
      }
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }
    const principalText = body["principal"];
    const possessionText = body["possession"];
    if (typeof principalText !== "string" || typeof possessionText !== "string") {
      return fail(400, ERR_INVALID_REQUEST);
    }
    let principal: Uint8Array;
    let possession: Uint8Array;
    try {
      principal = decodeKey(principalText);
      possession = fromHex(possessionText);
    } catch {
      return fail(400, ERR_INVALID_REQUEST);
    }

    const record = this.#live(idHex);
    if (record === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    if (record.answered !== undefined) return fail(409, ERR_INVALID_REQUEST);

    if (!verifyLogin(principal, this.audience, toRequest(record), possession)) {
      return fail(403, ERR_INVALID_GRANT);
    }
    if (this.#admit !== undefined) {
      try {
        await this.#admit(record.browser, principal, new TextEncoder().encode(authority ?? ""));
      } catch {
        return fail(403, ERR_INVALID_GRANT);
      }
    }

    // Everything the decision rested on, re-read after the await.
    const still = this.#live(idHex);
    if (still === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    if (still.answered !== undefined) {
      // Another answer won while this one was being admitted. Storing here would discard a
      // proof the browser may already have collected.
      return fail(409, ERR_INVALID_REQUEST);
    }
    still.answered = { principal: principalText, possession: possessionText, authority };
    return new Response(null, { status: 204 });
  }

  /**
   * Hands the answer to the browser ONCE and drops the record.
   *
   * THE ORDER IS caa's FIX: the interval is checked WITHOUT writing the timer, the proof is
   * verified, and only then does the timer advance — immediately before the answer is taken,
   * with NO `await` in between, which is what makes the take-and-drop atomic in this lane.
   * Advancing the timer before verification let a stranger polling junk hold the real browser
   * at 429 indefinitely, turning slow_down into a denial of service handed to anyone who saw
   * the id.
   *
   * A stranger is therefore not rate-limited here at all. That is correct: they get 403 every
   * time, and §B says to add no rate limiting beyond slow_down, which exists for the legitimate
   * client rather than as a guard.
   */
  #collect(request: Request, idHex: string): Response {
    const header = request.headers.get(COLLECT_HEADER);
    if (header === null || header.length === 0) return fail(403, ERR_INVALID_GRANT);
    let proof: Uint8Array;
    try {
      proof = fromHex(header);
    } catch {
      return fail(403, ERR_INVALID_GRANT);
    }

    const record = this.#live(idHex);
    if (record === undefined) return fail(404, ERR_EXPIRED_TOKEN);
    const now = this.#clock();
    if (record.lastPoll !== undefined && now - record.lastPoll < this.intervalSeconds) {
      return fail(429, ERR_SLOW_DOWN);
    }
    if (!verifyCollect(this.audience, toRequest(record), proof)) return fail(403, ERR_INVALID_GRANT);

    record.lastPoll = now;
    const answer = record.answered;
    if (answer === undefined) return fail(202, ERR_PENDING);
    this.#records.delete(idHex);

    // Built as TEXT, not as an object handed to JSON.stringify: the authority is spliced in
    // exactly as the CLI wrote it, which is the whole point. `principal` and `possession` are
    // this handler's own key text and hex, so encoding those is safe.
    const authority = answer.authority === undefined ? "" : `,"authority":${answer.authority}`;
    const body =
      `{"principal":${JSON.stringify(answer.principal)},` +
      `"possession":${JSON.stringify(answer.possession)}${authority}}`;
    return new Response(body, { status: 200, headers: JSON_HEADERS });
  }

  /** The record for `idHex`, or undefined if it never existed or has expired — which are the
   *  same answer on the wire, so a stranger probing ids learns nothing from the difference. */
  #live(idHex: string): Record_ | undefined {
    const record = this.#records.get(idHex);
    if (record === undefined) return undefined;
    if (this.#clock() >= record.expires) {
      this.#records.delete(idHex);
      return undefined;
    }
    return record;
  }
}
