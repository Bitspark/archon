// The server's half of key enrollment (ADR 0010 §7; docs/request.md §6, version 1, fixed by
// ADR 0010's status note of 4 October 2026).
//
// An enrollment has a new key prove its own possession while a separate authority — the
// service's session, or a bootstrap credential — says whose key it is. The sdk holds the binding
// and the proof. This module holds what only a server can, in two halves:
//
// - `prepare` builds the PENDING RECORD, the immutable association of authorizing context,
//   intended account, purpose, new key, a fresh nonce, the intent's digest and an expiry. The
//   service calls it only after validating the session or bootstrap credential, persists the
//   record in its own transaction (reserving a bootstrap credential to it atomically, when there
//   is one), and sends the client the challenge.
// - `complete` takes what a completion request carries — the transaction id and the proof — and
//   the authorization the service extracted from that request. It checks, in order: the record
//   exists and has not expired; the same authorization began it; the proof verifies under the
//   record's new key, over the binding rebuilt from the record and the configured audience. Only
//   then does it call the integration's `complete`, the service's ATOMIC business operation: the
//   key-account association recorded and the record consumed, in one persistence transaction.
//   archon cannot promise that atomicity across a callback and a separate database (ADR 0010
//   §7), so it does not pretend to: the operation is the service's.
//
// There is NO "possession alone suffices" mode: the constructor refuses a missing integration.
// Possession identifies a key; only the service's authority ties it to an account. And a
// completion cannot substitute anything: it names a record, and the account, key, purpose, nonce
// and intent all come from that record.
//
// archon defines no enrollment route. The service mounts completion wherever it serves its
// accounts, behind its own session and CSRF protection.
import {
  ENROLL_DIGEST_SIZE,
  ENROLL_MAX_TRANSACTION_SIZE,
  ENROLL_MIN_BLIND_SIZE,
  MIN_NONCE_SIZE,
  decodeEnrollIntent,
  encodeEnrollChallenge,
  encodeEnrollIntent,
  enrollBinding,
  verifyEnroll,
  type EnrollRequest,
} from "@bitspark/archon-sdk";

/** How long a pending enrollment lives, in seconds, when the config names no ttl. */
export const ENROLL_DEFAULT_TTL_SECONDS = 300;

/** The generated transaction id's and nonce's size: the possession scheme's floor, and enough
 *  that an id is not guessable. */
const ID_SIZE = MIN_NONCE_SIZE;

/** A pending enrollment: written once by `prepare`, persisted by the service, never changed —
 *  completion consumes it, it does not edit it. */
export interface EnrollmentRecord {
  transaction: Uint8Array;
  /** What authorized the enrollment: the session, or the bootstrap credential reserved to this
   *  record. An identifier, never a secret — a session's id, not its cookie — since the record
   *  is stored. */
  authorization: Uint8Array;
  /** The intended account, opaque to archon. */
  account: Uint8Array;
  purpose: string;
  newKey: Uint8Array;
  nonce: Uint8Array;
  /** SHA-256 of the service's immutable intent bytes. */
  intentDigest: Uint8Array;
  /** Seconds since the epoch. */
  expires: number;
}

/** What the client needs to prove: the record's public half and the audience. */
export interface EnrollmentChallenge {
  transaction: Uint8Array;
  nonce: Uint8Array;
  purpose: string;
  audience: string;
  intentDigest: Uint8Array;
  expires: number;
}

/** What the service supplies to `prepare`, after validating the authorizing credential. */
export interface EnrollmentBegin {
  authorization: Uint8Array;
  account: Uint8Array;
  purpose: string;
  newKey: Uint8Array;
  /** The immutable intent bytes — what the service will record. `prepare` and `complete` bind
   *  their digest and never interpret them. A digest is not confidentiality, so no intent may
   *  have a guessable preimage: build it with `Enroller.intent` (format 1, a fresh blind) for
   *  `archon enroll`, or keep guessable account data out (ADR 0013, docs/enroll.md §2). */
  intent: Uint8Array;
}

export type EnrollmentOutcome = "completed" | "notPending" | "unavailable";

/** The service's authorizing integration: its persistence of pending records and its atomic
 *  completion. */
export interface EnrollmentIntegration {
  /** The record for `transaction`, or undefined when there is none. A throw means it cannot
   *  answer, and the completion fails closed. */
  load(transaction: Uint8Array): EnrollmentRecord | undefined | Promise<EnrollmentRecord | undefined>;
  /**
   * The service's atomic business operation. In one persistence transaction it checks that
   * `record` is still pending and its authorizing context still acceptable under the service's
   * policy, records `record.newKey` as `record.account`'s for `record.purpose`, and consumes the
   * record (and any bootstrap credential reserved to it). Concurrent calls for one record answer
   * "completed" at most once.
   */
  complete(record: EnrollmentRecord): EnrollmentOutcome | Promise<EnrollmentOutcome>;
}

export interface EnrollerConfig {
  /** The configured audience every binding is rebuilt from (docs/request.md §2). */
  audience: string;
  /** Required: without it, possession alone would suffice. */
  integration: EnrollmentIntegration;
  /** Seconds; defaults to ENROLL_DEFAULT_TTL_SECONDS. */
  ttl?: number;
  /** Seconds since the epoch; defaults to the system clock. */
  clock?: () => number;
  entropy?: (n: number) => Uint8Array;
}

/** Why a completion failed, with the HTTP status a service's route answers: 400 for a malformed
 *  completion, 401 for a proof that does not verify, 403 for a completion under another
 *  authorization, 404 for an unknown or expired transaction, 409 for one already completed or no
 *  longer eligible, 503 when the integration cannot answer. */
export class EnrollmentRefusal extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function request(r: EnrollmentRecord): EnrollRequest {
  return { nonce: r.nonce, transaction: r.transaction, purpose: r.purpose, newKey: r.newKey, intentDigest: r.intentDigest };
}

/** Prepares and completes enrollments under one configuration. */
export class Enroller {
  readonly #audience: string;
  readonly #integration: EnrollmentIntegration;
  readonly #ttl: number;
  readonly #clock: () => number;
  readonly #entropy: (n: number) => Uint8Array;

  constructor(config: EnrollerConfig) {
    if (config.integration === undefined || config.integration === null) {
      throw new Error("enroll: an integration is required — possession identifies a key; only the service's authority ties it to an account");
    }
    // The binding's audience rules, checked once here rather than failing every completion.
    enrollBinding(config.audience, {
      nonce: new Uint8Array(ID_SIZE),
      transaction: new Uint8Array(1),
      purpose: "add-key",
      newKey: new Uint8Array(32),
      intentDigest: new Uint8Array(ENROLL_DIGEST_SIZE),
    });
    this.#audience = config.audience;
    this.#integration = config.integration;
    this.#ttl = config.ttl ?? ENROLL_DEFAULT_TTL_SECONDS;
    this.#clock = config.clock ?? (() => Math.floor(Date.now() / 1000));
    this.#entropy = config.entropy ?? ((n) => crypto.getRandomValues(new Uint8Array(n)));
  }

  /** The pending record for `begin`, and the challenge to send the client. The service persists
   *  the record; nothing here stores it. */
  async prepare(begin: EnrollmentBegin): Promise<{ record: EnrollmentRecord; challenge: EnrollmentChallenge }> {
    if (begin.authorization.length === 0) throw new Error("enroll: an enrollment needs the authorization that began it");
    if (begin.account.length === 0) throw new Error("enroll: an enrollment needs the account it is for");
    const intent = new Uint8Array(begin.intent);
    const record: EnrollmentRecord = {
      transaction: this.#entropy(ID_SIZE).slice(),
      authorization: begin.authorization.slice(),
      account: begin.account.slice(),
      purpose: begin.purpose,
      newKey: begin.newKey.slice(),
      nonce: this.#entropy(ID_SIZE).slice(),
      intentDigest: new Uint8Array(await crypto.subtle.digest("SHA-256", intent)),
      expires: this.#clock() + this.#ttl,
    };
    // The sdk's binding rules, refused here rather than at completion.
    enrollBinding(this.#audience, request(record));
    return {
      record,
      challenge: {
        transaction: record.transaction,
        nonce: record.nonce,
        purpose: record.purpose,
        audience: this.#audience,
        intentDigest: record.intentDigest,
        expires: record.expires,
      },
    };
  }

  /** Complete the enrollment `transaction` names, under `authorization`, with `proof`. Returns
   *  the completed record; throws an EnrollmentRefusal. */
  async complete(transaction: Uint8Array, proof: Uint8Array, authorization: Uint8Array): Promise<EnrollmentRecord> {
    if (transaction.length === 0 || transaction.length > ENROLL_MAX_TRANSACTION_SIZE) {
      throw new EnrollmentRefusal(400, "enroll: malformed transaction id");
    }
    let record: EnrollmentRecord | undefined;
    try {
      record = await this.#integration.load(transaction);
    } catch {
      throw new EnrollmentRefusal(503, "enroll: the integration cannot load");
    }
    if (record === undefined) throw new EnrollmentRefusal(404, "enroll: unknown or expired transaction");
    // A record for another transaction is an integration fault, and is never verified against.
    if (!equal(record.transaction, transaction)) {
      throw new EnrollmentRefusal(503, "enroll: the integration returned another transaction's record");
    }
    if (this.#clock() >= record.expires) throw new EnrollmentRefusal(404, "enroll: unknown or expired transaction");
    // The same authorization that began it — checked before the proof, so a stranger's
    // completion learns nothing about it.
    if (authorization.length === 0 || !equal(record.authorization, authorization)) {
      throw new EnrollmentRefusal(403, "enroll: not the authorization that began this enrollment");
    }
    if (!verifyEnroll(this.#audience, request(record), proof)) {
      throw new EnrollmentRefusal(401, "enroll: the proof does not verify");
    }
    let outcome: EnrollmentOutcome;
    try {
      outcome = await this.#integration.complete(record);
    } catch {
      outcome = "unavailable";
    }
    if (outcome === "completed") return record;
    if (outcome === "notPending") throw new EnrollmentRefusal(409, "enroll: already completed or no longer eligible");
    throw new EnrollmentRefusal(503, "enroll: the integration cannot complete");
  }

  // The service's half of `archon enroll`'s formats (docs/enroll.md §2–§3, §6; ADR 0013).
  // Verification and completion never read the intent; only these helpers and the command do.

  /**
   * An intent in format 1 (docs/enroll.md §2) with a fresh blind from this enroller's entropy.
   * `accountId` is the service's identifier for the account; `accountName` is the account's
   * unique name, such as its sign-in handle, never a display name its holder chooses freely.
   * Build both from the account the validated session or credential authorizes, never from a
   * label the browser sent.
   *
   * Pass the bytes to `prepare` as `intent` with `purpose` set to the same purpose, and persist
   * them beside the record: `challengeToken` needs them again.
   */
  intent(fields: { accountId: string; accountName: string; purpose: string; restrictions?: string[] }): Uint8Array {
    return encodeEnrollIntent({
      blind: this.#entropy(ENROLL_MIN_BLIND_SIZE).slice(),
      accountId: fields.accountId,
      accountName: fields.accountName,
      purpose: fields.purpose,
      restrictions: fields.restrictions ?? [],
    });
  }

  /**
   * The challenge token for `record` (docs/enroll.md §3): the configured audience, the record's
   * transaction, nonce and new key, `intent`, and the record's expiry rounded down to the
   * second. `intent` is the bytes passed to `prepare` for `record`.
   *
   * Refuses intent bytes whose SHA-256 is not the record's intent digest, an intent not in
   * format 1, and an intent whose purpose is not the record's: `archon enroll` binds the intent's
   * purpose and the digest of the bytes it shows, so a proof over any of those would never
   * verify.
   */
  async challengeToken(record: EnrollmentRecord, intent: Uint8Array): Promise<string> {
    // slice(): an ArrayBuffer-backed copy, which is what subtle.digest's BufferSource admits.
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", intent.slice()));
    if (!equal(digest, record.intentDigest)) {
      throw new Error("enroll: these intent bytes are not the record's: their SHA-256 differs from its intent digest");
    }
    const decoded = decodeEnrollIntent(intent);
    if (decoded.purpose !== record.purpose) {
      throw new Error(
        `enroll: the intent's purpose ${JSON.stringify(decoded.purpose)} is not the record's ${JSON.stringify(record.purpose)}; pass prepare the intent's purpose`,
      );
    }
    return encodeEnrollChallenge({
      audience: this.#audience,
      transaction: record.transaction,
      nonce: record.nonce,
      newKey: record.newKey,
      intent,
      deadline: Math.floor(record.expires),
    });
  }
}
