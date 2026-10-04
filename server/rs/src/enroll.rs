//! The server's half of key enrollment (ADR 0010 §7; `docs/request.md` §6, PROVISIONAL until
//! ADR 0010 §8's gate is met).
//!
//! An enrollment has a new key prove its own possession while a separate authority — the
//! service's session, or a bootstrap credential — says whose key it is. The sdk holds the
//! binding and the proof. This module holds what only a server can, in two halves:
//!
//! - [`Enroller::prepare`] builds the PENDING RECORD, the immutable association of authorizing
//!   context, intended account, purpose, new key, a fresh nonce, the intent's digest and an
//!   expiry. The service calls it only after validating the session or bootstrap credential,
//!   persists the record in its own transaction (reserving a bootstrap credential to it
//!   atomically, when there is one), and sends the client the [`Challenge`].
//! - [`Enroller::complete`] takes what a completion request carries — the transaction id and the
//!   proof — and the authorization the service extracted from that request. It checks, in order:
//!   the record exists and has not expired; the same authorization began it; the proof verifies
//!   under the record's new key, over the binding rebuilt from the record and the configured
//!   audience. Only then does it call [`Integration::complete`], the service's ATOMIC business
//!   operation: the key-account association recorded and the record consumed, in one persistence
//!   transaction. archon cannot promise that atomicity across a callback and a separate database
//!   (ADR 0010 §7), so it does not pretend to: the operation is the service's.
//!
//! There is NO "possession alone suffices" mode: [`Enroller::new`] takes the integration as a
//! required argument, so an enroller without one does not compile. Possession identifies a key;
//! only the service's authority ties it to an account. And a completion cannot substitute
//! anything: it names a record, and the account, key, purpose, nonce and intent all come from
//! that record.
//!
//! archon defines no enrollment route. The service mounts completion wherever it serves its
//! accounts, behind its own session and CSRF protection.

use std::fmt;
use std::sync::Arc;

use archon_core::crypto::PUBLIC_KEY_SIZE;
use archon_sdk::enroll::{self as sdk, Request};
use archon_sdk::possession::MIN_NONCE_SIZE;
use sha2::{Digest, Sha256};

use crate::{Clock, Entropy, Response};

/// How long a pending enrollment lives, in seconds, unless [`Enroller::with_ttl`] says otherwise.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// The generated transaction id's and nonce's size: the possession scheme's floor, and enough
/// that an id is not guessable.
const ID_SIZE: usize = MIN_NONCE_SIZE;

/// A pending enrollment: written once by [`Enroller::prepare`], persisted by the service, never
/// changed — completion consumes it, it does not edit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub transaction: Vec<u8>,
    /// What authorized the enrollment: the session, or the bootstrap credential reserved to this
    /// record. An identifier, never a secret — a session's id, not its cookie — since the record
    /// is stored.
    pub authorization: Vec<u8>,
    /// The intended account, opaque to archon.
    pub account: Vec<u8>,
    pub purpose: String,
    pub new_key: Vec<u8>,
    pub nonce: Vec<u8>,
    /// SHA-256 of the service's immutable intent bytes.
    pub intent_digest: Vec<u8>,
    /// Seconds since the epoch.
    pub expires: u64,
}

/// What the client needs to prove: the record's public half and the audience.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub transaction: Vec<u8>,
    pub nonce: Vec<u8>,
    pub purpose: String,
    pub audience: String,
    pub intent_digest: Vec<u8>,
    pub expires: u64,
}

/// What the service supplies to [`Enroller::prepare`], after validating the authorizing
/// credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Begin {
    pub authorization: Vec<u8>,
    pub account: Vec<u8>,
    pub purpose: String,
    pub new_key: Vec<u8>,
    /// The immutable intent bytes — what the service will record. archon binds their digest and
    /// never interprets them. A digest is not confidentiality: keep guessable account data out.
    pub intent: Vec<u8>,
}

/// What [`Integration::complete`] answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The association is recorded and the record consumed.
    Completed,
    /// Already completed or consumed, or no longer acceptable.
    NotPending,
    /// The integration cannot answer: the completion fails closed.
    Unavailable,
}

/// The service's authorizing integration: its persistence of pending records and its atomic
/// completion.
pub trait Integration: Send + Sync {
    /// The record for `transaction`; `Ok(None)` when there is none; `Err` when it cannot answer,
    /// and the completion fails closed.
    fn load(&self, transaction: &[u8]) -> Result<Option<Record>, String>;

    /// The service's atomic business operation. In one persistence transaction it checks that
    /// `record` is still pending and its authorizing context still acceptable under the
    /// service's policy, records `record.new_key` as `record.account`'s for `record.purpose`,
    /// and consumes the record (and any bootstrap credential reserved to it). Concurrent calls
    /// for one record answer `Completed` at most once.
    fn complete(&self, record: &Record) -> Outcome;
}

/// Why a completion failed, with the HTTP status a service's route answers: 400 for a malformed
/// completion, 401 for a proof that does not verify, 403 for a completion under another
/// authorization, 404 for an unknown or expired transaction, 409 for one already completed or no
/// longer eligible, 503 when the integration cannot answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub reason: String,
}

impl Refusal {
    fn new(status: u16, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
        }
    }

    /// The refusal as a response: its status and a one-line reason.
    pub fn response(&self) -> Response {
        Response {
            status: self.status,
            body: format!("{}\n", self.reason).into_bytes(),
            headers: vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Refusal {}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn request(r: &Record) -> Request {
    Request {
        nonce: r.nonce.clone(),
        transaction: r.transaction.clone(),
        purpose: r.purpose.clone(),
        new_key: r.new_key.clone(),
        intent_digest: r.intent_digest.clone(),
    }
}

/// Prepares and completes enrollments under one configuration.
pub struct Enroller {
    audience: String,
    integration: Arc<dyn Integration>,
    ttl: u64,
    clock: Clock,
    entropy: Entropy,
}

impl Enroller {
    /// An enroller for `audience`. The integration is required — without it, possession alone
    /// would suffice — and the clock and entropy are arguments, as the login handler's are.
    /// Refuses an audience the binding does not accept.
    pub fn new(
        audience: &str,
        integration: Arc<dyn Integration>,
        clock: Clock,
        entropy: Entropy,
    ) -> Result<Self, String> {
        let probe = Request {
            nonce: vec![0; ID_SIZE],
            transaction: vec![0],
            purpose: "add-key".to_string(),
            new_key: vec![0; PUBLIC_KEY_SIZE],
            intent_digest: vec![0; sdk::DIGEST_SIZE],
        };
        sdk::binding(audience, &probe)
            .map_err(|e| format!("enroll: audience {audience:?}: {e}"))?;
        Ok(Self {
            audience: audience.to_string(),
            integration,
            ttl: DEFAULT_TTL_SECS,
            clock,
            entropy,
        })
    }

    /// The same enroller with pending enrollments living `secs` seconds.
    pub fn with_ttl(mut self, secs: u64) -> Self {
        self.ttl = secs;
        self
    }

    /// The pending record for `begin`, and the challenge to send the client. The service
    /// persists the record; nothing here stores it.
    pub fn prepare(&self, begin: &Begin) -> Result<(Record, Challenge), String> {
        if begin.authorization.is_empty() {
            return Err("enroll: an enrollment needs the authorization that began it".to_string());
        }
        if begin.account.is_empty() {
            return Err("enroll: an enrollment needs the account it is for".to_string());
        }
        let mut transaction = vec![0; ID_SIZE];
        let mut nonce = vec![0; ID_SIZE];
        (self.entropy)(&mut transaction).map_err(|e| format!("enroll: entropy: {e}"))?;
        (self.entropy)(&mut nonce).map_err(|e| format!("enroll: entropy: {e}"))?;
        let record = Record {
            transaction,
            authorization: begin.authorization.clone(),
            account: begin.account.clone(),
            purpose: begin.purpose.clone(),
            new_key: begin.new_key.clone(),
            nonce,
            intent_digest: Sha256::digest(&begin.intent).to_vec(),
            expires: (self.clock)().saturating_add(self.ttl),
        };
        // The sdk's binding rules, refused here rather than at completion.
        sdk::binding(&self.audience, &request(&record))?;
        let challenge = Challenge {
            transaction: record.transaction.clone(),
            nonce: record.nonce.clone(),
            purpose: record.purpose.clone(),
            audience: self.audience.clone(),
            intent_digest: record.intent_digest.clone(),
            expires: record.expires,
        };
        Ok((record, challenge))
    }

    /// Completes the enrollment `transaction` names, under `authorization`, with `proof`, and
    /// returns the completed record.
    pub fn complete(
        &self,
        transaction: &[u8],
        proof: &[u8],
        authorization: &[u8],
    ) -> Result<Record, Refusal> {
        if transaction.is_empty() || transaction.len() > sdk::MAX_TRANSACTION_SIZE {
            return Err(Refusal::new(400, "enroll: malformed transaction id"));
        }
        let record = match self.integration.load(transaction) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(Refusal::new(404, "enroll: unknown or expired transaction")),
            Err(e) => {
                return Err(Refusal::new(
                    503,
                    format!("enroll: the integration cannot load: {e}"),
                ))
            }
        };
        // A record for another transaction is an integration fault, and is never verified
        // against.
        if !equal(&record.transaction, transaction) {
            return Err(Refusal::new(
                503,
                "enroll: the integration returned another transaction's record",
            ));
        }
        if (self.clock)() >= record.expires {
            return Err(Refusal::new(404, "enroll: unknown or expired transaction"));
        }
        // The same authorization that began it — checked before the proof, so a stranger's
        // completion learns nothing about it.
        if authorization.is_empty() || !equal(&record.authorization, authorization) {
            return Err(Refusal::new(
                403,
                "enroll: not the authorization that began this enrollment",
            ));
        }
        if !sdk::verify(&self.audience, &request(&record), proof) {
            return Err(Refusal::new(401, "enroll: the proof does not verify"));
        }
        match self.integration.complete(&record) {
            Outcome::Completed => Ok(record),
            Outcome::NotPending => Err(Refusal::new(
                409,
                "enroll: already completed or no longer eligible",
            )),
            Outcome::Unavailable => {
                Err(Refusal::new(503, "enroll: the integration cannot complete"))
            }
        }
    }
}
