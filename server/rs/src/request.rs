//! The server's half of request authentication (ADR 0010 §5–§6; `docs/request.md` §7 steps
//! 8–9, PROVISIONAL until ADR 0010 §8's gate is met).
//!
//! `archon_sdk::request::verify` checks a proof: one spelling, the coverage, the audience echo,
//! the digest, freshness and the signature. It does not remember. This module adds what only a
//! server can: the HTTP extraction (from an [`http::Head`](crate::http::Head), the request line
//! as received), the clock, and the REPLAY STORE — the one operation that makes a proof usable at
//! most once:
//!
//! ```text
//! insert_if_absent((profile, audience, principal, nonce), from, until) → Inserted | AlreadyPresent | Unavailable
//! ```
//!
//! A request reaches the application only as an [`Authenticated`], and only after a proof
//! verified AND its identifier was inserted. `AlreadyPresent` is a replay; `Unavailable` FAILS
//! CLOSED — a store that cannot answer is never permission to skip the check.
//!
//! Like the login handler, nothing here opens a socket or spawns a task. [`body_length`] tells the
//! caller how many body bytes to read, or that it must not read them at all; then
//! [`Verifier::authenticate`] is a function from the parsed head and its body to a verdict.
//!
//! What this does not do: authorize. [`Authenticated`] is the principal together with the
//! verified request descriptor, so the application's authorization evaluates the request
//! authentication verified — not a re-parse of it (ADR 0010 §6).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use archon_sdk::request::{self as sdk, Policy, Received, Verified};

use crate::http::Head;
use crate::{Clock, Response};

/// The largest body a verifier reads to recompute the digest. A larger one is refused, never
/// truncated: a digest over part of a body verifies nothing.
pub const MAX_REQUEST_BODY_BYTES: usize = 1 << 20;

/// What a replay store answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The identifier was new and is now remembered.
    Inserted,
    /// The identifier was seen: a replay.
    AlreadyPresent,
    /// The store cannot answer: the request fails closed.
    Unavailable,
}

/// What a replay store remembers. Never the signature bytes: a signature is one spelling of a
/// proof, the identifier is the proof's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    /// [`sdk::TAG`].
    pub profile: String,
    pub audience: String,
    /// The canonical key text.
    pub principal: String,
    /// Hex.
    pub nonce: String,
}

/// One insertion: the key, and the window in which any verifier could accept the proof — `from`
/// is created − δ, `until` is expires + δ, in seconds since the epoch. A store retains the key at
/// least until `until`; `from` is what lets a store that lost its memory refuse proofs it might
/// have seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayEntry {
    pub key: ReplayKey,
    pub from: u64,
    pub until: u64,
}

/// Makes a proof usable at most once. Requirements (ADR 0010 §5): one winner across every
/// verifier in the acceptance scope — concurrent inserts of one key return `Inserted` at most
/// once; a key retained at least until its `until`, when no verifier can still accept the proof;
/// and a store that cannot guarantee both answers `Unavailable` rather than `Inserted`.
pub trait ReplayStore: Send + Sync {
    fn insert_if_absent(&self, entry: &ReplayEntry) -> Outcome;
}

/// The reference [`ReplayStore`]: one process, in memory. It is correct for exactly one verifier
/// process, and its RESTART POLICY is what makes it correct across a restart at all (ADR 0010 §5:
/// losing accepted identifiers reopens old proofs).
///
/// A proof is acceptable from `entry.from` (created − δ). A process started at `start` cannot know
/// what an earlier process accepted, so this store admits only proofs whose window opened at or
/// after `start`, and answers `Unavailable` for anything older — waiting out, rather than guessing
/// about, the proofs a previous incarnation could have seen. A deployment with more than one
/// verifier, or that cannot afford the wait, supplies a shared store with the same contract.
pub struct MemoryReplayStore {
    start: u64,
    seen: Mutex<HashMap<ReplayKey, u64>>,
}

impl MemoryReplayStore {
    /// A store whose incarnation began at `start`, in seconds since the epoch.
    pub fn new(start: u64) -> Self {
        Self {
            start,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// When this incarnation began.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Forgets every identifier whose `until` is not after `now`, and returns how many. Optional
    /// and caller-driven: nothing here spawns a task, and retaining a key longer is always safe.
    pub fn sweep(&self, now: u64) -> usize {
        let Ok(mut seen) = self.seen.lock() else {
            return 0;
        };
        let before = seen.len();
        seen.retain(|_, until| *until > now);
        before - seen.len()
    }
}

impl ReplayStore for MemoryReplayStore {
    fn insert_if_absent(&self, entry: &ReplayEntry) -> Outcome {
        if entry.from < self.start {
            return Outcome::Unavailable;
        }
        // A poisoned lock is a store that can no longer vouch for what it holds.
        let Ok(mut seen) = self.seen.lock() else {
            return Outcome::Unavailable;
        };
        if seen.contains_key(&entry.key) {
            return Outcome::AlreadyPresent;
        }
        seen.insert(entry.key.clone(), entry.until);
        Outcome::Inserted
    }
}

/// A request that verified and was admitted by the replay store: the principal, and the request
/// descriptor authentication verified. Only [`Verifier::authenticate`] makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated(Verified);

impl Authenticated {
    /// What was verified.
    pub fn verified(&self) -> &Verified {
        &self.0
    }

    pub fn into_verified(self) -> Verified {
        self.0
    }
}

impl std::ops::Deref for Authenticated {
    type Target = Verified;
    fn deref(&self) -> &Verified {
        &self.0
    }
}

/// Why a request was not authenticated, with the HTTP status to answer: 400 for a request the
/// profile does not accept as transported, 401 for one that does not authenticate, 413 for an
/// oversized body, 503 when the replay store is unavailable.
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

/// How many body bytes to read for `head`, decided before a single one is read.
///
/// This crate frames a body by `Content-Length` alone, so a transfer coding is refused (400) —
/// which also refuses every trailer, as v1 requires (ADR 0010 §4). So is a `Content-Length` that
/// is not plain digits or appears more than once: two framings of one body are two bodies. A
/// declared length over [`MAX_REQUEST_BODY_BYTES`] is 413.
pub fn body_length(head: &Head) -> Result<usize, Refusal> {
    if head.header("transfer-encoding").is_some() {
        return Err(Refusal::new(
            400,
            "request: only a Content-Length body is accepted: no transfer coding, no trailers",
        ));
    }
    let lengths: Vec<&str> = head
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str())
        .collect();
    let raw = match lengths.as_slice() {
        [] => return Ok(0),
        [one] => *one,
        _ => {
            return Err(Refusal::new(
                400,
                "request: Content-Length appears more than once",
            ))
        }
    };
    if raw.is_empty() || raw.len() > 15 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::new(400, "request: Content-Length is not a length"));
    }
    let n: usize = raw
        .parse()
        .map_err(|_| Refusal::new(400, "request: Content-Length is not a length"))?;
    if n > MAX_REQUEST_BODY_BYTES {
        return Err(Refusal::new(
            413,
            "request: the body is over the verifier's limit",
        ));
    }
    Ok(n)
}

/// Authenticates requests under one policy against one replay store.
pub struct Verifier {
    policy: Policy,
    store: Arc<dyn ReplayStore>,
    clock: Clock,
}

impl Verifier {
    /// A verifier for `policy` against `store`. The clock is an argument, as the login
    /// handler's is: a test steps it by hand, production passes one that reads the system clock.
    pub fn new(policy: Policy, store: Arc<dyn ReplayStore>, clock: Clock) -> Self {
        Self {
            policy,
            store,
            clock,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Verifies the proof `head` and `body` carry, then inserts its identifier. The
    /// request-target is `head.target`, the request line as received, so what is verified is
    /// what arrived.
    pub fn authenticate(&self, head: &Head, body: &[u8]) -> Result<Authenticated, Refusal> {
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(Refusal::new(
                413,
                "request: the body is over the verifier's limit",
            ));
        }
        // v1 accepts no content coding and no trailers (ADR 0010 §4): the digest is over the
        // content as received, and a coded body would make "as received" ambiguous.
        if head.header("content-encoding").is_some() || head.header("transfer-encoding").is_some() {
            return Err(Refusal::new(
                400,
                "request: content codings and trailers are not accepted in v1",
            ));
        }
        let verified = sdk::verify(
            &self.policy,
            (self.clock)(),
            &Received {
                method: head.method.clone(),
                request_target: head.target.clone(),
                headers: head.headers.clone(),
                body: body.to_vec(),
            },
        )
        .map_err(|e| Refusal::new(401, e))?;

        // Only now, after the proof and its freshness verified (ADR 0010 §5: verify before
        // inserting), is the identifier remembered — until no verifier can still accept it.
        let entry = ReplayEntry {
            key: ReplayKey {
                profile: sdk::TAG.to_string(),
                audience: self.policy.audience.clone(),
                principal: verified.key_text.clone(),
                nonce: verified.nonce.iter().map(|b| format!("{b:02x}")).collect(),
            },
            from: verified.created.saturating_sub(self.policy.skew),
            until: verified.expires.saturating_add(self.policy.skew),
        };
        match self.store.insert_if_absent(&entry) {
            Outcome::Inserted => Ok(Authenticated(verified)),
            Outcome::AlreadyPresent => Err(Refusal::new(401, "request: replayed")),
            Outcome::Unavailable => Err(Refusal::new(
                503,
                "request: the replay store is unavailable",
            )),
        }
    }
}
