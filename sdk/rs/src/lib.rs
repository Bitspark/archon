//! archon-sdk — one layer above the identity floor.
//!
//! [archon-core] answers *"is this really them?"* over bytes. This crate answers the two
//! questions every protocol asks next, without knowing the protocol:
//!
//! - [`possession`] — *can they sign, right now, for this channel?* A challenge/response
//!   scheme: the challenger supplies a nonce and a channel binding, the prover signs a
//!   fixed layout of both in the protocol's domain, the challenger verifies. The binding
//!   is what makes the proof unrelayable; without one there is no proof, so an empty
//!   binding is refused.
//! - [`envelope`] — *these bytes, signed by this key, in this domain.* A fixed container:
//!   version, domain, public key, signature, opaque payload. JWS, never JWT: no expiry,
//!   issuer, audience or key-id — each is either policy (whose clock? whose trust?) or a
//!   second spelling of the key, and both are the consumer's.
//!
//! **The rule that keeps this layer honest:** entropy, time and channel binding are
//! *arguments*. This crate never sources them. That is what lets every byte it emits be a
//! deterministic function of its inputs and be pinned by `vectors/sdk.json` across three
//! languages — the same way the floor is pinned.
//!
//! Both schemes sign in the *caller's* domain via `archon_core::crypto::sign_in_domain`,
//! and each prefixes its layout with a one-byte scheme tag ([`possession::SCHEME_TAG`],
//! [`envelope::SCHEME_TAG`]) so a possession proof and an envelope payload in the same
//! domain can never be mistaken for each other.
//!
//! [archon-core]: https://github.com/Bitspark/archon

pub mod envelope;
pub mod login;
pub mod possession;
