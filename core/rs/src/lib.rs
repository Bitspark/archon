//! archon-core — the constellation's identity and crypto layer.
//!
//! **archon is who bears the office; [thesmos] is the law that binds it.** This crate
//! answers *"is this really them?"* — keys, their canonical spellings, and signatures
//! over canonical bytes. It has **no opinion whatsoever** about what any identity is
//! *allowed to do*: `is_root`, admission and grants are thesmos's, and thesmos depends
//! on archon rather than the other way round.
//!
//! Ownership follows the constellation's one-change-authority rule: the owner of a thing
//! is the lowest layer that can define its canonical bytes, validity conditions, success
//! claim and versioning **without higher-layer vocabulary**. Everything here is defined
//! by RFC 8032, RFC 5280 and RFC 5958 — no Bitspark vocabulary at all.
//!
//! [thesmos]: thesmos

pub mod crypto;
pub mod hexbytes;
pub mod keycodec;
pub mod keytext;
