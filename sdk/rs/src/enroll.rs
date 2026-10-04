//! Key enrollment — THIS NEW KEY BELONGS TO THIS ACCOUNT (ADR 0010 §7; `docs/request.md` §6,
//! PROVISIONAL until ADR 0010 §8's gate is met).
//!
//! Login has a person approve a browser key. Enrollment is a different statement: a NEW key
//! proves its own possession, while a separate authority — a session, or a bootstrap credential
//! — says whose key it becomes. That authority lives in the service's pending transaction
//! record, never in this proof: the service creates the record only after validating the
//! authority, and the verifier rebuilds the binding from that record and its configured
//! audience. A completion request names the transaction and carries the proof, nothing more.
//!
//! The proof is the possession scheme with the server's fresh nonce, in [`DOMAIN`], over
//!
//! ```text
//! version ‖ u16be(len purpose) ‖ purpose ‖ u16be(len audience) ‖ audience
//!         ‖ u16be(len transaction) ‖ transaction ‖ new_key[32] ‖ intent_digest[32]
//! ```
//!
//! The intent digest is the service's SHA-256 of its immutable enrollment intent; archon binds
//! the 32 bytes and never reads what they digest. Enrollment shows that an account and a key
//! are associated — not that the key is non-exportable, lives on one device, or is used by one
//! process.

use archon_core::crypto::{public_key_from_seed, PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE};

use crate::possession;
use crate::signer::{sign_with, Signer, SigningRequest};

/// The RFC 8032 context every enrollment proof is made in.
pub const DOMAIN: &str = "archon-enroll/1";

/// The first byte of every enrollment binding.
pub const VERSION: u8 = 0x01;

/// The longest purpose, in bytes.
pub const MAX_PURPOSE_SIZE: usize = 255;

/// The longest transaction id, in bytes.
pub const MAX_TRANSACTION_SIZE: usize = 255;

/// The intent digest's length: a SHA-256.
pub const DIGEST_SIZE: usize = 32;

/// A pending enrollment as the service recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The server's fresh entropy, at least the possession scheme's 16 bytes.
    pub nonce: Vec<u8>,
    /// The pending transaction's id, `1..=MAX_TRANSACTION_SIZE` bytes, opaque.
    pub transaction: Vec<u8>,
    /// `"add-key"`, `"rotate"`, `"recover"`, …: `1..=MAX_PURPOSE_SIZE` bytes, no control
    /// characters.
    pub purpose: String,
    /// The public key being enrolled, exactly `PUBLIC_KEY_SIZE` bytes.
    pub new_key: Vec<u8>,
    /// SHA-256 of the service's immutable intent bytes, exactly [`DIGEST_SIZE`] bytes.
    pub intent_digest: Vec<u8>,
}

/// The bytes an enrollment proof is bound to, for `req` at `audience`. Errors on a purpose that
/// is empty, over [`MAX_PURPOSE_SIZE`] or carrying a control character (U+0000–U+001F,
/// U+007F); an audience that is empty or carrying a control character; a transaction id that is
/// empty or over [`MAX_TRANSACTION_SIZE`]; a new key or intent digest of the wrong size; or a
/// binding that would not fit the possession scheme's u16 field. (A `&str` is UTF-8 by
/// construction; a lane that receives bytes must refuse invalid UTF-8 before it gets here.)
pub fn binding(audience: &str, req: &Request) -> Result<Vec<u8>, String> {
    check_text("purpose", &req.purpose)?;
    if req.purpose.len() > MAX_PURPOSE_SIZE {
        return Err(format!(
            "enroll: purpose is {} bytes, want 1..={MAX_PURPOSE_SIZE}",
            req.purpose.len()
        ));
    }
    check_text("audience", audience)?;
    if req.transaction.is_empty() || req.transaction.len() > MAX_TRANSACTION_SIZE {
        return Err(format!(
            "enroll: transaction is {} bytes, want 1..={MAX_TRANSACTION_SIZE}",
            req.transaction.len()
        ));
    }
    if req.new_key.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "enroll: new key is {} bytes, want {PUBLIC_KEY_SIZE}",
            req.new_key.len()
        ));
    }
    if req.intent_digest.len() != DIGEST_SIZE {
        return Err(format!(
            "enroll: intent digest is {} bytes, want {DIGEST_SIZE}",
            req.intent_digest.len()
        ));
    }
    let mut out = Vec::with_capacity(
        1 + 2
            + req.purpose.len()
            + 2
            + audience.len()
            + 2
            + req.transaction.len()
            + PUBLIC_KEY_SIZE
            + DIGEST_SIZE,
    );
    out.push(VERSION);
    put_field(&mut out, req.purpose.as_bytes());
    put_field(&mut out, audience.as_bytes());
    put_field(&mut out, &req.transaction);
    out.extend_from_slice(&req.new_key);
    out.extend_from_slice(&req.intent_digest);
    if out.len() > possession::MAX_FIELD_SIZE {
        return Err(format!(
            "enroll: binding is {} bytes, over the possession scheme's {}",
            out.len(),
            possession::MAX_FIELD_SIZE
        ));
    }
    Ok(out)
}

/// The enrollment proof: possession by the key behind `seed` — which must be `req.new_key` —
/// in [`DOMAIN`], over `req.nonce` and `binding(audience, req)`. A seed whose public key is not
/// the new key is an error: only the key being enrolled can prove it holds itself.
pub fn prove(
    seed: &[u8; SEED_SIZE],
    audience: &str,
    req: &Request,
) -> Result<[u8; SIGNATURE_SIZE], String> {
    if public_key_from_seed(seed)[..] != req.new_key[..] {
        return Err("enroll: seed is not the new key the request names".to_string());
    }
    let bound = binding(audience, req)?;
    possession::prove(seed, DOMAIN, &req.nonce, &bound)
}

/// Whether `signature` is the enrollment proof by `req.new_key` for `req` at `audience`. Total.
pub fn verify(audience: &str, req: &Request, signature: &[u8]) -> bool {
    match binding(audience, req) {
        Ok(bound) => possession::verify(&req.new_key, DOMAIN, &req.nonce, &bound, signature),
        Err(_) => false,
    }
}

/// The signing request the enrollment proof needs (ADR 0009 §4). Pure. The expected key is
/// `req.new_key`, so only that key's signer can complete it — [`prove`]'s refusal of any other
/// seed, carried into the request itself. Complete it with [`possession::complete`].
pub fn prepare(audience: &str, req: &Request) -> Result<SigningRequest, String> {
    let bound = binding(audience, req)?;
    let new_key: [u8; PUBLIC_KEY_SIZE] = req.new_key[..]
        .try_into()
        .map_err(|_| "enroll: new key is not 32 bytes".to_string())?;
    possession::prepare(&new_key, DOMAIN, &req.nonce, &bound)
}

/// [`prove`] through a signer instead of a seed. A signer for any other key is refused.
pub async fn prove_with<S: Signer>(
    signer: &S,
    audience: &str,
    req: &Request,
) -> Result<[u8; SIGNATURE_SIZE], String> {
    let request = prepare(audience, req)?;
    let signature = sign_with(signer, &request).await?;
    possession::complete(&request, &signature)
}

fn check_text(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > possession::MAX_FIELD_SIZE {
        return Err(format!(
            "enroll: {what} is {} bytes, want 1..={}",
            s.len(),
            possession::MAX_FIELD_SIZE
        ));
    }
    if let Some(c) = s.chars().find(|c| (*c as u32) < 0x20 || *c == '\u{7f}') {
        return Err(format!(
            "enroll: {what} carries a control character U+{:04X}",
            c as u32
        ));
    }
    Ok(())
}

/// `u16be(len field) ‖ field`. Callers have bounded `field.len()`.
fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_N: [u8; 32] = [0x44; 32];
    const AUDIENCE: &str = "https://dawn.example/api";

    fn request() -> Request {
        Request {
            nonce: vec![0xcc; 16],
            transaction: b"txn-1".to_vec(),
            purpose: "add-key".to_string(),
            new_key: public_key_from_seed(&SEED_N).to_vec(),
            intent_digest: vec![0x5f; 32],
        }
    }

    // The oversize refusal the vectors leave to the lanes: an audience that makes the binding
    // exceed the possession scheme's u16 field.
    #[test]
    fn a_binding_over_the_possession_field_is_refused() {
        let room = possession::MAX_FIELD_SIZE - (1 + 2 + 7 + 2 + 2 + 5 + 32 + 32);
        assert!(binding(&"a".repeat(room), &request()).is_ok());
        assert!(binding(&"a".repeat(room + 1), &request()).is_err());
    }

    #[test]
    fn proves_and_verifies_and_every_field_binds() {
        let req = request();
        let sig = prove(&SEED_N, AUDIENCE, &req).unwrap();
        assert!(verify(AUDIENCE, &req, &sig));
        let mut other = req.clone();
        other.purpose = "rotate".to_string();
        assert!(!verify(AUDIENCE, &other, &sig));
        assert!(prove(&[0x11; 32], AUDIENCE, &req).is_err());
    }
}
