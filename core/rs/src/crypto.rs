//! Ed25519 sign / verify over canonical bytes (RFC 8032).
//!
//! Wraps `ed25519-dalek`. [`verify`] collapses every shape failure (wrong-sized key
//! or signature, malformed point) into a single `false` so callers can treat all
//! "bad signature" cases uniformly. These are the generic primitives the
//! callers sign and check over — no authority vocabulary of any kind.
//!
//! Two ways to sign, deliberately:
//!
//! - [`sign`] / [`verify`] — **raw**: pure Ed25519 over exactly the bytes given. The
//!   caller owns separation; two protocols signing overlapping byte layouts with one key
//!   can replay each other's signatures. This is what every consumer's on-disk
//!   signatures are today, and it stays.
//! - [`sign_in_domain`] / [`verify_in_domain`] — **domain-separated**: Ed25519ph with a
//!   context string (RFC 8032 §5.1), the *domain*, mixed into the hash. A signature made
//!   in one domain verifies in no other and never as a raw signature, and a raw
//!   signature verifies in no domain — cryptographically, whatever the bytes. One key,
//!   many protocols, no cross-talk: the default for any protocol that has no bytes on
//!   disk yet. The domain is the caller's (`<repo>/<purpose>/v<n>` by convention);
//!   archon neither knows nor registers domains.

use ed25519_dalek::{
    Digest, Sha512, Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};

/// The length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH;
/// The length of an Ed25519 signature, in bytes.
pub const SIGNATURE_SIZE: usize = SIGNATURE_LENGTH;
/// The length of an Ed25519 seed (private key), in bytes.
pub const SEED_SIZE: usize = SECRET_KEY_LENGTH;
/// The longest domain (RFC 8032 context) a signature can be made in, in bytes.
pub const MAX_DOMAIN_SIZE: usize = 255;

/// Derives the Ed25519 public key for a 32-byte `seed`.
pub fn public_key_from_seed(seed: &[u8; SEED_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Signs `message` with the key derived from `seed`, returning the 64-byte
/// signature (the message is whatever canonical byte sequence the caller defines).
pub fn sign(seed: &[u8; SEED_SIZE], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Verifies `signature` over `message` under the public key `pubkey`. Returns
/// `false` on any shape failure rather than erroring.
pub fn verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key_bytes: [u8; PUBLIC_KEY_SIZE] = match pubkey.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    key.verify(message, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// Signs `message` with the key derived from `seed` **in `domain`** (Ed25519ph with the
/// domain as the RFC 8032 context). Errors — never silently signs raw — when the domain
/// is empty or longer than [`MAX_DOMAIN_SIZE`] bytes: an empty domain is "sign in no
/// domain", which is exactly what this function exists to make impossible.
pub fn sign_in_domain(
    seed: &[u8; SEED_SIZE],
    domain: &str,
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], String> {
    check_domain(domain)?;
    SigningKey::from_bytes(seed)
        .sign_prehashed(Sha512::new().chain_update(message), Some(domain.as_bytes()))
        .map(|s| s.to_bytes())
        .map_err(|e| e.to_string())
}

/// Verifies `signature` over `message` **in `domain`** under `pubkey`. Total, like
/// [`verify`]: every shape failure — including an empty or over-long domain — is
/// `false`. A raw signature over the same message is `false` here; a signature from any
/// other domain is `false` here.
pub fn verify_in_domain(pubkey: &[u8], domain: &str, message: &[u8], signature: &[u8]) -> bool {
    if check_domain(domain).is_err() {
        return false;
    }
    let key_bytes: [u8; PUBLIC_KEY_SIZE] = match pubkey.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    key.verify_prehashed(
        Sha512::new().chain_update(message),
        Some(domain.as_bytes()),
        &Signature::from_bytes(&sig_bytes),
    )
    .is_ok()
}

/// A domain is 1..=255 bytes — the RFC 8032 context bound, with the empty context
/// excluded on purpose (see [`sign_in_domain`]).
fn check_domain(domain: &str) -> Result<(), String> {
    match domain.len() {
        0 => Err("domain is empty".to_string()),
        n if n > MAX_DOMAIN_SIZE => Err(format!("domain is {n} bytes, max {MAX_DOMAIN_SIZE}")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separates_and_raw_never_crosses() {
        let seed = [0x09u8; SEED_SIZE];
        let pk = public_key_from_seed(&seed);
        let msg = b"the law laid down";
        let sig_a = sign_in_domain(&seed, "archon/test/a", msg).unwrap();
        assert!(verify_in_domain(&pk, "archon/test/a", msg, &sig_a));
        assert!(!verify_in_domain(&pk, "archon/test/b", msg, &sig_a)); // other domain
        assert!(!verify(&pk, msg, &sig_a)); // never raw
        let raw = sign(&seed, msg);
        assert!(!verify_in_domain(&pk, "archon/test/a", msg, &raw)); // raw never in-domain
        assert!(!verify_in_domain(&pk, "archon/test/a", b"other", &sig_a));
        assert!(!verify_in_domain(
            &[0u8; PUBLIC_KEY_SIZE],
            "archon/test/a",
            msg,
            &sig_a
        ));
    }

    #[test]
    fn domain_bounds() {
        let seed = [0x09u8; SEED_SIZE];
        let pk = public_key_from_seed(&seed);
        assert!(sign_in_domain(&seed, "", b"m").is_err());
        assert!(!verify_in_domain(&pk, "", b"m", &[0u8; SIGNATURE_SIZE]));
        let max = "d".repeat(MAX_DOMAIN_SIZE);
        let sig = sign_in_domain(&seed, &max, b"m").unwrap();
        assert!(verify_in_domain(&pk, &max, b"m", &sig));
        let over = "d".repeat(MAX_DOMAIN_SIZE + 1);
        assert!(sign_in_domain(&seed, &over, b"m").is_err());
        assert!(!verify_in_domain(&pk, &over, b"m", &sig));
    }

    #[test]
    fn sign_verify_round_trip() {
        let seed = [0x09u8; SEED_SIZE];
        let pk = public_key_from_seed(&seed);
        let msg = b"the law laid down";
        let sig = sign(&seed, msg);
        assert!(verify(&pk, msg, &sig));
        // a different message, a flipped sig byte, and a wrong key all fail.
        assert!(!verify(&pk, b"other", &sig));
        let mut bad = sig;
        bad[0] ^= 0xff;
        assert!(!verify(&pk, msg, &bad));
        assert!(!verify(&[0u8; PUBLIC_KEY_SIZE], msg, &sig));
    }
}
