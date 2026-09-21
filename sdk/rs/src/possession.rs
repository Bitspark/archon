//! Proof of possession — *can they sign, right now, for this channel?*
//!
//! The challenger picks a `nonce` (fresh entropy, ≥ 16 bytes — its own, never this
//! crate's) and a `binding` (something only this channel has: a session key, a TLS
//! exporter, the server's identity — the transport's, never this crate's). The prover
//! signs a fixed layout of both in the protocol's domain; the challenger verifies with
//! the prover's public key.
//!
//! **The binding is what makes this a proof.** A signed nonce alone is relayable: an
//! attacker facing the server as the victim forwards the server's nonce to the victim
//! under some pretext, gets it signed, and presents the signature. Bound to the channel,
//! the signature is worthless anywhere else. So an empty binding is refused outright —
//! the thing it would produce looks like a proof and is not one.
//!
//! The signed bytes are `SCHEME_TAG ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖
//! binding`, signed with `archon_core::crypto::sign_in_domain` in the caller's domain.
//! The tag keeps a possession message and an [envelope](crate::envelope) payload in the
//! same domain from ever being the same bytes.

use archon_core::crypto::{sign_in_domain, verify_in_domain, SEED_SIZE, SIGNATURE_SIZE};

/// The first byte of every possession message. Distinct from
/// [`crate::envelope::SCHEME_TAG`].
pub const SCHEME_TAG: u8 = 0x01;

/// The shortest nonce accepted, in bytes. Below this a proof is guessable, so it is
/// refused rather than weakened.
pub const MIN_NONCE_SIZE: usize = 16;

/// The longest nonce or binding, in bytes — the u16 length prefix's bound.
pub const MAX_FIELD_SIZE: usize = u16::MAX as usize;

/// Prove possession of the key behind `seed` to a challenger who supplied `nonce` and
/// `binding`, in `domain`. Errors on an invalid domain (see
/// [`archon_core::crypto::sign_in_domain`]), a nonce shorter than [`MIN_NONCE_SIZE`], an
/// empty binding, or either field over [`MAX_FIELD_SIZE`].
pub fn prove(
    seed: &[u8; SEED_SIZE],
    domain: &str,
    nonce: &[u8],
    binding: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], String> {
    let message = message_bytes(nonce, binding)?;
    sign_in_domain(seed, domain, &message)
}

/// Verify a possession proof: `signature` was made by the key behind `pubkey` over this
/// `nonce` and `binding` in `domain`. Total: every shape failure — bad domain, short
/// nonce, empty binding, wrong-sized key or signature — is `false`.
pub fn verify(pubkey: &[u8], domain: &str, nonce: &[u8], binding: &[u8], signature: &[u8]) -> bool {
    match message_bytes(nonce, binding) {
        Ok(message) => verify_in_domain(pubkey, domain, &message, signature),
        Err(_) => false,
    }
}

/// The pinned layout of what gets signed. Public so a consumer can pin it too.
pub fn message_bytes(nonce: &[u8], binding: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() < MIN_NONCE_SIZE {
        return Err(format!(
            "nonce is {} bytes, min {MIN_NONCE_SIZE}",
            nonce.len()
        ));
    }
    if nonce.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "nonce is {} bytes, max {MAX_FIELD_SIZE}",
            nonce.len()
        ));
    }
    if binding.is_empty() {
        return Err("binding is empty — an unbound proof is not a proof".to_string());
    }
    if binding.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "binding is {} bytes, max {MAX_FIELD_SIZE}",
            binding.len()
        ));
    }
    let mut out = Vec::with_capacity(1 + 2 + nonce.len() + 2 + binding.len());
    out.push(SCHEME_TAG);
    out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(binding.len() as u16).to_be_bytes());
    out.extend_from_slice(binding);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archon_core::crypto::{public_key_from_seed, sign, sign_in_domain};

    const D: &str = "archon/test/pop";

    #[test]
    fn proves_and_refuses_every_substitution() {
        let seed = [0x09u8; SEED_SIZE];
        let pk = public_key_from_seed(&seed);
        let nonce = [0xaau8; 16];
        let binding = b"session:1";
        let sig = prove(&seed, D, &nonce, binding).unwrap();
        assert!(verify(&pk, D, &nonce, binding, &sig));
        assert!(!verify(&pk, D, &[0xabu8; 16], binding, &sig), "other nonce");
        assert!(!verify(&pk, D, &nonce, b"session:2", &sig), "other binding");
        assert!(
            !verify(&pk, "archon/test/other", &nonce, binding, &sig),
            "other domain"
        );
        assert!(!verify(&[0u8; 32], D, &nonce, binding, &sig), "other key");
        // A raw signature, or a domain signature over the bare nonce, is not a proof.
        let m = message_bytes(&nonce, binding).unwrap();
        assert!(!verify(&pk, D, &nonce, binding, &sign(&seed, &m)));
        assert!(!verify(
            &pk,
            D,
            &nonce,
            binding,
            &sign_in_domain(&seed, D, &nonce).unwrap()
        ));
    }

    #[test]
    fn refuses_short_nonce_and_empty_binding() {
        let seed = [0x09u8; SEED_SIZE];
        let pk = public_key_from_seed(&seed);
        assert!(prove(&seed, D, &[0xaau8; 15], b"b").is_err());
        assert!(prove(&seed, D, &[0xaau8; 16], b"").is_err());
        assert!(prove(&seed, "", &[0xaau8; 16], b"b").is_err());
        assert!(!verify(&pk, D, &[0xaau8; 15], b"b", &[0u8; SIGNATURE_SIZE]));
        assert!(!verify(&pk, D, &[0xaau8; 16], b"", &[0u8; SIGNATURE_SIZE]));
    }

    #[test]
    fn layout_is_the_pinned_one() {
        let m = message_bytes(&[0x11u8; 16], b"ab").unwrap();
        let mut want = vec![SCHEME_TAG, 0x00, 0x10];
        want.extend_from_slice(&[0x11u8; 16]);
        want.extend_from_slice(&[0x00, 0x02, b'a', b'b']);
        assert_eq!(m, want);
    }
}
