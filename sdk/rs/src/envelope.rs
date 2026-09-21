//! The signed envelope — *these bytes, signed by this key, in this domain.*
//!
//! A fixed binary container, JWS-shaped and deliberately not JWT-shaped:
//!
//! ```text
//! "arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ signature[64] ‖ payload
//! ```
//!
//! where `signature = sign_in_domain(seed, domain, SCHEME_TAG ‖ payload)`. The domain
//! is bound cryptographically (it is the RFC 8032 context), the public key is bound by
//! verification, and the payload is opaque: the envelope says nothing about what it
//! means. **What is not here, on purpose:** expiry, issuer, audience, key-id, nonce.
//! Each is either policy — whose clock, whose trust? — or a second spelling of the key,
//! and both belong to the consumer.
//!
//! [`open`] takes the domain the *verifier* expects and refuses an envelope that claims
//! another. The verifier chooses the domain; an envelope never gets to choose it for
//! them. Whether to trust the key it names is, again, the verifier's.

use archon_core::crypto::{
    sign_in_domain, verify_in_domain, MAX_DOMAIN_SIZE, PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE,
};

/// The first four bytes of every envelope.
pub const MAGIC: &[u8; 4] = b"arcn";
/// The envelope format version.
pub const VERSION: u8 = 0x01;
/// The first byte of every signed envelope message. Distinct from
/// [`crate::possession::SCHEME_TAG`].
pub const SCHEME_TAG: u8 = 0x02;

/// What [`open`] returns: the sealing key and the payload, both verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The public key that sealed the envelope. Trusting it is the caller's decision.
    pub pubkey: [u8; PUBLIC_KEY_SIZE],
    /// The payload, verbatim.
    pub payload: Vec<u8>,
}

/// Seal `payload` in `domain` with the key behind `seed`. Errors on an invalid domain
/// (see [`archon_core::crypto::sign_in_domain`]). An empty payload is allowed — the
/// signed message is never empty because of the scheme tag.
pub fn seal(seed: &[u8; SEED_SIZE], domain: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let signature = sign_in_domain(seed, domain, &message_bytes(payload))?;
    let pubkey = archon_core::crypto::public_key_from_seed(seed);
    let d = domain.as_bytes();
    let mut out =
        Vec::with_capacity(4 + 1 + 1 + d.len() + PUBLIC_KEY_SIZE + SIGNATURE_SIZE + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(d.len() as u8); // ≤ 255: sign_in_domain has already checked it
    out.extend_from_slice(d);
    out.extend_from_slice(&pubkey);
    out.extend_from_slice(&signature);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Open `envelope`, which the caller expects to be sealed in `domain`. Errors — never
/// returns a payload — when the bytes are not an envelope (magic, version, length), the
/// envelope claims a different domain, or the signature does not verify.
pub fn open(envelope: &[u8], domain: &str) -> Result<Opened, String> {
    let mut at = 0;
    let take = |at: &mut usize, n: usize| -> Result<&[u8], String> {
        let end = *at + n;
        if end > envelope.len() {
            return Err(format!("envelope truncated at byte {}", envelope.len()));
        }
        let s = &envelope[*at..end];
        *at = end;
        Ok(s)
    };
    if take(&mut at, 4)? != MAGIC {
        return Err("not an envelope: bad magic".to_string());
    }
    let version = take(&mut at, 1)?[0];
    if version != VERSION {
        return Err(format!("unsupported envelope version {version}"));
    }
    let dlen = take(&mut at, 1)?[0] as usize;
    if dlen == 0 || dlen > MAX_DOMAIN_SIZE {
        return Err(format!("envelope domain length {dlen} out of range"));
    }
    let claimed = take(&mut at, dlen)?;
    if claimed != domain.as_bytes() {
        return Err("envelope claims a different domain".to_string());
    }
    let mut pubkey = [0u8; PUBLIC_KEY_SIZE];
    pubkey.copy_from_slice(take(&mut at, PUBLIC_KEY_SIZE)?);
    let signature = take(&mut at, SIGNATURE_SIZE)?;
    let payload = &envelope[at..];
    if !verify_in_domain(&pubkey, domain, &message_bytes(payload), signature) {
        return Err("envelope signature does not verify".to_string());
    }
    Ok(Opened {
        pubkey,
        payload: payload.to_vec(),
    })
}

/// The pinned layout of what gets signed: the scheme tag, then the payload verbatim.
pub fn message_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(SCHEME_TAG);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use archon_core::crypto::public_key_from_seed;

    const D: &str = "archon/test/env";

    #[test]
    fn seals_and_opens() {
        let seed = [0x09u8; SEED_SIZE];
        let env = seal(&seed, D, b"payload").unwrap();
        let o = open(&env, D).unwrap();
        assert_eq!(o.pubkey, public_key_from_seed(&seed));
        assert_eq!(o.payload, b"payload");
        assert!(open(&seal(&seed, D, b"").unwrap(), D)
            .unwrap()
            .payload
            .is_empty());
    }

    #[test]
    fn refuses_every_tamper() {
        let seed = [0x09u8; SEED_SIZE];
        let env = seal(&seed, D, b"payload").unwrap();
        assert!(
            open(&env, "archon/test/other").is_err(),
            "verifier expects another domain"
        );
        let mut t = env.clone();
        *t.last_mut().unwrap() ^= 0x01;
        assert!(open(&t, D).is_err(), "payload tampered");
        let mut t = env.clone();
        t[0] = b'x';
        assert!(open(&t, D).is_err(), "bad magic");
        let mut t = env.clone();
        t[4] = 0x02;
        assert!(open(&t, D).is_err(), "unknown version");
        assert!(open(&env[..env.len() - 8], D).is_err(), "truncated");
        assert!(open(&env[..10], D).is_err(), "far too short");
        let mut t = env.clone();
        t[6] ^= 0x01; // first byte of the domain
        assert!(open(&t, D).is_err(), "domain bytes altered");
        // A different key's signature over the same payload does not open under the
        // original key's envelope header (the pubkey field must match the signer).
        let other = seal(&[0x0au8; SEED_SIZE], D, b"payload").unwrap();
        let mut t = env.clone();
        let sig_at = 4 + 1 + 1 + D.len() + PUBLIC_KEY_SIZE;
        t[sig_at..sig_at + SIGNATURE_SIZE].copy_from_slice(&other[sig_at..sig_at + SIGNATURE_SIZE]);
        assert!(open(&t, D).is_err(), "signature from another key");
    }
}
