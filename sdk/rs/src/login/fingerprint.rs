//! The transaction fingerprint a person compares before approving a login (`docs/login.md` §5.3).

use sha2::{Digest, Sha256};

use super::{binding, put_field, Request, MAX_FIELD_SIZE, ROLE_LOGIN};
use crate::possession::MIN_NONCE_SIZE;

/// The label the transaction fingerprint's digest is computed under (`docs/login.md` §5.3). It
/// is not an RFC 8032 context: nothing is signed with it, and no login proof's bytes are ever a
/// fingerprint's input or the other way round.
pub const FINGERPRINT_DOMAIN: &str = "archon-login-fingerprint/1";

/// The login's transaction fingerprint (`docs/login.md` §5.3), what a person compares before
/// approving: the page that began the login computes it from its own K and the begin response,
/// the CLI from the exact request it is about to sign, and the two agree only if every field
/// the login proof binds — audience, K, id, scope, validity — and the nonce are the same on both
/// sides. It is the first 16 bytes (128 bits) of
///
/// ```text
/// SHA-256( u16be(len domain) ‖ domain ‖ u16be(len nonce) ‖ nonce ‖ binding(ROLE_LOGIN, audience, req) )
/// ```
///
/// with domain [`FINGERPRINT_DOMAIN`] — an encoding of its own beside the proof's, pinned by
/// `vectors/login.json`'s `login_fingerprint` family. Errors on everything
/// [`binding`]`(ROLE_LOGIN, …)` errors on, and on a nonce shorter than
/// [`MIN_NONCE_SIZE`](crate::possession::MIN_NONCE_SIZE) or longer than the u16 prefix allows.
/// Total: it never panics.
pub fn fingerprint(audience: &str, req: &Request) -> Result<[u8; 16], String> {
    let bound = binding(ROLE_LOGIN, audience, req)?;
    if req.nonce.len() < MIN_NONCE_SIZE || req.nonce.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "login: nonce is {} bytes, want {MIN_NONCE_SIZE}..={MAX_FIELD_SIZE}",
            req.nonce.len()
        ));
    }
    let mut input =
        Vec::with_capacity(2 + FINGERPRINT_DOMAIN.len() + 2 + req.nonce.len() + bound.len());
    put_field(&mut input, FINGERPRINT_DOMAIN.as_bytes());
    put_field(&mut input, &req.nonce);
    input.extend_from_slice(&bound);
    let digest = Sha256::digest(&input);
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&digest[..16]);
    Ok(fp)
}

/// `fp` as a person reads and compares it (`docs/login.md` §5.3): its 32 lowercase hex digits
/// in eight groups of four, separated by single ASCII spaces —
/// `7a91 b2c3 d4e5 f607 1829 3a4b 5c6d 7e8f`. The three lanes spell it identically, so the
/// page's rendering and the CLI's can be compared character by character.
pub fn format_fingerprint(fp: &[u8; 16]) -> String {
    let mut out = String::with_capacity(39);
    for (i, pair) in fp.chunks(2).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02x}{:02x}", pair[0], pair[1]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::ROLE_COLLECT;
    use super::*;
    use archon_core::crypto::public_key_from_seed;

    const SEED_P: [u8; 32] = [0x11; 32];
    const SEED_K: [u8; 32] = [0x22; 32];
    const AUDIENCE: &str = "https://dawn.example/api";

    fn request() -> Request {
        Request {
            id: b"req-1".to_vec(),
            nonce: vec![0xaa; 16],
            browser: public_key_from_seed(&SEED_K).to_vec(),
            scope: vec!["read:projects".into(), "read:campaigns".into()],
            valid_for: 28800,
        }
    }

    /// The digest recomputed from §5.3 with the domain spelled out here, not taken from the
    /// constant, so a change to either is caught.
    #[test]
    fn layout() {
        let req = request();
        let fp = fingerprint(AUDIENCE, &req).unwrap();
        let bound = binding(ROLE_LOGIN, AUDIENCE, &req).unwrap();
        let domain = b"archon-login-fingerprint/1";
        let mut input = (domain.len() as u16).to_be_bytes().to_vec();
        input.extend_from_slice(domain);
        input.extend_from_slice(&(req.nonce.len() as u16).to_be_bytes());
        input.extend_from_slice(&req.nonce);
        let prefix = input.clone();
        input.extend_from_slice(&bound);
        assert_eq!(fp[..], Sha256::digest(&input)[..16]);
        assert_eq!(FINGERPRINT_DOMAIN.as_bytes(), domain);
        // The login role, never the collect role.
        let mut collect = prefix;
        collect.extend_from_slice(&binding(ROLE_COLLECT, AUDIENCE, &req).unwrap());
        assert_ne!(fp[..], Sha256::digest(&collect)[..16]);
    }

    /// The comparison is only worth making if a substitution of any field the proof binds, or
    /// of the nonce, changes what the person reads.
    #[test]
    fn every_field_changes_it() {
        let base = fingerprint(AUDIENCE, &request()).unwrap();
        assert_eq!(base, fingerprint(AUDIENCE, &request()).unwrap());
        assert_ne!(
            base,
            fingerprint("https://evil.example/api", &request()).unwrap()
        );
        type Tamper = (&'static str, Box<dyn Fn(&mut Request)>);
        let tampers: Vec<Tamper> = vec![
            (
                "browser",
                Box::new(|r| r.browser = public_key_from_seed(&SEED_P).to_vec()),
            ),
            ("id", Box::new(|r| r.id = b"req-2".to_vec())),
            ("nonce", Box::new(|r| r.nonce = vec![0xab; 16])),
            ("nonce length", Box::new(|r| r.nonce = vec![0xaa; 17])),
            ("scope order", Box::new(|r| r.scope.reverse())),
            (
                "scope entry",
                Box::new(|r| r.scope[1] = "write:campaigns".into()),
            ),
            ("scope extra", Box::new(|r| r.scope.push("admin".into()))),
            ("valid_for", Box::new(|r| r.valid_for += 1)),
        ];
        for (name, modify) in tampers {
            let mut r = request();
            modify(&mut r);
            assert_ne!(
                base,
                fingerprint(AUDIENCE, &r).unwrap(),
                "{name} did not change the fingerprint"
            );
        }
    }

    /// What the vectors do not carry — the nonce over the u16 field, a 130 KB vector — beside
    /// the shorter refusals they do.
    #[test]
    fn refusals() {
        type Case = (&'static str, &'static str, Box<dyn Fn(&mut Request)>);
        let cases: Vec<Case> = vec![
            ("short nonce", AUDIENCE, Box::new(|r| r.nonce.truncate(15))),
            ("empty nonce", AUDIENCE, Box::new(|r| r.nonce.clear())),
            (
                "nonce over the u16 field",
                AUDIENCE,
                Box::new(|r| r.nonce = vec![0; MAX_FIELD_SIZE + 1]),
            ),
            ("empty audience", "", Box::new(|_| {})),
            (
                "browser wrong size",
                AUDIENCE,
                Box::new(|r| r.browser.truncate(31)),
            ),
            ("empty id", AUDIENCE, Box::new(|r| r.id.clear())),
            ("zero validity", AUDIENCE, Box::new(|r| r.valid_for = 0)),
        ];
        for (name, aud, modify) in cases {
            let mut r = request();
            modify(&mut r);
            assert!(fingerprint(aud, &r).is_err(), "{name}: not refused");
        }
        let mut r = request();
        r.nonce = vec![0; MAX_FIELD_SIZE];
        assert!(
            fingerprint(AUDIENCE, &r).is_ok(),
            "a nonce of exactly the u16 field was refused"
        );
    }

    #[test]
    fn display_form() {
        let seq: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            format_fingerprint(&seq),
            "0001 0203 0405 0607 0809 0a0b 0c0d 0e0f"
        );
        assert_eq!(
            format_fingerprint(&[0xff; 16]),
            "ffff ffff ffff ffff ffff ffff ffff ffff"
        );
        let example = [
            0x7a, 0x91, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d,
            0x7e, 0x8f,
        ];
        assert_eq!(
            format_fingerprint(&example),
            "7a91 b2c3 d4e5 f607 1829 3a4b 5c6d 7e8f"
        );
    }
}
