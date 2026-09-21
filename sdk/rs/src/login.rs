//! The archon login scheme — *may this ephemeral key act as me, here, for this, until then?*
//!
//! A browser (any key-less client) holds an ephemeral key **K** and opens a request at a
//! service; the person's CLI, holding **P**, proves to that service that P agrees to let K act
//! there for a stated scope and validity. The proof is the [possession](crate::possession)
//! scheme in the domain [`DOMAIN`], over the server's nonce and a binding that names
//! everything the person approved: the audience the CLI talks to, K, the request, the scope
//! entries and the validity — see `docs/login.md` §3.
//!
//! **The audience is derived, never transported**: the CLI takes it from the URL it was
//! invoked with and the server from its own configuration (`docs/login.md` §2). This module
//! takes it as an argument and binds it; it never reads it off a message. Everything this
//! module refuses to source — the nonce, the id, K, clocks, the delegation's contents,
//! custody, sockets — is an argument or another layer's (ADR 0004, ADR 0007).
//!
//! Two proofs share the layout and differ in a role byte: the login proof
//! ([`ROLE_LOGIN`]) is made by P; the collect proof ([`ROLE_COLLECT`]) is made by K when the
//! browser collects the answer, so a bystander who saw the request id cannot consume the
//! login.

use archon_core::crypto::{public_key_from_seed, PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE};

mod audience;
pub use audience::derive_audience;

use crate::possession;

/// The RFC 8032 context every login-scheme proof is made in.
pub const DOMAIN: &str = "archon-login/1";

/// The binding's first byte for the person's proof (made by P).
pub const ROLE_LOGIN: u8 = 0x01;

/// The binding's first byte for the browser's collect proof (made by K).
pub const ROLE_COLLECT: u8 = 0x02;

/// The longest audience, id or scope entry, in bytes — the u16 length prefix's bound. It
/// also bounds the scope entry count and the whole binding (which must fit the possession
/// scheme's own u16 field).
pub const MAX_FIELD_SIZE: usize = u16::MAX as usize;

/// A pending login as the server issued it and the CLI reads it back (`docs/login.md`
/// §3.1). The nonce is validated by the possession scheme (≥ 16 bytes) at proof time; the
/// other fields by [`binding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The server's, opaque, `1..=MAX_FIELD_SIZE` bytes.
    pub id: Vec<u8>,
    /// The server's fresh entropy, one per request.
    pub nonce: Vec<u8>,
    /// K's public key, exactly `PUBLIC_KEY_SIZE` bytes.
    pub browser: Vec<u8>,
    /// Ordered; each `1..=MAX_FIELD_SIZE` bytes of UTF-8 with no control characters.
    pub scope: Vec<String>,
    /// The delegation's requested lifetime in seconds, `> 0`.
    pub valid_for: u32,
}

/// The bytes both proofs are bound to, for `role` over `audience` and `req`
/// (`docs/login.md` §3.2):
///
/// ```text
/// role ‖ u16be(len audience) ‖ audience ‖ browser[32] ‖ u16be(len id) ‖ id
///      ‖ u16be(count scope) ‖ ( u16be(len entry) ‖ entry )* ‖ u32be(valid_for)
/// ```
///
/// Errors on an unknown role, an empty or oversized audience, an audience or scope entry
/// carrying a control character (U+0000–U+001F, U+007F), an empty scope entry, a browser key
/// of the wrong size, an empty or oversized id, a zero validity, or a binding that would not
/// fit the possession scheme's u16 field. (A `&str` is UTF-8 by construction; a lane that
/// receives bytes must refuse invalid UTF-8 before it gets here.)
pub fn binding(role: u8, audience: &str, req: &Request) -> Result<Vec<u8>, String> {
    if role != ROLE_LOGIN && role != ROLE_COLLECT {
        return Err(format!("login: unknown role 0x{role:02x}"));
    }
    check_text("audience", audience)?;
    if req.browser.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "login: browser key is {} bytes, want {PUBLIC_KEY_SIZE}",
            req.browser.len()
        ));
    }
    if req.id.is_empty() || req.id.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "login: id is {} bytes, want 1..={MAX_FIELD_SIZE}",
            req.id.len()
        ));
    }
    if req.scope.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "login: {} scope entries, want at most {MAX_FIELD_SIZE}",
            req.scope.len()
        ));
    }
    for (i, entry) in req.scope.iter().enumerate() {
        check_text(&format!("scope[{i}]"), entry)?;
    }
    if req.valid_for == 0 {
        return Err("login: valid_for is 0".to_string());
    }

    let mut out =
        Vec::with_capacity(1 + 2 + audience.len() + PUBLIC_KEY_SIZE + 2 + req.id.len() + 2 + 4);
    out.push(role);
    put_field(&mut out, audience.as_bytes());
    out.extend_from_slice(&req.browser);
    put_field(&mut out, &req.id);
    out.extend_from_slice(&(req.scope.len() as u16).to_be_bytes());
    for entry in &req.scope {
        put_field(&mut out, entry.as_bytes());
    }
    out.extend_from_slice(&req.valid_for.to_be_bytes());
    if out.len() > possession::MAX_FIELD_SIZE {
        return Err(format!(
            "login: binding is {} bytes, over the possession scheme's {}",
            out.len(),
            possession::MAX_FIELD_SIZE
        ));
    }
    Ok(out)
}

/// The person's login proof: possession by the key behind `seed`, in [`DOMAIN`], over
/// `req.nonce` and `binding(ROLE_LOGIN, audience, req)`. Errors are [`binding`]'s and the
/// possession scheme's (short nonce).
pub fn prove(
    seed: &[u8; SEED_SIZE],
    audience: &str,
    req: &Request,
) -> Result<[u8; SIGNATURE_SIZE], String> {
    let bound = binding(ROLE_LOGIN, audience, req)?;
    possession::prove(seed, DOMAIN, &req.nonce, &bound)
}

/// Whether `signature` is the login proof by the key behind `pubkey` for `req` at
/// `audience`. Total: every shape failure is `false`.
pub fn verify(pubkey: &[u8], audience: &str, req: &Request, signature: &[u8]) -> bool {
    match binding(ROLE_LOGIN, audience, req) {
        Ok(bound) => possession::verify(pubkey, DOMAIN, &req.nonce, &bound, signature),
        Err(_) => false,
    }
}

/// The browser's collect proof: possession by the key behind `seed` — which must be the key
/// `req` names as `browser` — in [`DOMAIN`], over `req.nonce` and
/// `binding(ROLE_COLLECT, audience, req)`. A seed whose public key is not `req.browser` is an
/// error: the proof is only meaningful from the key the request names.
pub fn prove_collect(
    seed: &[u8; SEED_SIZE],
    audience: &str,
    req: &Request,
) -> Result<[u8; SIGNATURE_SIZE], String> {
    if public_key_from_seed(seed)[..] != req.browser[..] {
        return Err("login: seed is not the browser key the request names".to_string());
    }
    let bound = binding(ROLE_COLLECT, audience, req)?;
    possession::prove(seed, DOMAIN, &req.nonce, &bound)
}

/// Whether `signature` is the collect proof by `req.browser` for `req` at `audience`. Total.
pub fn verify_collect(audience: &str, req: &Request, signature: &[u8]) -> bool {
    match binding(ROLE_COLLECT, audience, req) {
        Ok(bound) => possession::verify(&req.browser, DOMAIN, &req.nonce, &bound, signature),
        Err(_) => false,
    }
}

/// The rule shared by the audience and every scope entry: `1..=MAX_FIELD_SIZE` bytes with no
/// control character (U+0000–U+001F, U+007F). These bytes are displayed verbatim by the CLI
/// before signing; a control character could make the display lie about what is bound.
fn check_text(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "login: {what} is {} bytes, want 1..={MAX_FIELD_SIZE}",
            s.len()
        ));
    }
    if let Some(c) = s.chars().find(|c| (*c as u32) < 0x20 || *c == '\u{7f}') {
        return Err(format!(
            "login: {what} carries a control character U+{:04X}",
            c as u32
        ));
    }
    Ok(())
}

/// `u16be(len field) ‖ field`. Callers have bounded `field.len()` to [`MAX_FIELD_SIZE`].
fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use archon_core::crypto::sign;

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

    #[test]
    fn binding_layout() {
        let req = request();
        let b = binding(ROLE_LOGIN, AUDIENCE, &req).unwrap();
        let mut want = vec![0x01, 0x00, AUDIENCE.len() as u8];
        want.extend_from_slice(AUDIENCE.as_bytes());
        want.extend_from_slice(&req.browser);
        want.extend_from_slice(&[0x00, 0x05]);
        want.extend_from_slice(b"req-1");
        want.extend_from_slice(&[0x00, 0x02, 0x00, 0x0d]);
        want.extend_from_slice(b"read:projects");
        want.extend_from_slice(&[0x00, 0x0e]);
        want.extend_from_slice(b"read:campaigns");
        want.extend_from_slice(&[0x00, 0x00, 0x70, 0x80]);
        assert_eq!(b, want);
        let c = binding(ROLE_COLLECT, AUDIENCE, &req).unwrap();
        assert_eq!(c[0], ROLE_COLLECT);
        assert_eq!(c[1..], b[1..]);
    }

    #[test]
    fn round_trip_and_every_field_binds() {
        let req = request();
        let sig = prove(&SEED_P, AUDIENCE, &req).unwrap();
        let pub_p = public_key_from_seed(&SEED_P);
        assert!(verify(&pub_p, AUDIENCE, &req, &sig));
        let bound = binding(ROLE_LOGIN, AUDIENCE, &req).unwrap();
        assert!(possession::verify(&pub_p, DOMAIN, &req.nonce, &bound, &sig));

        assert!(!verify(&pub_p, "https://evil.example/api", &req, &sig));
        let mut r = request();
        r.browser = pub_p.to_vec();
        assert!(!verify(&pub_p, AUDIENCE, &r, &sig));
        let mut r = request();
        r.id = b"req-2".to_vec();
        assert!(!verify(&pub_p, AUDIENCE, &r, &sig));
        let mut r = request();
        r.nonce = vec![0xab; 16];
        assert!(!verify(&pub_p, AUDIENCE, &r, &sig));
        let mut r = request();
        r.scope.reverse();
        assert!(!verify(&pub_p, AUDIENCE, &r, &sig));
        let mut r = request();
        r.scope.push("admin".into());
        assert!(!verify(&pub_p, AUDIENCE, &r, &sig));
        let mut r = request();
        r.valid_for += 1;
        assert!(!verify(&pub_p, AUDIENCE, &r, &sig));

        assert!(!verify(
            &public_key_from_seed(&SEED_K),
            AUDIENCE,
            &req,
            &sig
        ));
        let msg = possession::message_bytes(&req.nonce, &bound).unwrap();
        assert!(!verify(&pub_p, AUDIENCE, &req, &sign(&SEED_P, &msg)));
        let other = possession::prove(&SEED_P, "archon-login/2", &req.nonce, &bound).unwrap();
        assert!(!verify(&pub_p, AUDIENCE, &req, &other));
        let collect = prove_collect(&SEED_K, AUDIENCE, &req).unwrap();
        assert!(!verify(
            &public_key_from_seed(&SEED_K),
            AUDIENCE,
            &req,
            &collect
        ));
    }

    #[test]
    fn collect() {
        let req = request();
        let sig = prove_collect(&SEED_K, AUDIENCE, &req).unwrap();
        assert!(verify_collect(AUDIENCE, &req, &sig));
        assert!(!verify_collect("https://evil.example/api", &req, &sig));
        let login = prove(&SEED_K, AUDIENCE, &req).unwrap();
        assert!(!verify_collect(AUDIENCE, &req, &login));
        assert!(prove_collect(&SEED_P, AUDIENCE, &req).is_err());
    }

    #[test]
    fn refusals() {
        let pub_p = public_key_from_seed(&SEED_P);
        type Case = (&'static str, &'static str, Box<dyn Fn(&mut Request)>);
        let cases: Vec<Case> = vec![
            ("empty audience", "", Box::new(|_| {})),
            (
                "control char in audience",
                "https://dawn.example/api\n",
                Box::new(|_| {}),
            ),
            (
                "browser wrong size",
                AUDIENCE,
                Box::new(|r| r.browser.truncate(31)),
            ),
            ("empty id", AUDIENCE, Box::new(|r| r.id.clear())),
            (
                "empty scope entry",
                AUDIENCE,
                Box::new(|r| r.scope = vec![String::new()]),
            ),
            (
                "control char in scope",
                AUDIENCE,
                Box::new(|r| r.scope = vec!["read:\u{7}projects".into()]),
            ),
            (
                "DEL in scope",
                AUDIENCE,
                Box::new(|r| r.scope = vec!["read:\u{7f}projects".into()]),
            ),
            ("zero validity", AUDIENCE, Box::new(|r| r.valid_for = 0)),
            (
                "oversized id",
                AUDIENCE,
                Box::new(|r| r.id = vec![1; MAX_FIELD_SIZE + 1]),
            ),
            (
                "binding over the possession bound",
                AUDIENCE,
                Box::new(|r| {
                    r.scope = vec!["a".repeat(MAX_FIELD_SIZE), "b".repeat(MAX_FIELD_SIZE)]
                }),
            ),
        ];
        for (name, aud, modify) in cases {
            let mut r = request();
            modify(&mut r);
            assert!(binding(ROLE_LOGIN, aud, &r).is_err(), "{name}: not refused");
            assert!(
                prove(&SEED_P, aud, &r).is_err(),
                "{name}: prove did not refuse"
            );
            assert!(
                !verify(&pub_p, aud, &r, &[0u8; 64]),
                "{name}: verify returned true"
            );
        }
        assert!(binding(0x03, AUDIENCE, &request()).is_err());
        let mut r = request();
        r.nonce.truncate(15);
        assert!(prove(&SEED_P, AUDIENCE, &r).is_err());
        let mut r = request();
        r.scope.clear();
        assert!(
            binding(ROLE_LOGIN, AUDIENCE, &r).is_ok(),
            "empty scope list is allowed"
        );
    }
}
