//! The signer seam (ADR 0009 §2–4): every helper through a `Signer` produces the SAME bytes the
//! seed functions produce — checked against the vectors, whose signatures OpenSSL derived — and
//! every rule the seam enforces is exercised against a signer that breaks it.

use std::cell::Cell;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use archon_core::crypto::{
    public_key_from_seed, sign, sign_in_domain, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};
use archon_sdk::signer::{
    check_signature, sign_with, Capabilities, Kind, Scheme, SeedSigner, Signer, SigningRequest,
};
use archon_sdk::{envelope, login, possession};
use serde_json::Value;

/// Drives a future that never waits — every signer here answers at once — to completion.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seed32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte seed")
}

fn vectors(name: &str) -> Value {
    let raw = std::fs::read_to_string(format!("../../vectors/{name}")).expect("vectors");
    serde_json::from_str(&raw).expect("json")
}

fn ok_cases<'a>(v: &'a Value, family: &str) -> Vec<&'a Value> {
    v[family]
        .as_array()
        .expect(family)
        .iter()
        .filter(|c| c["result"].get("ok").is_some())
        .collect()
}

fn login_request(r: &Value) -> login::Request {
    login::Request {
        id: unhex(r["id"].as_str().unwrap()),
        nonce: unhex(r["nonce"].as_str().unwrap()),
        browser: unhex(r["browser"].as_str().unwrap()),
        scope: r["scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| String::from_utf8(unhex(s.as_str().unwrap())).unwrap())
            .collect(),
        valid_for: r["valid_for"].as_u64().unwrap() as u32,
    }
}

#[test]
fn through_a_seed_signer_every_helper_reproduces_the_vectors() {
    let sdk = vectors("sdk.json");
    let lv = vectors("login.json");
    let mut checked = 0;
    for c in ok_cases(&sdk, "possession_prove") {
        let s = SeedSigner::new(&seed32(c["seed"].as_str().unwrap()));
        let sig = block_on(possession::prove_with(
            &s,
            c["domain"].as_str().unwrap(),
            &unhex(c["nonce"].as_str().unwrap()),
            &unhex(c["binding"].as_str().unwrap()),
        ))
        .expect("prove_with");
        assert_eq!(
            hex(&sig),
            c["result"]["ok"].as_str().unwrap(),
            "possession {}",
            c["name"]
        );
        checked += 1;
    }
    for c in ok_cases(&sdk, "envelope_seal") {
        let s = SeedSigner::new(&seed32(c["seed"].as_str().unwrap()));
        let env = block_on(envelope::seal_with(
            &s,
            c["domain"].as_str().unwrap(),
            &unhex(c["payload"].as_str().unwrap()),
        ))
        .expect("seal_with");
        assert_eq!(
            hex(&env),
            c["result"]["ok"].as_str().unwrap(),
            "envelope {}",
            c["name"]
        );
        checked += 1;
    }
    for c in ok_cases(&lv, "login_prove") {
        let s = SeedSigner::new(&seed32(c["seed"].as_str().unwrap()));
        let sig = block_on(login::prove_with(
            &s,
            c["audience"].as_str().unwrap(),
            &login_request(&c["request"]),
        ))
        .expect("prove_with");
        assert_eq!(
            hex(&sig),
            c["result"]["ok"].as_str().unwrap(),
            "login {}",
            c["name"]
        );
        checked += 1;
    }
    for c in ok_cases(&lv, "login_collect_prove") {
        let s = SeedSigner::new(&seed32(c["seed"].as_str().unwrap()));
        let sig = block_on(login::prove_collect_with(
            &s,
            c["audience"].as_str().unwrap(),
            &login_request(&c["request"]),
        ))
        .expect("prove_collect_with");
        assert_eq!(
            hex(&sig),
            c["result"]["ok"].as_str().unwrap(),
            "collect {}",
            c["name"]
        );
        checked += 1;
    }
    // A key slip that skipped every case would otherwise pass in silence.
    assert!(checked >= 8, "checked {checked} vector cases");
}

/// A signer that counts its calls and signs however `how` says.
struct Fake<F: Fn(&SigningRequest) -> Vec<u8>> {
    public_key: [u8; PUBLIC_KEY_SIZE],
    capabilities: Capabilities,
    how: F,
    calls: Cell<usize>,
}

impl<F: Fn(&SigningRequest) -> Vec<u8>> Signer for Fake<F> {
    fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key
    }
    fn capabilities(&self) -> Capabilities {
        self.capabilities.clone()
    }
    fn sign(
        &self,
        request: &SigningRequest,
    ) -> impl Future<Output = Result<[u8; SIGNATURE_SIZE], String>> {
        self.calls.set(self.calls.get() + 1);
        let sig = (self.how)(request);
        // A short answer is a malformed signature; it reaches the check as 64 bytes of junk.
        let mut fixed = [0u8; SIGNATURE_SIZE];
        let n = sig.len().min(SIGNATURE_SIZE);
        fixed[..n].copy_from_slice(&sig[..n]);
        std::future::ready(Ok(fixed))
    }
}

fn both() -> Capabilities {
    Capabilities {
        schemes: vec![Kind::Raw, Kind::PhContext],
        domains: None,
    }
}

fn fake<F: Fn(&SigningRequest) -> Vec<u8>>(
    public_key: [u8; PUBLIC_KEY_SIZE],
    capabilities: Capabilities,
    how: F,
) -> Fake<F> {
    Fake {
        public_key,
        capabilities,
        how,
        calls: Cell::new(0),
    }
}

const SEED: [u8; 32] = [7; 32];
const DOMAIN: &str = "archon/test/pop";

#[test]
fn an_out_of_range_request_is_refused_before_the_signer_is_invoked() {
    let f = fake(public_key_from_seed(&SEED), both(), |r| {
        sign(&SEED, &r.message).to_vec()
    });
    assert!(block_on(possession::prove_with(&f, "", &[1; 16], &[1])).is_err());
    assert!(block_on(possession::prove_with(&f, DOMAIN, &[1; 15], &[1])).is_err());
    assert!(block_on(envelope::seal_with(&f, &"d".repeat(256), &[])).is_err());
    assert_eq!(f.calls.get(), 0, "the signer must never have been asked");
}

#[test]
fn a_signer_is_asked_only_for_what_it_says_it_can_do() {
    let public_key = public_key_from_seed(&SEED);
    let request = possession::prepare(&public_key, DOMAIN, &[1; 16], &[1]).unwrap();
    // A raw-only signer — every agent and device ADR 0007 §A measured — is refused for ph.
    let raw_only = fake(
        public_key,
        Capabilities {
            schemes: vec![Kind::Raw],
            domains: None,
        },
        |r| sign(&SEED, &r.message).to_vec(),
    );
    let err = block_on(sign_with(&raw_only, &request)).unwrap_err();
    assert!(err.contains("cannot produce"), "{err}");
    let elsewhere = fake(
        public_key,
        Capabilities {
            schemes: vec![Kind::PhContext],
            domains: Some(vec!["archon/test/other".to_string()]),
        },
        |r| sign_in_domain(&SEED, DOMAIN, &r.message).unwrap().to_vec(),
    );
    let err = block_on(sign_with(&elsewhere, &request)).unwrap_err();
    assert!(err.contains("does not sign in domain"), "{err}");
    let other_key = fake(public_key_from_seed(&[8; 32]), both(), |r| {
        sign(&SEED, &r.message).to_vec()
    });
    let err = block_on(sign_with(&other_key, &request)).unwrap_err();
    assert!(err.contains("not the expected key"), "{err}");
    assert_eq!(
        raw_only.calls.get() + elsewhere.calls.get() + other_key.calls.get(),
        0
    );
}

/// A signer behaviour that breaks the contract one way.
type Liar = Box<dyn Fn(&SigningRequest) -> Vec<u8>>;

#[test]
fn a_signature_is_checked_against_the_request_never_the_signers_word() {
    let public_key = public_key_from_seed(&SEED);
    let request = possession::prepare(&public_key, DOMAIN, &[1; 16], &[1]).unwrap();
    let liars: Vec<(&str, Liar)> = vec![
        (
            "signs with another key",
            Box::new(|r| {
                sign_in_domain(&[8; 32], DOMAIN, &r.message)
                    .unwrap()
                    .to_vec()
            }),
        ),
        (
            "drops the context and signs raw",
            Box::new(|r| sign(&SEED, &r.message).to_vec()),
        ),
        (
            "signs in another domain",
            Box::new(|r| {
                sign_in_domain(&SEED, "archon/test/other", &r.message)
                    .unwrap()
                    .to_vec()
            }),
        ),
        (
            "signs other bytes",
            Box::new(|_| sign_in_domain(&SEED, DOMAIN, &[0]).unwrap().to_vec()),
        ),
        (
            "returns 63 bytes",
            Box::new(|r| sign_in_domain(&SEED, DOMAIN, &r.message).unwrap()[1..].to_vec()),
        ),
    ];
    for (label, how) in liars {
        let f = fake(public_key, both(), &how);
        let err = block_on(sign_with(&f, &request)).unwrap_err();
        assert!(err.contains("does not verify"), "{label}: {err}");
        assert!(
            possession::complete(&request, &how(&request)).is_err(),
            "complete: {label}"
        );
    }
}

#[test]
fn complete_assembles_from_the_request_and_the_seed_signer_is_deterministic() {
    let s = SeedSigner::new(&SEED);
    let request = envelope::prepare_seal(&s.public_key(), "archon/test/env", b"payload").unwrap();
    let first = block_on(s.sign(&request)).unwrap();
    assert_eq!(
        block_on(s.sign(&request)).unwrap(),
        first,
        "signing twice gives the same bytes"
    );
    let env = envelope::complete_seal(&request, &first).unwrap();
    assert_eq!(
        envelope::open(&env, "archon/test/env").unwrap().payload,
        b"payload"
    );
    let not_a_seal = possession::prepare(&s.public_key(), "d", &[0; 16], &[1]).unwrap();
    assert!(envelope::complete_seal(&not_a_seal, &first).is_err());
    assert!(check_signature(&request, &first).is_ok());
    assert!(matches!(request.scheme, Scheme::PhContext { .. }));
}
