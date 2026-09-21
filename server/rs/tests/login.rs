//! The Rust lane's suite, deliberately the same cases as the Go lane's: the three server
//! lanes must agree, and keeping the suites parallel is how a divergence shows up as a
//! failing test rather than as a surprise in production.
//!
//! Every case here plays the browser and the CLI against the handler with the real sdk. The
//! clock and the entropy are injected, so nothing sleeps and nothing flakes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use archon_core::crypto;
use archon_core::keytext;
use archon_sdk::login;
use archon_server::{Config, Handler, Request, Response, COLLECT_HEADER};

const AUDIENCE: &str = "https://dawn.example/api";

/// What an `AdmitAuthority` was handed: the browser key, the principal key, and the authority
/// payload, recorded so a test can assert the law saw exactly what the CLI sent.
type Admitted = Arc<Mutex<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>>>;

fn seed_for(b: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, s) in seed.iter_mut().enumerate() {
        *s = b.wrapping_add(i as u8);
    }
    seed
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A clock the test steps by hand, shared with the handler.
#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1_789_034_640)))
    }
    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

/// Distinct, predictable bytes per call, so an id and a nonce are never accidentally equal.
fn counting_entropy() -> archon_server::Entropy {
    let n = Arc::new(AtomicU64::new(0));
    Box::new(move |b: &mut [u8]| {
        let v = n.fetch_add(1, Ordering::SeqCst) as u8 + 1;
        for x in b.iter_mut() {
            *x = v;
        }
        Ok(())
    })
}

fn handler(admit: Option<archon_server::AdmitAuthority>) -> (Handler, TestClock) {
    let clock = TestClock::new();
    let c = clock.clone();
    let mut cfg = Config::new(AUDIENCE)
        .clock(Box::new(move || c.0.load(Ordering::SeqCst)))
        .entropy(counting_entropy());
    if let Some(a) = admit {
        cfg = cfg.admit(a);
    }
    (Handler::new(cfg).expect("Handler::new"), clock)
}

/// The address a service configures for the offers form (§4.1); only the tests that need the
/// optional `page` key set it, so both shapes are on the wire.
const PAGE: &str = "https://dawn.example/login";

fn handler_with_page() -> (Handler, TestClock) {
    let clock = TestClock::new();
    let c = clock.clone();
    let cfg = Config::new(AUDIENCE)
        .page(PAGE)
        .clock(Box::new(move || c.0.load(Ordering::SeqCst)))
        .entropy(counting_entropy());
    (Handler::new(cfg).expect("Handler::new"), clock)
}

/// A handler whose entropy draws are COUNTED, so a test can assert that a refused begin built
/// nothing — the id and the nonce would be the first things built.
fn handler_with_counter() -> (Handler, Arc<AtomicU64>) {
    let n = Arc::new(AtomicU64::new(0));
    let drawn = n.clone();
    let entropy: archon_server::Entropy = Box::new(move |b: &mut [u8]| {
        let v = n.fetch_add(1, Ordering::SeqCst) as u8 + 1;
        for x in b.iter_mut() {
            *x = v;
        }
        Ok(())
    });
    let clock = TestClock::new();
    let c = clock.clone();
    let cfg = Config::new(AUDIENCE)
        .clock(Box::new(move || c.0.load(Ordering::SeqCst)))
        .entropy(entropy);
    (Handler::new(cfg).expect("Handler::new"), drawn)
}

/// A well-formed code — 16 bytes as 32 lowercase hex characters — distinct per byte, so two
/// tests never share one by accident.
fn code_for(b: u8) -> String {
    to_hex(&[b; 16])
}

fn offer_body(code: &str, scope: &[&str], valid_for: u32) -> String {
    format!(
        "{{\"code\":\"{code}\",\"scope\":{},\"valid_for\":{valid_for}}}",
        serde_json::to_string(scope).unwrap()
    )
}

/// §4's begin body with the one member §4.1 adds.
fn begin_on_body(code: &str, browser: &[u8], scope: &[&str], valid_for: u32) -> String {
    format!(
        "{{\"browser\":\"{}\",\"scope\":{},\"valid_for\":{valid_for},\"offer\":\"{code}\"}}",
        keytext::encode_key(browser),
        serde_json::to_string(scope).unwrap()
    )
}

fn req(method: &str, path: &str, body: &str, headers: &[(&str, &str)]) -> Request {
    Request {
        method: method.to_string(),
        path: path.to_string(),
        body: body.as_bytes().to_vec(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

fn body_json(r: &Response) -> serde_json::Value {
    serde_json::from_slice(&r.body).unwrap_or_else(|_| {
        panic!(
            "response body is not JSON ({}): {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        )
    })
}

/// Opens a login and returns (id hex, the scheme Request the CLI would prove over).
fn begin(
    h: &Handler,
    browser_seed: &[u8; 32],
    scope: &[&str],
    valid_for: u32,
) -> (String, login::Request) {
    let browser = crypto::public_key_from_seed(browser_seed);
    let scope_json = serde_json::to_string(scope).unwrap();
    let body = format!(
        "{{\"browser\":\"{}\",\"scope\":{},\"valid_for\":{}}}",
        keytext::encode_key(&browser),
        scope_json,
        valid_for
    );
    let r = h.handle(&req("POST", "/", &body, &[]));
    assert_eq!(r.status, 201, "begin: {}", String::from_utf8_lossy(&r.body));
    let v = body_json(&r);
    let id = v["id"].as_str().unwrap().to_string();
    let request = login::Request {
        id: from_hex(&id),
        nonce: from_hex(v["nonce"].as_str().unwrap()),
        browser: browser.to_vec(),
        scope: scope.iter().map(|s| s.to_string()).collect(),
        valid_for,
    };
    (id, request)
}

// THE WHOLE PROTOCOL, browser and CLI played against the handler with the real sdk.
#[test]
fn end_to_end() {
    let seen: Admitted = Arc::new(Mutex::new(None));
    let s = seen.clone();
    let (h, _clock) = handler(Some(Box::new(move |browser, principal, authority| {
        *s.lock().unwrap() = Some((browser.to_vec(), principal.to_vec(), authority.to_vec()));
        Ok(())
    })));

    let (browser_seed, person_seed) = (seed_for(1), seed_for(100));
    let (id, request) = begin(
        &h,
        &browser_seed,
        &["read:projects", "read:campaigns"],
        28800,
    );

    // The verification_uri is what the browser shows the person to type, and §2.1's grammar
    // requires exactly this shape.
    let begun = body_json(&h.handle(&req("GET", &format!("/{id}"), "", &[])));
    assert!(
        begun.get("audience").is_none(),
        "an audience must never be on the wire"
    );
    assert_eq!(begun["id"].as_str().unwrap(), id);

    // ANSWER
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let principal = keytext::encode_key(&crypto::public_key_from_seed(&person_seed));
    let body = format!(
        "{{\"principal\":\"{}\",\"possession\":\"{}\",\"authority\":{{\"grants\":[\"read:projects\"]}}}}",
        principal,
        to_hex(&proof)
    );
    let r = h.handle(&req("POST", &format!("/{id}/answer"), &body, &[]));
    assert_eq!(
        r.status,
        204,
        "answer: {}",
        String::from_utf8_lossy(&r.body)
    );

    let (browser_seen, principal_seen, authority_seen) =
        seen.lock().unwrap().clone().expect("admit called");
    assert_eq!(
        browser_seen,
        crypto::public_key_from_seed(&browser_seed).to_vec()
    );
    assert_eq!(
        principal_seen,
        crypto::public_key_from_seed(&person_seed).to_vec()
    );
    assert_eq!(
        String::from_utf8_lossy(&authority_seen),
        r#"{"grants":["read:projects"]}"#,
        "the authority reached the law altered"
    );

    // COLLECT, once.
    let collect = login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect");
    let r = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, &to_hex(&collect))],
    ));
    assert_eq!(
        r.status,
        200,
        "collect: {}",
        String::from_utf8_lossy(&r.body)
    );
    let got = body_json(&r);
    assert_eq!(got["principal"].as_str().unwrap(), principal);
    assert_eq!(got["possession"].as_str().unwrap(), to_hex(&proof));

    let r = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, &to_hex(&collect))],
    ));
    assert_eq!(r.status, 404, "the answer is handed over ONCE");
}

// A proof-only service: no admitter, no authority payload (§3.4 allows it absent).
#[test]
fn a_proof_only_service_needs_no_authority() {
    let (h, _clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(2), seed_for(200));
    let (id, request) = begin(&h, &browser_seed, &[], 60);

    // An empty scope is a LIST, never null — a client should not need a special case.
    let read = body_json(&h.handle(&req("GET", &format!("/{id}"), "", &[])));
    assert_eq!(read["scope"].as_array().map(|a| a.len()), Some(0));

    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let body = format!(
        "{{\"principal\":\"{}\",\"possession\":\"{}\"}}",
        keytext::encode_key(&crypto::public_key_from_seed(&person_seed)),
        to_hex(&proof)
    );
    assert_eq!(
        h.handle(&req("POST", &format!("/{id}/answer"), &body, &[]))
            .status,
        204
    );
}

fn answer_body(person_seed: &[u8; 32], proof: &[u8]) -> String {
    format!(
        "{{\"principal\":\"{}\",\"possession\":\"{}\"}}",
        keytext::encode_key(&crypto::public_key_from_seed(person_seed)),
        to_hex(proof)
    )
}

// Everything §4 says to refuse. Each would otherwise be a way to deposit or take something
// that was never proved.
#[test]
fn a_proof_by_the_wrong_key_is_refused_and_nothing_is_stored() {
    let (h, _clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(3), seed_for(30));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);

    let imposter = login::prove(&seed_for(77), AUDIENCE, &request).expect("prove");
    let r = h.handle(&req(
        "POST",
        &format!("/{id}/answer"),
        &answer_body(&person_seed, &imposter),
        &[],
    ));
    assert_eq!(r.status, 403);

    // The request must still be answerable by the real holder: a refused answer that
    // consumed the request would be a denial of service by anyone who saw the id.
    let good = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let r = h.handle(&req(
        "POST",
        &format!("/{id}/answer"),
        &answer_body(&person_seed, &good),
        &[],
    ));
    assert_eq!(
        r.status, 204,
        "the real answer after a refused one must still land"
    );
}

#[test]
fn a_proof_for_another_audience_is_refused() {
    let (h, _clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(4), seed_for(40));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    // The same request, proved against a different service: the phishing case the derived
    // audience rule exists for, seen from the server's side.
    let proof = login::prove(&person_seed, "https://evil.example", &request).expect("prove");
    assert_eq!(
        h.handle(&req(
            "POST",
            &format!("/{id}/answer"),
            &answer_body(&person_seed, &proof),
            &[]
        ))
        .status,
        403
    );
}

#[test]
fn a_proof_over_a_wider_scope_is_refused() {
    let (h, _clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(5), seed_for(50));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let mut wider = request.clone();
    wider.scope.push("publish:everything".to_string());
    let proof = login::prove(&person_seed, AUDIENCE, &wider).expect("prove");
    assert_eq!(
        h.handle(&req(
            "POST",
            &format!("/{id}/answer"),
            &answer_body(&person_seed, &proof),
            &[]
        ))
        .status,
        403,
        "the scope is bound, so a delegation wider than the CLI printed cannot verify"
    );
}

#[test]
fn the_law_can_refuse_and_then_nothing_is_stored() {
    let (h, _clock) = handler(Some(Box::new(|_, _, _| Err("the law says no".to_string()))));
    let (browser_seed, person_seed) = (seed_for(6), seed_for(60));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let body = format!(
        "{{\"principal\":\"{}\",\"possession\":\"{}\",\"authority\":{{\"nope\":true}}}}",
        keytext::encode_key(&crypto::public_key_from_seed(&person_seed)),
        to_hex(&proof)
    );
    assert_eq!(
        h.handle(&req("POST", &format!("/{id}/answer"), &body, &[]))
            .status,
        403
    );

    // The browser must still be told "pending", not handed a refused answer.
    let collect = login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect");
    let r = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, &to_hex(&collect))],
    ));
    assert_eq!(
        r.status, 202,
        "collect after a refused answer must be authorization_pending"
    );
}

#[test]
fn a_request_is_consumed_by_its_first_verified_answer() {
    let (h, _clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(7), seed_for(70));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let body = answer_body(&person_seed, &proof);
    assert_eq!(
        h.handle(&req("POST", &format!("/{id}/answer"), &body, &[]))
            .status,
        204
    );
    assert_eq!(
        h.handle(&req("POST", &format!("/{id}/answer"), &body, &[]))
            .status,
        409
    );
}

#[test]
fn a_stranger_cannot_collect() {
    let (h, _clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(8), seed_for(80));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    h.handle(&req(
        "POST",
        &format!("/{id}/answer"),
        &answer_body(&person_seed, &proof),
        &[],
    ));

    // Someone who saw the URL, holding a key that is not the request's browser key. The
    // scheme will not prove_collect with a seed the request does not name, so the only way to
    // build this attack at all is to prove over a request naming the stranger -- which is
    // exactly what an attacker with their own key has.
    let mut theirs = request.clone();
    theirs.browser = crypto::public_key_from_seed(&seed_for(9)).to_vec();
    let stranger = login::prove_collect(&seed_for(9), AUDIENCE, &theirs).expect("prove_collect");
    assert_eq!(
        h.handle(&req(
            "GET",
            &format!("/{id}/answer"),
            "",
            &[(COLLECT_HEADER, &to_hex(&stranger))]
        ))
        .status,
        403
    );
    // A login proof is not a collect proof: the roles are distinct (§3.3).
    assert_eq!(
        h.handle(&req(
            "GET",
            &format!("/{id}/answer"),
            "",
            &[(COLLECT_HEADER, &to_hex(&proof))]
        ))
        .status,
        403
    );
    // And no header at all.
    assert_eq!(
        h.handle(&req("GET", &format!("/{id}/answer"), "", &[]))
            .status,
        403
    );
}

#[test]
fn polling_faster_than_the_interval_is_slowed_down() {
    let (h, clock) = handler(None);
    let (browser_seed, _) = (seed_for(10), seed_for(101));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    let hdr = [(COLLECT_HEADER, collect.as_str())];

    assert_eq!(
        h.handle(&req("GET", &format!("/{id}/answer"), "", &hdr))
            .status,
        202
    );
    assert_eq!(
        h.handle(&req("GET", &format!("/{id}/answer"), "", &hdr))
            .status,
        429
    );
    clock.advance(archon_server::DEFAULT_INTERVAL_SECS);
    assert_eq!(
        h.handle(&req("GET", &format!("/{id}/answer"), "", &hdr))
            .status,
        202
    );
}

// caa's finding, carried from the Go lane rather than rediscovered here. The timer advances
// only for a poll whose collect proof VERIFIED — otherwise a stranger polling junk keeps the
// real browser at 429 forever, and slow_down becomes a denial of service handed to anyone who
// saw the id.
#[test]
fn an_unverified_poll_does_not_hold_the_browser_in_slow_down() {
    let (h, _clock) = handler(None);
    let (browser_seed, _) = (seed_for(11), seed_for(111));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);

    let junk = to_hex(&[0u8; 64]);
    for i in 0..5 {
        assert_eq!(
            h.handle(&req(
                "GET",
                &format!("/{id}/answer"),
                "",
                &[(COLLECT_HEADER, junk.as_str())]
            ))
            .status,
            403,
            "junk poll {i}"
        );
    }
    // The real browser, polling immediately after all that, must NOT be slowed down: none of
    // those polls was a poll.
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    assert_eq!(
        h.handle(&req(
            "GET",
            &format!("/{id}/answer"),
            "",
            &[(COLLECT_HEADER, collect.as_str())]
        ))
        .status,
        202,
        "the real browser after five junk polls"
    );
}

#[test]
fn everything_about_an_expired_request_is_404() {
    let (h, clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(12), seed_for(120));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    clock.advance(archon_server::DEFAULT_TTL_SECS + 1);

    assert_eq!(
        h.handle(&req("GET", &format!("/{id}"), "", &[])).status,
        404
    );
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let r = h.handle(&req(
        "POST",
        &format!("/{id}/answer"),
        &answer_body(&person_seed, &proof),
        &[],
    ));
    assert_eq!(r.status, 404);
    assert_eq!(body_json(&r)["error"].as_str().unwrap(), "expired_token");
}

#[test]
fn an_unknown_id_is_indistinguishable_from_an_expired_one() {
    let (h, _clock) = handler(None);
    let r = h.handle(&req("GET", &format!("/{}", "ab".repeat(16)), "", &[]));
    assert_eq!(r.status, 404);
    assert_eq!(body_json(&r)["error"].as_str().unwrap(), "expired_token");
}

// The door: what begin refuses before a request exists at all.
#[test]
fn begin_refusals() {
    let ok = keytext::encode_key(&crypto::public_key_from_seed(&seed_for(13)));
    for (name, body) in [
        (
            "browser is not key text",
            r#"{"browser":"7a91","scope":["a"],"valid_for":60}"#.to_string(),
        ),
        (
            "valid_for is zero",
            format!(r#"{{"browser":"{ok}","scope":["a"],"valid_for":0}}"#),
        ),
        (
            "a scope entry is empty",
            format!(r#"{{"browser":"{ok}","scope":[""],"valid_for":60}}"#),
        ),
        (
            "a control character",
            format!("{{\"browser\":\"{ok}\",\"scope\":[\"read:\\u001b[2Jx\"],\"valid_for\":60}}"),
        ),
        (
            "an unknown field",
            format!(
                r#"{{"browser":"{ok}","scope":["a"],"valid_for":60,"audience":"https://evil.example"}}"#
            ),
        ),
        ("not json at all", "{".to_string()),
    ] {
        let (h, _clock) = handler(None);
        assert_eq!(
            h.handle(&req("POST", "/", &body, &[])).status,
            400,
            "{name}"
        );
    }
}

// The audience is configuration, and a misconfiguration is a startup error an operator can
// read. Each of these DERIVES (by §2.1) to something other than itself, so a handler
// configured with one would bind a string the CLI never produces.
#[test]
fn new_refuses_an_audience_that_is_not_canonical() {
    for bad in [
        "",
        "https://dawn.example/api/",
        "https://Dawn.Example/api",
        "https://dawn.example:443/api",
        "wss://dawn.example/api",
        "HTTPS://dawn.example/api",
        "https://dawn.example/api?x=1",
        "dawn.example/api",
    ] {
        assert!(
            Handler::new(Config::new(bad)).is_err(),
            "accepted audience {bad:?}"
        );
    }
    // The error must NAME the spelling the CLI will derive, so the fix is in the message.
    let err = match Handler::new(Config::new("https://Dawn.Example/api")) {
        Err(e) => e,
        Ok(_) => panic!("accepted a non-canonical audience"),
    };
    assert!(
        err.contains("https://dawn.example/api"),
        "error must name the derived spelling: {err}"
    );
    assert!(Handler::new(Config::new(AUDIENCE)).is_ok());
}

// A SERVICE'S LAW MUST NOT BE ABLE TO STALL THE HANDLER. AdmitAuthority is the service's own
// code and may block on a database or a network; if it ran under the store's lock, one slow
// law would decide the throughput of every login in the process. This fails by TIMING OUT
// rather than by asserting, because a lock held across a callback does not produce a wrong
// value — it produces a wait.
#[test]
fn a_blocking_admitter_does_not_block_the_handler() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let entered = Mutex::new(Some(entered_tx));

    let h = Arc::new(
        Handler::new(
            Config::new(AUDIENCE)
                .clock(Box::new(|| 1_789_034_640))
                .entropy(counting_entropy())
                .admit(Box::new(move |_, _, _| {
                    // Only the FIRST admitter waits: taking the sender out of the Option
                    // says "first" without depending on who has drained what.
                    //
                    // The take is its OWN statement on purpose. A temporary in an `if let`
                    // scrutinee lives for the whole body, so writing this as
                    // `if let Some(tx) = entered.lock()...take()` would hold that lock across
                    // the wait below and deadlock every later admitter on it.
                    let first = entered.lock().unwrap().take();
                    if let Some(tx) = first {
                        let _ = tx.send(());
                        let _ = release_rx.lock().unwrap().recv();
                    }
                    Ok(())
                })),
        )
        .expect("Handler::new"),
    );

    let (browser_seed, person_seed) = (seed_for(14), seed_for(140));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let body = answer_body(&person_seed, &proof);

    let h2 = h.clone();
    let id2 = id.clone();
    let answering = std::thread::spawn(move || {
        h2.handle(&req("POST", &format!("/{id2}/answer"), &body, &[]))
            .status
    });

    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the admitter never ran");

    // The law is now inside, and would be holding the lock if we had it wrong.
    let h3 = h.clone();
    let id3 = id.clone();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(h3.handle(&req("GET", &format!("/{id3}"), "", &[])).status);
    });
    match done_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(status) => assert_eq!(status, 200, "concurrent read"),
        Err(_) => {
            panic!("a read blocked behind AdmitAuthority — the law is holding the store's lock")
        }
    }

    let _ = release_tx.send(());
    assert_eq!(answering.join().unwrap(), 204);
}

// Mounting under a prefix is the normal case: the routes are relative to wherever the service
// put the handler.
#[test]
fn routes_are_relative_to_the_mount() {
    let (h, _clock) = handler(None);
    let (id, _) = begin(&h, &seed_for(15), &["read:projects"], 60);
    // The service strips its own prefix before calling; the handler never sees it.
    assert_eq!(
        h.handle(&req("GET", &format!("/{id}"), "", &[])).status,
        200
    );
    assert_eq!(h.handle(&req("GET", &id, "", &[])).status, 200);
}

// Sweep is optional tidiness, not correctness — records expire on read regardless. The test
// says which, so nobody later "fixes" the absence of a background task.
#[test]
fn sweep_is_optional() {
    let (h, clock) = handler(None);
    begin(&h, &seed_for(16), &["read:projects"], 60);
    assert_eq!(h.sweep(), 0, "swept a live record");
    clock.advance(archon_server::DEFAULT_TTL_SECS + 1);
    assert_eq!(h.sweep(), 1);
}

// THE CROSS-LANE WIRE FIXTURE, the same file the Go lane reads. A cross-lane smoke run is
// impractical for a server (each lane needs its own socket and runtime), so this is where go,
// rs and ts are held to one wire format. It pins KEYS and their absence, not values: an id and
// a nonce are random by construction, and pinning them would pin the entropy.
#[test]
fn wire_shapes_match_the_shared_fixture() {
    let raw = std::fs::read_to_string("../testdata/login-wire.json")
        .expect("could not read the shared wire fixture");
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture is not JSON");
    let responses = fixture["responses"].as_object().expect("responses");
    assert!(
        !responses.is_empty(),
        "a fixture nobody can fail is not a pin"
    );

    // A handler WITH a page configured, so the offer response's optional `page` key is on the
    // wire and the fixture's optional_keys is exercised rather than satisfied by absence.
    let (h, _clock) = handler_with_page();
    let (browser_seed, person_seed) = (seed_for(17), seed_for(170));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);

    let mut emitted = std::collections::HashMap::new();
    emitted.insert(
        "begin".to_string(),
        h.handle(&req(
            "POST",
            "/",
            &format!(
                "{{\"browser\":\"{}\",\"scope\":[\"read:projects\"],\"valid_for\":3600}}",
                keytext::encode_key(&crypto::public_key_from_seed(&seed_for(18)))
            ),
            &[],
        )),
    );
    emitted.insert(
        "read".to_string(),
        h.handle(&req("GET", &format!("/{id}"), "", &[])),
    );
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    emitted.insert(
        "answer".to_string(),
        h.handle(&req(
            "POST",
            &format!("/{id}/answer"),
            &answer_body(&person_seed, &proof),
            &[],
        )),
    );
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    emitted.insert(
        "collect".to_string(),
        h.handle(&req(
            "GET",
            &format!("/{id}/answer"),
            "",
            &[(COLLECT_HEADER, collect.as_str())],
        )),
    );

    // And the offers form (§4.1): the prover offers, the page begins on the offer, the prover
    // reads the offer back — the two routes and the one member the fixture pins.
    let code = code_for(0x08);
    emitted.insert(
        "offer".to_string(),
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &["read:projects"], 3600),
            &[],
        )),
    );
    emitted.insert(
        "begin_on_offer".to_string(),
        h.handle(&req(
            "POST",
            "/",
            &begin_on_body(
                &code,
                &crypto::public_key_from_seed(&seed_for(9)),
                &["read:projects"],
                3600,
            ),
            &[],
        )),
    );
    emitted.insert(
        "offer_read".to_string(),
        h.handle(&req("GET", &format!("/offers/{code}"), "", &[])),
    );

    for (route, want) in responses {
        let got = emitted
            .get(route)
            .unwrap_or_else(|| panic!("fixture pins route {route:?}, untested here"));
        assert_eq!(
            got.status as u64,
            want["status"].as_u64().unwrap(),
            "status for {route}: {}",
            String::from_utf8_lossy(&got.body)
        );
        let keys: Vec<&str> = want["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_str().unwrap())
            .collect();
        if keys.is_empty() {
            assert!(got.body.is_empty(), "fixture says no body for {route}");
            continue;
        }
        let value = body_json(got);
        let object = value.as_object().unwrap();
        for k in &keys {
            assert!(object.contains_key(*k), "{route}: missing key {k:?}");
        }
        for k in want["forbidden_keys"].as_array().unwrap() {
            let k = k.as_str().unwrap();
            assert!(
                !object.contains_key(k),
                "{route}: key {k:?} must NOT be on the wire"
            );
        }
        let optional: Vec<&str> = want["optional_keys"]
            .as_array()
            .map(|a| a.iter().map(|k| k.as_str().unwrap()).collect())
            .unwrap_or_default();
        for k in object.keys() {
            assert!(
                keys.contains(&k.as_str()) || optional.contains(&k.as_str()),
                "{route}: unexpected key {k:?} — the fixture does not allow it"
            );
        }
    }
}

// EVERY ERROR CODE THE FIXTURE PINS, each driven by the situation that produces it — never by
// building a Response by hand. A code listed in a file three lanes read, that no lane actually
// emits, is a lie in the one place they all trust; the count assertion at the end is what
// keeps this from drifting into a subset.
#[test]
fn every_pinned_error_code_is_emitted() {
    let raw = std::fs::read_to_string("../testdata/login-wire.json").expect("fixture");
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture is not JSON");
    let codes = fixture["errors"]["codes"]
        .as_object()
        .expect("errors.codes");
    let error_keys: Vec<String> = fixture["errors"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();

    let mut got: std::collections::HashMap<String, Response> = std::collections::HashMap::new();
    let (h, _clock) = handler(None);

    got.insert(
        "begin_malformed".into(),
        h.handle(&req("POST", "/", "{", &[])),
    );
    got.insert(
        "read_unknown_or_expired".into(),
        h.handle(&req("GET", &format!("/{}", "ab".repeat(16)), "", &[])),
    );

    let (browser_seed, person_seed) = (seed_for(20), seed_for(210));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let good = answer_body(&person_seed, &proof);

    got.insert(
        "answer_malformed".into(),
        h.handle(&req("POST", &format!("/{id}/answer"), "{", &[])),
    );
    let wrong = login::prove(&seed_for(211), AUDIENCE, &request).expect("prove");
    got.insert(
        "answer_proof_refused".into(),
        h.handle(&req(
            "POST",
            &format!("/{id}/answer"),
            &answer_body(&person_seed, &wrong),
            &[],
        )),
    );

    // Two polls back to back: the first is pending, the second is too fast.
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    let hdr = [(COLLECT_HEADER, collect.as_str())];
    got.insert(
        "collect_pending".into(),
        h.handle(&req("GET", &format!("/{id}/answer"), "", &hdr)),
    );
    got.insert(
        "collect_too_fast".into(),
        h.handle(&req("GET", &format!("/{id}/answer"), "", &hdr)),
    );
    got.insert(
        "collect_proof_refused".into(),
        h.handle(&req("GET", &format!("/{id}/answer"), "", &[])),
    );

    assert_eq!(
        h.handle(&req("POST", &format!("/{id}/answer"), &good, &[]))
            .status,
        204
    );
    got.insert(
        "answer_already_answered".into(),
        h.handle(&req("POST", &format!("/{id}/answer"), &good, &[])),
    );

    // A service whose law refuses.
    let (h2, _c2) = handler(Some(Box::new(|_, _, _| Err("no".to_string()))));
    let (id2, request2) = begin(&h2, &seed_for(21), &["read:projects"], 3600);
    let proof2 = login::prove(&person_seed, AUDIENCE, &request2).expect("prove");
    got.insert(
        "answer_authority_refused".into(),
        h2.handle(&req(
            "POST",
            &format!("/{id2}/answer"),
            &answer_body(&person_seed, &proof2),
            &[],
        )),
    );

    // And a request that ran out of time, approached from both sides.
    let (h3, clock3) = handler(None);
    let browser3 = seed_for(22);
    let (id3, request3) = begin(&h3, &browser3, &["read:projects"], 3600);
    let proof3 = login::prove(&person_seed, AUDIENCE, &request3).expect("prove");
    let collect3 =
        to_hex(&login::prove_collect(&browser3, AUDIENCE, &request3).expect("prove_collect"));
    clock3.advance(archon_server::DEFAULT_TTL_SECS + 1);
    got.insert(
        "answer_expired".into(),
        h3.handle(&req(
            "POST",
            &format!("/{id3}/answer"),
            &answer_body(&person_seed, &proof3),
            &[],
        )),
    );
    got.insert(
        "collect_expired".into(),
        h3.handle(&req(
            "GET",
            &format!("/{id3}/answer"),
            "",
            &[(COLLECT_HEADER, collect3.as_str())],
        )),
    );

    // The offers form (§4.1). Where the spec says the answers are indistinguishable, one
    // fixture entry is driven several ways and every drive must equal the first, so a lane
    // cannot tell an unknown code from an expired or a malformed one even by accident.
    let scope = ["read:projects"];
    let browser = crypto::public_key_from_seed(&seed_for(23));
    got.insert(
        "offer_malformed".into(),
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code_for(0xc1)[..30], &scope, 3600),
            &[],
        )),
    );
    let code = code_for(0xc2);
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &scope, 3600),
            &[]
        ))
        .status,
        201
    );
    got.insert(
        "offer_code_taken".into(),
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &scope, 3600),
            &[],
        )),
    );
    got.insert(
        "begin_offer_mismatch".into(),
        h.handle(&req(
            "POST",
            "/",
            &begin_on_body(&code, &browser, &["read:campaigns"], 3600),
            &[],
        )),
    );
    assert_eq!(
        h.handle(&req(
            "POST",
            "/",
            &begin_on_body(&code, &browser, &scope, 3600),
            &[]
        ))
        .status,
        201
    );
    got.insert(
        "begin_offer_taken".into(),
        h.handle(&req(
            "POST",
            "/",
            &begin_on_body(&code, &browser, &scope, 3600),
            &[],
        )),
    );
    let (h5, clock5) = handler(None);
    let stale = code_for(0xc3);
    assert_eq!(
        h5.handle(&req(
            "POST",
            "/offers",
            &offer_body(&stale, &scope, 3600),
            &[]
        ))
        .status,
        201
    );
    clock5.advance(archon_server::DEFAULT_TTL_SECS + 1);
    let mut alike = |name: &str, drives: Vec<Response>| {
        for (i, d) in drives.iter().enumerate().skip(1) {
            assert_eq!(
                (d.status, &d.body),
                (drives[0].status, &drives[0].body),
                "{name}: drive {i} differs from drive 0 — the spec says indistinguishable"
            );
        }
        got.insert(name.to_string(), drives.into_iter().next().unwrap());
    };
    alike(
        "offer_unknown_or_expired",
        vec![
            h.handle(&req("GET", &format!("/offers/{}", code_for(0xc4)), "", &[])),
            h5.handle(&req("GET", &format!("/offers/{stale}"), "", &[])),
            h.handle(&req(
                "GET",
                &format!("/offers/{}", code.to_uppercase()),
                "",
                &[],
            )),
        ],
    );
    alike(
        "begin_offer_unknown_or_expired",
        vec![
            h.handle(&req(
                "POST",
                "/",
                &begin_on_body(&code_for(0xc4), &browser, &scope, 3600),
                &[],
            )),
            h5.handle(&req(
                "POST",
                "/",
                &begin_on_body(&stale, &browser, &scope, 3600),
                &[],
            )),
            h.handle(&req(
                "POST",
                "/",
                &begin_on_body(&code[..30], &browser, &scope, 3600),
                &[],
            )),
        ],
    );

    let pinned: Vec<&String> = codes.keys().filter(|k| !k.starts_with('_')).collect();
    for name in &pinned {
        let want = &codes[name.as_str()];
        let r = got.get(name.as_str()).unwrap_or_else(|| {
            panic!("the fixture pins error {name:?}, which no case here drives")
        });
        assert_eq!(
            r.status as u64,
            want["status"].as_u64().unwrap(),
            "status for {name}"
        );
        let value = body_json(r);
        let object = value.as_object().unwrap();
        assert_eq!(
            object.get("error").and_then(|e| e.as_str()),
            want["error"].as_str(),
            "code for {name}"
        );
        // The body carries the code and NOTHING else: no description, no echoed id, so a
        // stranger probing ids learns nothing from the difference between them.
        for k in object.keys() {
            assert!(
                error_keys.contains(k),
                "{name}: an error body carries {k:?}"
            );
        }
    }
    assert_eq!(
        got.len(),
        pinned.len(),
        "a case driven here that the fixture does not pin"
    );
}

// TWO CLIs ANSWERING ONE LOGIN, the second landing while the first is still inside the law.
//
// This is the case the RE-LOCKED `answered` check exists for, and the only case that reaches
// it: a sequential second answer is caught by the earlier check, so without a race that branch
// is dead code a refactor could quietly delete. A person with two terminals is ordinary; what
// must not happen is the slow one overwriting an answer the browser may already hold.
#[test]
fn a_second_answer_during_verification_loses_cleanly() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let entered = Mutex::new(Some(entered_tx));

    let h = Arc::new(
        Handler::new(
            Config::new(AUDIENCE)
                .clock(Box::new(|| 1_789_034_640))
                .entropy(counting_entropy())
                .admit(Box::new(move |_, _, _| {
                    // See the note in the blocking-admitter test: the take is its own
                    // statement so the lock is not held across the wait.
                    let first = entered.lock().unwrap().take();
                    if let Some(tx) = first {
                        let _ = tx.send(());
                        let _ = release_rx.lock().unwrap().recv();
                    }
                    Ok(())
                })),
        )
        .expect("Handler::new"),
    );

    let browser_seed = seed_for(23);
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);

    // The binding does not name the principal (§3.2), so two different key holders can each
    // make a genuine proof for one request. Both are real; only one can win.
    let (slow_seed, fast_seed) = (seed_for(230), seed_for(231));
    let slow = answer_body(
        &slow_seed,
        &login::prove(&slow_seed, AUDIENCE, &request).expect("prove"),
    );
    let fast = answer_body(
        &fast_seed,
        &login::prove(&fast_seed, AUDIENCE, &request).expect("prove"),
    );

    let h2 = h.clone();
    let id2 = id.clone();
    let slow_answer = std::thread::spawn(move || {
        h2.handle(&req("POST", &format!("/{id2}/answer"), &slow, &[]))
            .status
    });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the law never ran");

    // The second CLI, arriving while the first is still being admitted, wins outright.
    assert_eq!(
        h.handle(&req("POST", &format!("/{id}/answer"), &fast, &[]))
            .status,
        204
    );

    let _ = release_tx.send(());
    assert_eq!(
        slow_answer.join().unwrap(),
        409,
        "the answer that lost the race must be refused, not stored over the winner"
    );

    // And the browser gets the one that won, not the one that finished last.
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    let r = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, collect.as_str())],
    ));
    assert_eq!(
        r.status,
        200,
        "collect: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(
        body_json(&r)["principal"].as_str().unwrap(),
        keytext::encode_key(&crypto::public_key_from_seed(&fast_seed))
    );
}

// THE ADAPTER AND THE HANDLER, COMPOSED: a whole login driven from raw HTTP bytes through
// `http::parse_head` -> `into_request` -> `handle` -> `write_response` and back to bytes.
//
// The unit tests in `http` prove the parsing in isolation; this proves the two halves fit.
// Note the header is spelled `Archon-Collect` here on purpose: a browser may send any casing,
// and if the adapter did not lowercase it the collect would read as unproven -- a 403 that
// looks exactly like an attack.
#[test]
fn the_adapter_carries_a_whole_login_from_wire_bytes() {
    use archon_server::http;

    const MOUNT: &str = "/api/login";
    let (h, _clock) = handler(None);

    // Bytes in, bytes out -- the way a socket would hand them over.
    let round_trip = |raw: &str| -> (u16, String) {
        let bytes = raw.as_bytes();
        let sep = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a request head ends with a blank line");
        let head = http::parse_head(&bytes[..sep]).expect("parse_head");
        let want = head.content_length().expect("content_length");
        let body = bytes[sep + 4..].to_vec();
        assert_eq!(
            body.len(),
            want,
            "the fixture's content-length must match its body"
        );
        let req = head.into_request(body, MOUNT).expect("into_request");
        let resp = h.handle(&req);
        let out = String::from_utf8(http::write_response(&resp)).expect("response is UTF-8");
        let status: u16 = out
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("a status in the status line");
        let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        assert!(
            out.contains(&format!("content-length: {}\r\n", body.len())),
            "{out}"
        );
        (status, body)
    };

    let post = |path: &str, body: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nHost: dawn.example\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };

    let (browser_seed, person_seed) = (seed_for(24), seed_for(240));
    let browser = crypto::public_key_from_seed(&browser_seed);
    let begin_body = format!(
        r#"{{"browser":"{}","scope":["read:projects"],"valid_for":3600}}"#,
        keytext::encode_key(&browser)
    );
    let (status, body) = round_trip(&post(MOUNT, &begin_body));
    assert_eq!(status, 201, "{body}");
    let opened: serde_json::Value = serde_json::from_str(&body).expect("begin body");
    let id = opened["id"].as_str().unwrap().to_string();

    // A read, with a query string the routes must never see.
    let (status, body) = round_trip(&format!(
        "GET {MOUNT}/{id}?from=email HTTP/1.1\r\nHost: dawn.example\r\n\r\n"
    ));
    assert_eq!(status, 200, "{body}");
    let read: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(read["id"].as_str().unwrap(), id);

    let request = login::Request {
        id: from_hex(&id),
        nonce: from_hex(read["nonce"].as_str().unwrap()),
        browser: browser.to_vec(),
        scope: vec!["read:projects".to_string()],
        valid_for: 3600,
    };
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    let (status, body) = round_trip(&post(
        &format!("{MOUNT}/{id}/answer"),
        &answer_body(&person_seed, &proof),
    ));
    assert_eq!(status, 204, "{body}");
    assert!(body.is_empty(), "a 204 carries no body");

    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    let (status, body) = round_trip(&format!(
        "GET {MOUNT}/{id}/answer HTTP/1.1\r\nHost: dawn.example\r\nArchon-Collect: {collect}\r\n\r\n"
    ));
    assert_eq!(status, 200, "{body}");
    let got: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        got["principal"].as_str().unwrap(),
        keytext::encode_key(&crypto::public_key_from_seed(&person_seed))
    );
}

// THE AUTHORITY IS OPAQUE BYTES (ADR 0007 §B), pinned by VALUE from the fixture all three
// server lanes read.
//
// This lane had the defect caa found on #28: the authority was an `Option<serde_json::Value>`,
// and a `Value` is not the CLI's bytes. Its object is a sorted map, its numbers normalise and
// its strings are decoded. A law that signs its payload, or carries a 64-bit id, was handed
// something the CLI never sent.
//
// The `responses` section of the same fixture could not catch this: it pins KEY SETS, and a
// rebuilt payload has the same keys. That is why this case pins a VALUE.
#[test]
fn the_authority_crosses_this_lane_as_bytes() {
    let payload = fixture()["authority_roundtrip"]["payload"]
        .as_str()
        .expect("the fixture states no authority_roundtrip payload")
        .to_string();

    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let s = seen.clone();
    let (h, _clock) = handler(Some(Box::new(move |_, _, authority| {
        *s.lock().unwrap() = Some(String::from_utf8_lossy(authority).into_owned());
        Ok(())
    })));

    let (browser_seed, person_seed) = (seed_for(41), seed_for(210));
    let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");

    // Built as TEXT so the fixture's exact bytes reach the handler. Serialising a parsed
    // value here would reproduce the very defect the test exists to catch, in the test.
    let body = format!(
        "{{\"principal\":\"{}\",\"possession\":\"{}\",\"authority\":{}}}",
        keytext::encode_key(&crypto::public_key_from_seed(&person_seed)),
        to_hex(&proof),
        payload
    );
    let r = h.handle(&req("POST", &format!("/{id}/answer"), &body, &[]));
    assert_eq!(
        r.status,
        204,
        "answer: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some(payload.as_str()),
        "the law was handed a rebuilt payload"
    );

    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    let r = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, &collect)],
    ));
    assert_eq!(
        r.status,
        200,
        "collect: {}",
        String::from_utf8_lossy(&r.body)
    );
    // `no-store` is not decoration: the body carries a possession proof, and a cache holding
    // it is exactly what must not happen. Until now no lane asserted a response header at all.
    for (name, want) in [
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
    ] {
        let got = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str());
        assert_eq!(got, Some(want), "{name}");
    }
    let text = String::from_utf8(r.body).expect("the response is UTF-8");
    assert!(
        text.ends_with(&format!(",\"authority\":{payload}}}")),
        "the browser received a rebuilt authority: {text}"
    );

    // Every kind of damage a round trip does, named separately, so a regression says WHICH
    // one came back. The last two are caa's second probe -- Go's encoder compacts a
    // RawMessage AND HTML-escapes it, and a payload without whitespace or & could see
    // neither. This lane passes them for free, and carries them so it keeps doing so.
    for (what, want) in [
        ("the 64-bit integer changed", "9007199254740993"),
        ("the trailing zero was normalised away", "1.10"),
        ("the escape was decoded", "\\u00e9"),
        (
            "the insignificant whitespace was compacted away",
            "{\"z\":1, \"a\"",
        ),
        ("the ampersand did not survive", "?a=1&b=2"),
        ("the angle brackets did not survive", "<b>"),
    ] {
        assert!(text.contains(want), "{what}: {want:?} not in {text}");
    }
    for escaped in ["\\u0026", "\\u003c", "\\u003e"] {
        assert!(
            !text.contains(escaped),
            "the payload was HTML-escaped ({escaped}): {text}"
        );
    }
    assert!(
        text.find("\"z\"").unwrap() < text.find("\"a\"").unwrap(),
        "the keys were reordered: {text}"
    );
}

// The malformed-body cases the three lanes must answer ALIKE, from the shared fixture.
//
// Each case is members APPENDED to an otherwise-valid body, and the test proves that framing
// by sending the SAME body without them afterwards and requiring `base_status`. So a case
// here cannot pass because the request was refused for some unrelated reason — which is
// exactly how the door-check tests fooled themselves before.
#[test]
fn malformed_bodies_are_refused_alike() {
    let doc = fixture();
    let cases = doc["malformed_bodies"]["cases"]
        .as_array()
        .expect("the fixture states no malformed_bodies cases");
    assert!(!cases.is_empty(), "a pin nobody can fail is not a pin");

    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let route = case["route"].as_str().expect("route");
        let append = case["append_to_a_valid_body"]
            .as_str()
            .expect("append text");
        let want_status = case["status"].as_u64().expect("status") as u16;
        let want_error = case["error"].as_str().expect("error");
        let base_status = case["base_status"].as_u64().expect("base_status") as u16;
        assert!(
            !append.is_empty(),
            "{name}: appends nothing, so it distinguishes nothing"
        );

        let (h, _clock) = handler(None);
        let (browser_seed, person_seed) = (seed_for(51), seed_for(220));
        let (path, open) = match route {
            "begin" => (
                "/".to_string(),
                format!(
                    "{{\"browser\":\"{}\",\"scope\":[\"read:projects\"],\"valid_for\":3600",
                    keytext::encode_key(&crypto::public_key_from_seed(&browser_seed))
                ),
            ),
            "answer" => {
                let (id, request) = begin(&h, &browser_seed, &["read:projects"], 3600);
                let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
                (
                    format!("/{id}/answer"),
                    format!(
                        "{{\"principal\":\"{}\",\"possession\":\"{}\"",
                        keytext::encode_key(&crypto::public_key_from_seed(&person_seed)),
                        to_hex(&proof)
                    ),
                )
            }
            // The third route a body enters by (§4.1). The base body's 201 is what proves the
            // refusal above was for the repeated member and not for the code.
            "offer" => (
                "/offers".to_string(),
                format!(
                    "{{\"code\":\"{}\",\"scope\":[\"read:projects\"],\"valid_for\":3600",
                    code_for(0x77)
                ),
            ),
            other => panic!("the fixture names a route this suite does not drive: {other:?}"),
        };

        let r = h.handle(&req("POST", &path, &format!("{open}{append}}}"), &[]));
        assert_eq!(
            r.status,
            want_status,
            "{name}: {}",
            String::from_utf8_lossy(&r.body)
        );
        let body: serde_json::Value = serde_json::from_slice(&r.body).expect("an error body");
        assert_eq!(body["error"].as_str(), Some(want_error), "{name}");

        // The framing: the same body WITHOUT the appended members is accepted. If this
        // fails, the case above proved nothing about what it names.
        let r = h.handle(&req("POST", &path, &format!("{open}}}"), &[]));
        assert_eq!(
            r.status,
            base_status,
            "{name}: the base body must be accepted, else the case proves nothing: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
}

// ---- THE OFFERS FORM (docs/login.md §4.1) ------------------------------------------------
//
// The prover starts, the page finishes. Two routes and one member; the binding and the proofs
// are the same, so every case below ends in the same sdk calls the page-started form ends in.
// Names and cases mirror the Go and ts suites.

#[test]
fn offers_end_to_end() {
    let (h, _clock) = handler_with_page();
    let (browser_seed, person_seed) = (seed_for(60), seed_for(160));
    let browser = crypto::public_key_from_seed(&browser_seed);
    let scope = ["read:projects", "read:campaigns"];
    let code = code_for(0xa1);

    // The prover offers what it is willing to delegate, to a key it does not know yet.
    let r = h.handle(&req(
        "POST",
        "/offers",
        &offer_body(&code, &scope, 28800),
        &[],
    ));
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let offered = body_json(&r);
    assert_eq!(offered["code"].as_str(), Some(code.as_str()));
    // The code rides in the page's FRAGMENT — the part of an address a browser never sends
    // to any server — so the page's script reads it and no log does (§4.1 "The code").
    assert_eq!(
        offered["page"].as_str(),
        Some(format!("{PAGE}#{code}").as_str()),
        "the code must ride in the page's fragment"
    );
    assert_eq!(
        offered["expires_in"].as_u64(),
        Some(archon_server::DEFAULT_TTL_SECS)
    );
    assert_eq!(
        offered["interval"].as_u64(),
        Some(archon_server::DEFAULT_INTERVAL_SECS)
    );
    assert!(
        offered.get("audience").is_none(),
        "an audience on the wire — Finding 1 applies to this route too"
    );

    // The page reads the offer: open, nothing taken yet.
    let r = h.handle(&req("GET", &format!("/offers/{code}"), "", &[]));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let read = body_json(&r);
    assert!(
        read["request"].is_null(),
        "an open offer must say request: null"
    );
    assert_eq!(
        read["scope"],
        serde_json::json!(["read:projects", "read:campaigns"])
    );

    // The page begins on the offer with EXACTLY what was offered.
    let r = h.handle(&req(
        "POST",
        "/",
        &begin_on_body(&code, &browser, &scope, 28800),
        &[],
    ));
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let begun = body_json(&r);
    assert!(
        begun.get("offer").is_none(),
        "begin's response must not echo the offer — one shape for begin"
    );
    let id = begun["id"].as_str().unwrap().to_string();

    // The prover polls: taken, and by that request.
    let polled = body_json(&h.handle(&req("GET", &format!("/offers/{code}"), "", &[])));
    assert_eq!(polled["request"].as_str(), Some(id.as_str()));

    // The prover reads the request the offer names. The CLI re-checks scope and validity
    // itself (§4.1 rule 2); here the server's word is checked to be the offer's.
    let request_json = body_json(&h.handle(&req("GET", &format!("/{id}"), "", &[])));
    assert_eq!(
        request_json["browser"].as_str(),
        Some(keytext::encode_key(&browser).as_str())
    );
    assert_eq!(request_json["valid_for"].as_u64(), Some(28800));
    assert_eq!(
        request_json["scope"],
        serde_json::json!(["read:projects", "read:campaigns"])
    );

    // ...it answers with the sdk, the page collects, and the proof verifies — §4 unchanged.
    let request = login::Request {
        id: from_hex(&id),
        nonce: from_hex(request_json["nonce"].as_str().unwrap()),
        browser: browser.to_vec(),
        scope: scope.iter().map(|s| s.to_string()).collect(),
        valid_for: 28800,
    };
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    assert_eq!(
        h.handle(&req(
            "POST",
            &format!("/{id}/answer"),
            &answer_body(&person_seed, &proof),
            &[]
        ))
        .status,
        204
    );
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    let r = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, collect.as_str())],
    ));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let answer = body_json(&r);
    let possession = from_hex(answer["possession"].as_str().unwrap());
    assert!(
        login::verify(
            &crypto::public_key_from_seed(&person_seed),
            AUDIENCE,
            &request,
            &possession
        ),
        "the collected answer is not the person's verified proof"
    );

    // ...and the offer died with its request (§4.1 "State").
    let r = h.handle(&req("GET", &format!("/offers/{code}"), "", &[]));
    assert_eq!(r.status, 404, "after collection the offer must be gone");
    assert_eq!(body_json(&r)["error"].as_str(), Some("expired_token"));
}

// THE offer_mismatch FAMILY from the shared fixture: a request naming an offer whose scope or
// validity differ IN ANY WAY is refused before anything is stored and before any key is
// involved. "Nothing stored" and "no key involved" are asserted, not assumed: a refused begin
// draws no entropy (the id and nonce would be the first thing built), and the offer is still
// open afterwards. Then the FRAMING: the exact offer is accepted, and accepted once.
#[test]
fn a_mismatched_request_is_refused_before_anything_is_stored() {
    let doc = fixture();
    let family = &doc["offer_mismatch"];
    let cases = family["cases"]
        .as_array()
        .expect("the fixture states no offer_mismatch cases");
    assert!(!cases.is_empty(), "a pin nobody can fail is not a pin");
    let strings = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    };
    let offered_scope = strings(&family["offer"]["scope"]);
    let offered_valid_for = family["offer"]["valid_for"].as_u64().unwrap() as u32;
    let offered_refs: Vec<&str> = offered_scope.iter().map(String::as_str).collect();

    let (h, drawn) = handler_with_counter();
    let browser = crypto::public_key_from_seed(&seed_for(61));
    let code = code_for(0xa2);
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &offered_refs, offered_valid_for),
            &[]
        ))
        .status,
        201
    );
    let before = drawn.load(Ordering::SeqCst);

    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let scope = strings(&case["scope"]);
        let refs: Vec<&str> = scope.iter().map(String::as_str).collect();
        let valid_for = case["valid_for"].as_u64().unwrap() as u32;
        let r = h.handle(&req(
            "POST",
            "/",
            &begin_on_body(&code, &browser, &refs, valid_for),
            &[],
        ));
        assert_eq!(
            r.status as u64,
            case["status"].as_u64().unwrap(),
            "{name}: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(
            body_json(&r)["error"].as_str(),
            case["error"].as_str(),
            "{name}"
        );
        assert_eq!(
            drawn.load(Ordering::SeqCst),
            before,
            "{name}: a refused begin drew entropy — a request was built before the offer was checked"
        );
        let read = body_json(&h.handle(&req("GET", &format!("/offers/{code}"), "", &[])));
        assert!(
            read["request"].is_null(),
            "{name}: a refused begin took the offer"
        );
    }

    // A begin that passes the offer check but fails LATER must not take the offer either: the
    // take happens with the store, in one critical section, and a body refused after the
    // check never reaches it.
    let r = h.handle(&req(
        "POST",
        "/",
        &format!(
            "{{\"browser\":\"not a key\",\"scope\":{},\"valid_for\":{offered_valid_for},\"offer\":\"{code}\"}}",
            serde_json::to_string(&offered_scope).unwrap()
        ),
        &[],
    ));
    assert_eq!(r.status, 400, "a malformed browser key on an exact offer");
    assert!(
        body_json(&h.handle(&req("GET", &format!("/offers/{code}"), "", &[])))["request"].is_null(),
        "a begin refused after the offer check took the offer"
    );

    // THE FRAMING: the exact offer is accepted — else the cases above proved nothing — and
    // the same request a second time is refused as taken (one offer, one request).
    let r = h.handle(&req(
        "POST",
        "/",
        &begin_on_body(&code, &browser, &offered_refs, offered_valid_for),
        &[],
    ));
    assert_eq!(
        r.status,
        201,
        "the exact offer must be accepted, else the family proves nothing: {}",
        String::from_utf8_lossy(&r.body)
    );
    let r = h.handle(&req(
        "POST",
        "/",
        &begin_on_body(&code, &browser, &offered_refs, offered_valid_for),
        &[],
    ));
    assert_eq!(r.status, 409, "a second request on a taken offer");
    assert_eq!(body_json(&r)["error"].as_str(), Some("invalid_request"));
}

#[test]
fn one_offer_one_request() {
    let (h, clock) = handler(None);
    let browser = crypto::public_key_from_seed(&seed_for(62));
    let scope = ["read:projects"];
    let code = code_for(0xa3);

    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &scope, 3600),
            &[]
        ))
        .status,
        201
    );
    // One code, one offer: a second registration under a LIVE code is a conflict.
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &scope, 3600),
            &[]
        ))
        .status,
        409,
        "a second offer under a live code"
    );
    // One offer, one request: the first matching request takes it, the next is refused, and
    // the poll keeps naming the first.
    let r = h.handle(&req(
        "POST",
        "/",
        &begin_on_body(&code, &browser, &scope, 3600),
        &[],
    ));
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let first = body_json(&r)["id"].as_str().unwrap().to_string();
    let other = crypto::public_key_from_seed(&seed_for(63));
    assert_eq!(
        h.handle(&req(
            "POST",
            "/",
            &begin_on_body(&code, &other, &scope, 3600),
            &[]
        ))
        .status,
        409,
        "a second request on a taken offer"
    );
    assert_eq!(
        body_json(&h.handle(&req("GET", &format!("/offers/{code}"), "", &[])))["request"].as_str(),
        Some(first.as_str()),
        "the offer must keep naming the first request"
    );

    // Past its TTL the offer is dead — and so is its request — and the code is FREE again: a
    // new registration replaces the dead one rather than colliding with it.
    clock.advance(archon_server::DEFAULT_TTL_SECS + 1);
    assert_eq!(
        h.handle(&req("GET", &format!("/offers/{code}"), "", &[]))
            .status,
        404
    );
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &scope, 3600),
            &[]
        ))
        .status,
        201,
        "re-registering a dead code"
    );
}

// Unknown, expired and MALFORMED codes are one answer, on both routes a code can name an
// offer by: a registered code is always well-formed, so a malformed one is unknown by
// construction, and a stranger probing learns nothing from the difference. Only the offer
// route itself says 400 to a malformed code — that one is the prover's own mistake, and the
// prover is who is told.
#[test]
fn an_unknown_expired_or_malformed_code_is_404_alike() {
    let (h, clock) = handler(None);
    let browser = crypto::public_key_from_seed(&seed_for(64));
    let good = code_for(0xab);
    let codes = [
        ("unknown", code_for(0xee)),
        ("not hex", format!("zz{}", &good[2..])),
        ("odd length", good[..31].to_string()),
        ("too short", good[..30].to_string()),
        ("uppercase", good.to_uppercase()),
    ];
    for (name, code) in &codes {
        let r = h.handle(&req("GET", &format!("/offers/{code}"), "", &[]));
        assert_eq!(r.status, 404, "{name}: read");
        assert_eq!(
            body_json(&r)["error"].as_str(),
            Some("expired_token"),
            "{name}: read"
        );
        let r = h.handle(&req(
            "POST",
            "/",
            &begin_on_body(code, &browser, &["read:projects"], 3600),
            &[],
        ));
        assert_eq!(r.status, 404, "{name}: begin");
        assert_eq!(
            body_json(&r)["error"].as_str(),
            Some("expired_token"),
            "{name}: begin"
        );
    }

    // An expired one, from both sides.
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&good, &["read:projects"], 3600),
            &[]
        ))
        .status,
        201
    );
    clock.advance(archon_server::DEFAULT_TTL_SECS + 1);
    assert_eq!(
        h.handle(&req("GET", &format!("/offers/{good}"), "", &[]))
            .status,
        404,
        "expired: read"
    );
    assert_eq!(
        h.handle(&req(
            "POST",
            "/",
            &begin_on_body(&good, &browser, &["read:projects"], 3600),
            &[]
        ))
        .status,
        404,
        "expired: begin"
    );

    // Whereas the prover registering a malformed code is told so: 400, nothing registered.
    for (name, code) in &codes[1..] {
        let r = h.handle(&req(
            "POST",
            "/offers",
            &offer_body(code, &["read:projects"], 3600),
            &[],
        ));
        assert_eq!(r.status, 400, "{name}: offer");
        assert_eq!(
            body_json(&r)["error"].as_str(),
            Some("invalid_request"),
            "{name}: offer"
        );
    }
}

// An offer dies with its request (§4.1 "State"), and the store knows it without anything
// running at collection time: liveness consults the record the offer points at.
#[test]
fn an_offer_dies_with_its_request() {
    let (h, clock) = handler(None);
    let (browser_seed, person_seed) = (seed_for(65), seed_for(165));
    let browser = crypto::public_key_from_seed(&browser_seed);
    let scope = ["read:projects"];

    // Collected: the request is handed over once and dropped, and the offer goes with it.
    let code = code_for(0xa5);
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &scope, 3600),
            &[]
        ))
        .status,
        201
    );
    let r = h.handle(&req(
        "POST",
        "/",
        &begin_on_body(&code, &browser, &scope, 3600),
        &[],
    ));
    assert_eq!(r.status, 201);
    let begun = body_json(&r);
    let id = begun["id"].as_str().unwrap().to_string();
    let request = login::Request {
        id: from_hex(&id),
        nonce: from_hex(begun["nonce"].as_str().unwrap()),
        browser: browser.to_vec(),
        scope: vec!["read:projects".to_string()],
        valid_for: 3600,
    };
    let proof = login::prove(&person_seed, AUDIENCE, &request).expect("prove");
    assert_eq!(
        h.handle(&req(
            "POST",
            &format!("/{id}/answer"),
            &answer_body(&person_seed, &proof),
            &[]
        ))
        .status,
        204
    );
    let collect =
        to_hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).expect("prove_collect"));
    assert_eq!(
        h.handle(&req(
            "GET",
            &format!("/{id}/answer"),
            "",
            &[(COLLECT_HEADER, collect.as_str())]
        ))
        .status,
        200
    );
    // Not read first: sweep must see the orphan on its own, not because a read dropped it.
    assert_eq!(h.sweep(), 1, "sweep after collection: the orphaned offer");
    assert_eq!(
        h.handle(&req("GET", &format!("/offers/{code}"), "", &[]))
            .status,
        404,
        "the collected login's offer"
    );

    // Never taken and past its TTL: swept as well, counted once.
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code_for(0xa6), &scope, 3600),
            &[]
        ))
        .status,
        201
    );
    assert_eq!(h.sweep(), 0, "swept a live offer");
    clock.advance(archon_server::DEFAULT_TTL_SECS + 1);
    assert_eq!(h.sweep(), 1, "sweep past the TTL");
}

// Everything that would make an offer impossible to begin on is refused at the offer route,
// where the prover hears it — not at the page's begin, where only the page would.
#[test]
fn offer_refusals_at_the_door() {
    let (h, _clock) = handler(None);
    let refused = |what: &str, r: Response| {
        assert_eq!(
            r.status,
            400,
            "{what}: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(
            body_json(&r)["error"].as_str(),
            Some("invalid_request"),
            "{what}"
        );
    };
    refused(
        "an unparseable body",
        h.handle(&req("POST", "/offers", "{", &[])),
    );
    refused(
        "an unknown member",
        h.handle(&req(
            "POST",
            "/offers",
            &format!(
                "{{\"code\":\"{}\",\"scope\":[\"read:projects\"],\"valid_for\":3600,\"audience\":\"https://evil.example\"}}",
                code_for(0xb1)
            ),
            &[],
        )),
    );
    refused(
        "a validity of zero",
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code_for(0xb2), &["read:projects"], 0),
            &[],
        )),
    );
    refused(
        "a scope entry that could lie on screen",
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code_for(0xb3), &["read:\u{1b}[2Jx"], 3600),
            &[],
        )),
    );
    refused(
        "an empty scope entry",
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code_for(0xb4), &[""], 3600),
            &[],
        )),
    );
    // A scope that cannot BIND (an entry over the binding's u16 field) is refused now, not at
    // the page's begin, where an offer nobody could ever begin on would sit until it expired.
    let huge = "a".repeat(login::MAX_FIELD_SIZE + 1);
    refused(
        "a scope that cannot bind",
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code_for(0xb5), &[huge.as_str()], 3600),
            &[],
        )),
    );
    // None of the refused codes exists afterwards.
    for b in [0xb1u8, 0xb2, 0xb3, 0xb4, 0xb5] {
        assert_eq!(
            h.handle(&req("GET", &format!("/offers/{}", code_for(b)), "", &[]))
                .status,
            404,
            "a refused offer {b:x} exists"
        );
    }
    // Methods: the offer route is POST, the read route is GET, and nothing else.
    assert_eq!(h.handle(&req("GET", "/offers", "", &[])).status, 405);
    assert_eq!(
        h.handle(&req(
            "POST",
            &format!("/offers/{}", code_for(0xb6)),
            "",
            &[]
        ))
        .status,
        405
    );

    // The page's fragment is where the code goes, so a configured page with one is refused
    // where the operator can read it.
    let err = Handler::new(Config::new(AUDIENCE).page(format!("{PAGE}#already")))
        .expect_err("a page carrying a fragment must be refused");
    assert!(err.contains("fragment"), "{err}");
    // And a handler WITHOUT a page emits no page key — the fixture calls it optional, and
    // optional means absent when unconfigured, never null or empty.
    let got = body_json(&h.handle(&req(
        "POST",
        "/offers",
        &offer_body(&code_for(0xb7), &["read:projects"], 3600),
        &[],
    )));
    assert!(
        got.get("page").is_none(),
        "a handler with no page configured emitted page = {}",
        got["page"]
    );
}

// THE OFFER ROUTE IS NOT PACED (ADR 0007 §C.7, amendment #39). §4's collect is polled by one
// party with a proof; this route is read by the page AND polled by the prover, and one
// reference time would let the prover's period lock the page out on every retry. There is
// also nothing here to protect — no proof to verify, no answer to hand over; a stranger with
// the code already has everything the route returns. The prover paces itself by the
// advertised interval. This test is the regression guard for that ruling: ten reads at one
// instant all answer 200, and the offer stays open.
#[test]
fn the_offer_route_is_not_paced() {
    let (h, _clock) = handler(None);
    let code = code_for(0xa7);
    assert_eq!(
        h.handle(&req(
            "POST",
            "/offers",
            &offer_body(&code, &["read:projects"], 3600),
            &[]
        ))
        .status,
        201
    );
    for i in 0..10 {
        let r = h.handle(&req("GET", &format!("/offers/{code}"), "", &[]));
        assert_eq!(
            r.status,
            200,
            "poll {i} — the offer route must not be paced: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert!(
            body_json(&r)["request"].is_null(),
            "poll {i}: the offer was taken by nobody"
        );
    }
}

/// The shared cross-lane fixture, read once per case that needs it.
fn fixture() -> serde_json::Value {
    let raw = std::fs::read_to_string("../testdata/login-wire.json")
        .expect("could not read the shared wire fixture");
    serde_json::from_str(&raw).expect("the shared wire fixture is not JSON")
}
