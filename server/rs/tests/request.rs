//! ADR 0010 §8's failure tests for the Rust lane, deliberately the same cases as the Go and
//! TypeScript lanes' (server/go/request/request_test.go, server/ts/test/request.test.ts).
//!
//! This crate has no HTTP framework by design (ADR 0007 §B): its HTTP stack is `http.rs` on a
//! `TcpListener`, as `examples/serve.rs` mounts it. So that is what every case goes through: a
//! real listener, requests written on a raw TCP socket byte for byte (the request line exactly as
//! given), and an application that records whether it ran. Every refusal is checked twice: the
//! status, and that the application never saw the request.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use archon_core::crypto;
use archon_sdk::request::{self as sdk, Policy, ToSign};
use archon_server::http;
use archon_server::request::{
    body_length, Authenticated, MemoryReplayStore, Outcome, ReplayEntry, ReplayStore, Verifier,
    MAX_REQUEST_BODY_BYTES,
};
use archon_server::Response;

const AUDIENCE: &str = "https://dawn.example/api";
const SEED: [u8; 32] = [0x44; 32];
const OTHER_SEED: [u8; 32] = [0x55; 32];
const T0: u64 = 1_789_034_640;
const BODY: &[u8] = br#"{"name":"thing"}"#;

fn policy() -> Policy {
    Policy {
        audience: AUDIENCE.to_string(),
        declared: vec!["idempotency-key".to_string()],
        max_lifetime: 300,
        skew: 30,
    }
}

/// A fresh nonce per proof, from a counter: distinct, and nothing random in the suite.
fn nonce() -> Vec<u8> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let mut out = vec![0xa5; 16];
    out[8..].copy_from_slice(&n.to_be_bytes());
    out
}

/// What last reached the application: what was verified, and the body it read.
type Last = Mutex<Option<(Authenticated, Vec<u8>)>>;

struct Harness {
    addr: SocketAddr,
    clock: Arc<AtomicU64>,
    hits: Arc<AtomicUsize>,
    last: Arc<Last>,
}

fn harness(store: Arc<dyn ReplayStore>) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let clock = Arc::new(AtomicU64::new(T0 + 5));
    let at = Arc::clone(&clock);
    let verifier = Arc::new(Verifier::new(
        policy(),
        store,
        Box::new(move || at.load(Ordering::SeqCst)),
    ));
    let hits = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(None));
    let (h, l) = (Arc::clone(&hits), Arc::clone(&last));
    // The accept loop is never joined: it lives until the test binary exits.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (v, h, l) = (Arc::clone(&verifier), Arc::clone(&h), Arc::clone(&l));
            std::thread::spawn(move || serve(&v, stream, &h, &l));
        }
    });
    Harness {
        addr,
        clock,
        hits,
        last,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One connection, the way `examples/serve.rs` serves one, with the verifier in front of the
/// application.
fn serve(verifier: &Verifier, mut stream: TcpStream, hits: &AtomicUsize, last: &Last) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let response = match http::parse_head(&buf[..head_end]) {
        Err(_) => Response {
            status: 400,
            body: Vec::new(),
            headers: Vec::new(),
        },
        Ok(head) => match body_length(&head) {
            Err(refusal) => refusal.response(),
            Ok(want) => {
                let mut body = buf[head_end + 4..].to_vec();
                while body.len() < want {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                    }
                }
                body.truncate(want);
                match verifier.authenticate(&head, &body) {
                    Err(refusal) => refusal.response(),
                    Ok(auth) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        *last.lock().unwrap() = Some((auth, body));
                        Response {
                            status: 204,
                            body: Vec::new(),
                            headers: Vec::new(),
                        }
                    }
                }
            }
        },
    };
    let _ = stream.write_all(&http::write_response(&response));
    // A lingering close: drain what the client is still sending, so closing does not reset the
    // connection under a response it has not read yet (a 413 is answered before its body).
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    while matches!(stream.read(&mut chunk), Ok(n) if n > 0) {}
}

#[derive(Clone)]
struct Signed {
    method: String,
    target: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

fn input(method: &str, target: &str, body: &[u8]) -> ToSign {
    ToSign {
        method: method.to_string(),
        audience: AUDIENCE.to_string(),
        request_target: target.to_string(),
        body: body.to_vec(),
        content_type: Some("application/json".to_string()),
        declared: vec![("idempotency-key".to_string(), "k-1".to_string())],
        created: T0,
        expires: T0 + 60,
        nonce: nonce(),
    }
}

fn signed_with(input: ToSign) -> Signed {
    let (_, h) = sdk::sign(&SEED, &input).unwrap();
    let mut headers = vec![
        ("Archon-Audience".to_string(), h.archon_audience),
        ("Content-Digest".to_string(), h.content_digest),
        ("Signature-Input".to_string(), h.signature_input),
        ("Signature".to_string(), h.signature),
    ];
    if let Some(ct) = &input.content_type {
        headers.push(("Content-Type".to_string(), ct.clone()));
    }
    headers.extend(input.declared.iter().cloned());
    Signed {
        method: input.method,
        target: input.request_target,
        body: input.body,
        headers,
    }
}

fn signed(method: &str, target: &str, body: &[u8]) -> Signed {
    signed_with(input(method, target, body))
}

fn without(headers: &[(String, String)], name: &str) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(n, _)| !n.eq_ignore_ascii_case(name))
        .cloned()
        .collect()
}

fn replace(headers: &[(String, String)], name: &str, value: &str) -> Vec<(String, String)> {
    let mut out = without(headers, name);
    out.push((name.to_string(), value.to_string()));
    out
}

fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Write the request on a raw TCP connection, `Content-Length` framed unless the caller's
/// headers frame it themselves, and return the response status.
fn send(h: &Harness, s: &Signed) -> u16 {
    send_bytes(h, s, true)
}

fn send_bytes(h: &Harness, s: &Signed, frame: bool) -> u16 {
    let mut stream = TcpStream::connect(h.addr).unwrap();
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: dawn.example\r\nConnection: close\r\n",
        s.method, s.target
    );
    if frame {
        head.push_str(&format!("Content-Length: {}\r\n", s.body.len()));
    }
    for (n, v) in &s.headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&s.body);
    stream.write_all(&bytes).unwrap();
    let _ = stream.shutdown(Shutdown::Write);
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    text.strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no response: {text:?}"))
}

fn fresh() -> Arc<dyn ReplayStore> {
    Arc::new(MemoryReplayStore::new(T0 - 3600))
}

#[test]
fn an_authenticated_request_reaches_the_application_with_what_was_verified() {
    let h = harness(fresh());
    assert_eq!(send(&h, &signed("POST", "/api/v1/things?x=1", BODY)), 204);
    assert_eq!(h.hits.load(Ordering::SeqCst), 1);
    let last = h.last.lock().unwrap();
    let (auth, body) = last.as_ref().unwrap();
    assert_eq!(auth.principal, crypto::public_key_from_seed(&SEED));
    assert_eq!(auth.target_uri, "https://dawn.example/api/v1/things?x=1");
    assert_eq!(body, BODY);
}

#[test]
fn every_refusal_keeps_the_request_from_the_application() {
    type Make = fn() -> (Signed, bool);
    let cases: Vec<(&str, Make, u16)> = vec![
        (
            "wrong-key signer: keyid names one key, another signed",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                let p = sdk::prepare(
                    &crypto::public_key_from_seed(&SEED),
                    &input("POST", "/api/v1/things", BODY),
                )
                .unwrap();
                let wrong =
                    crypto::sign_in_domain(&OTHER_SEED, sdk::DOMAIN, &p.signing.message).unwrap();
                s.headers = replace(&s.headers, "Signature-Input", &p.headers.signature_input);
                s.headers = replace(
                    &s.headers,
                    "Signature",
                    &format!("archon=:{}:", b64(&wrong)),
                );
                (s, true)
            },
            401,
        ),
        (
            "dropped-context signer: a raw signature over the base",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                let p = sdk::prepare(
                    &crypto::public_key_from_seed(&SEED),
                    &input("POST", "/api/v1/things", BODY),
                )
                .unwrap();
                let raw = crypto::sign(&SEED, &p.signing.message);
                s.headers = replace(&s.headers, "Signature-Input", &p.headers.signature_input);
                s.headers = replace(&s.headers, "Signature", &format!("archon=:{}:", b64(&raw)));
                (s, true)
            },
            401,
        ),
        (
            "path ambiguity: signed with an escape, sent decoded",
            || {
                let mut s = signed("POST", "/api/a%2Fb", BODY);
                s.target = "/api/a/b".to_string();
                (s, true)
            },
            401,
        ),
        (
            "query ambiguity: parameters reordered",
            || {
                let mut s = signed("POST", "/api/v1/things?a=1&b=2", BODY);
                s.target = "/api/v1/things?b=2&a=1".to_string();
                (s, true)
            },
            401,
        ),
        (
            "modified body",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.body = br#"{"name":"other"}"#.to_vec();
                (s, true)
            },
            401,
        ),
        (
            "emptied body",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.body.clear();
                (s, true)
            },
            401,
        ),
        (
            "missing covered header",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.headers = without(&s.headers, "Idempotency-Key");
                (s, true)
            },
            401,
        ),
        (
            "duplicated covered header",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.headers
                    .push(("Idempotency-Key".to_string(), "k-1".to_string()));
                (s, true)
            },
            401,
        ),
        (
            "a content coding",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.headers
                    .push(("Content-Encoding".to_string(), "identity".to_string()));
                (s, true)
            },
            400,
        ),
        (
            "absolute-form request-target",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.target = "http://dawn.example/api/v1/things".to_string();
                (s, true)
            },
            401,
        ),
        (
            // This crate frames by Content-Length alone, so a chunked body (and with it every
            // trailer) is refused before a byte of it is read.
            "a chunked body with a trailer",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.headers
                    .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
                s.headers
                    .push(("Trailer".to_string(), "Idempotency-Key".to_string()));
                let mut chunked = format!("{:x}\r\n", s.body.len()).into_bytes();
                chunked.extend_from_slice(&s.body);
                chunked.extend_from_slice(b"\r\n0\r\nIdempotency-Key: k-2\r\n\r\n");
                s.body = chunked;
                (s, false)
            },
            400,
        ),
        (
            "two Content-Length fields",
            || {
                let mut s = signed("POST", "/api/v1/things", BODY);
                s.headers
                    .push(("Content-Length".to_string(), "0".to_string()));
                (s, true)
            },
            400,
        ),
    ];
    for (name, make, want) in cases {
        let h = harness(fresh());
        let (s, frame) = make();
        assert_eq!(send_bytes(&h, &s, frame), want, "{name}");
        assert_eq!(
            h.hits.load(Ordering::SeqCst),
            0,
            "{name}: the application ran"
        );
    }
}

#[test]
fn expiry_bounds() {
    // created T0, expires T0+60, skew 30: acceptable on [T0−30, T0+90).
    for (at, want) in [
        (T0 - 30, 204),
        (T0 - 31, 401),
        (T0 + 89, 204),
        (T0 + 90, 401),
    ] {
        let h = harness(fresh());
        h.clock.store(at, Ordering::SeqCst);
        assert_eq!(
            send(&h, &signed("POST", "/api/v1/things", BODY)),
            want,
            "at T0{:+}",
            at as i64 - T0 as i64
        );
    }
}

#[test]
fn concurrent_copies_of_one_proof_admit_one() {
    let h = Arc::new(harness(fresh()));
    let s = signed("POST", "/api/v1/things", BODY);
    let threads: Vec<_> = (0..24)
        .map(|_| {
            let (h, s) = (Arc::clone(&h), s.clone());
            std::thread::spawn(move || send(&h, &s))
        })
        .collect();
    let statuses: Vec<u16> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        statuses.iter().filter(|&&st| st == 204).count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses.iter().all(|&st| st == 204 || st == 401),
        "{statuses:?}"
    );
    assert_eq!(h.hits.load(Ordering::SeqCst), 1);
}

/// A store that cannot answer.
struct Outage;

impl ReplayStore for Outage {
    fn insert_if_absent(&self, _: &ReplayEntry) -> Outcome {
        Outcome::Unavailable
    }
}

#[test]
fn an_unavailable_replay_store_fails_closed() {
    let h = harness(Arc::new(Outage));
    assert_eq!(send(&h, &signed("POST", "/api/v1/things", BODY)), 503);
    assert_eq!(
        h.hits.load(Ordering::SeqCst),
        0,
        "the application ran while the replay store was down"
    );
}

#[test]
fn failover_to_another_verifier_sharing_the_store_still_admits_once() {
    let shared = fresh();
    let (first, second) = (harness(Arc::clone(&shared)), harness(shared));
    let s = signed("POST", "/api/v1/things", BODY);
    assert_eq!(send(&first, &s), 204);
    assert_eq!(
        send(&second, &s),
        401,
        "the second verifier admitted the same proof"
    );
}

#[test]
fn a_restarted_process_refuses_proofs_it_cannot_know_about() {
    // The process restarts at T0+10: a proof created at T0 (open from T0−30) may have been
    // accepted before the restart, so the new incarnation refuses it; a proof opened after the
    // restart is admitted.
    let h = harness(Arc::new(MemoryReplayStore::new(T0 + 10)));
    h.clock.store(T0 + 20, Ordering::SeqCst);
    assert_eq!(send(&h, &signed("POST", "/api/v1/things", BODY)), 503);
    let mut later = input("POST", "/api/v1/things", BODY);
    later.created = T0 + 40;
    later.expires = T0 + 100;
    h.clock.store(T0 + 45, Ordering::SeqCst);
    assert_eq!(send(&h, &signed_with(later)), 204);
}

#[test]
fn an_oversized_body_is_refused_not_truncated() {
    let h = harness(fresh());
    let big = vec![b'a'; MAX_REQUEST_BODY_BYTES + 1];
    assert_eq!(send(&h, &signed("POST", "/api/v1/things", &big)), 413);
    assert_eq!(h.hits.load(Ordering::SeqCst), 0);
}

// The body bound below HTTP: body_length refuses a declared length first, so through a server
// the verifier's own check is masked — it is pinned here, for a caller that frames bodies itself.
#[test]
fn authenticate_refuses_an_oversized_body_handed_to_it_directly() {
    let verifier = Verifier::new(policy(), fresh(), Box::new(|| T0));
    let head = http::parse_head(b"POST /api HTTP/1.1\r\nHost: dawn.example").unwrap();
    let refusal = verifier
        .authenticate(&head, &vec![0; MAX_REQUEST_BODY_BYTES + 1])
        .unwrap_err();
    assert_eq!(refusal.status, 413);
}

// And body_length's own refusals, which authenticate's re-checks mask through a server: a
// transfer coding, and a declared length over the limit — decided before a byte is read.
#[test]
fn body_length_decides_before_a_byte_is_read() {
    let length = |extra: &str| {
        let head = http::parse_head(format!("POST /api HTTP/1.1\r\n{extra}").as_bytes()).unwrap();
        body_length(&head).map_err(|r| r.status)
    };
    assert_eq!(length(""), Ok(0));
    assert_eq!(length("Content-Length: 16\r\n"), Ok(16));
    assert_eq!(
        length(&format!("Content-Length: {MAX_REQUEST_BODY_BYTES}\r\n")),
        Ok(MAX_REQUEST_BODY_BYTES)
    );
    assert_eq!(
        length(&format!(
            "Content-Length: {}\r\n",
            MAX_REQUEST_BODY_BYTES + 1
        )),
        Err(413)
    );
    assert_eq!(length("Transfer-Encoding: chunked\r\n"), Err(400));
    assert_eq!(
        length("Transfer-Encoding: chunked\r\nContent-Length: 16\r\n"),
        Err(400)
    );
    assert_eq!(
        length("Content-Length: 16\r\ncontent-length: 16\r\n"),
        Err(400)
    );
    for bad in ["+16", "0x10", "1e3", "16, 16", "1234567890123456"] {
        assert_eq!(
            length(&format!("Content-Length: {bad}\r\n")),
            Err(400),
            "{bad}"
        );
    }
}

#[test]
fn memory_replay_store_restart_policy_presence_and_sweep() {
    let store = MemoryReplayStore::new(T0);
    let entry = |from| ReplayEntry {
        key: archon_server::request::ReplayKey {
            profile: sdk::TAG.to_string(),
            audience: AUDIENCE.to_string(),
            principal: "k".to_string(),
            nonce: "00".to_string(),
        },
        from,
        until: T0 + 90,
    };
    assert_eq!(store.insert_if_absent(&entry(T0 - 1)), Outcome::Unavailable);
    assert_eq!(store.insert_if_absent(&entry(T0)), Outcome::Inserted);
    assert_eq!(store.insert_if_absent(&entry(T0)), Outcome::AlreadyPresent);
    assert_eq!(store.sweep(T0 + 89), 0);
    assert_eq!(store.insert_if_absent(&entry(T0)), Outcome::AlreadyPresent);
    assert_eq!(store.sweep(T0 + 90), 1);
    assert_eq!(store.insert_if_absent(&entry(T0)), Outcome::Inserted);
}
