//! ADR 0010 §8's enrollment failure tests for the Rust lane — substitution and replay —
//! deliberately the same cases as the Go and TypeScript lanes' (server/go/enroll/enroll_test.go,
//! server/ts/test/enroll.test.ts), through this crate's HTTP stack: `http.rs` on a `TcpListener`.
//!
//! archon defines no enrollment route, so the test plays the service: a route that takes its
//! session from a cookie, reads `{"transaction","proof"}` and calls `complete`, in front of an
//! integration that keeps records and associations under one lock. Every refusal is checked
//! twice: the status, and that no association was recorded.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use archon_core::crypto;
use archon_sdk::enroll::{self as sdk, Request};
use archon_server::enroll::{
    Begin, Challenge, Enroller, Integration, Outcome, Record, DEFAULT_TTL_SECS,
};
use archon_server::{http, Response};
use sha2::{Digest, Sha256};

const AUDIENCE: &str = "https://dawn.example/api";
const KEY_SEED: [u8; 32] = [0x61; 32];
const OTHER_SEED: [u8; 32] = [0x62; 32];
const T0: u64 = 1_789_034_640;
const INTENT: &[u8] = b"acct-1 add-key restrictions=none";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Association {
    account: Vec<u8>,
    key: Vec<u8>,
    purpose: String,
}

#[derive(Default)]
struct State {
    records: HashMap<Vec<u8>, Record>,
    consumed: HashSet<Vec<u8>>,
    associations: Vec<Association>,
    load_down: bool,
    complete_down: bool,
    wrong_record: bool,
}

/// The integration: everything under one lock, which is what makes its `complete` atomic.
#[derive(Default)]
struct Service(Mutex<State>);

impl Service {
    fn persist(&self, r: Record) {
        self.0
            .lock()
            .unwrap()
            .records
            .insert(r.transaction.clone(), r);
    }

    fn recorded(&self) -> Vec<Association> {
        self.0.lock().unwrap().associations.clone()
    }
}

impl Integration for Service {
    fn load(&self, transaction: &[u8]) -> Result<Option<Record>, String> {
        let s = self.0.lock().unwrap();
        if s.load_down {
            return Err("the database is down".to_string());
        }
        let found = s.records.get(transaction).cloned();
        if found.is_some() && s.wrong_record {
            return Ok(s
                .records
                .values()
                .find(|r| r.transaction != transaction)
                .cloned());
        }
        Ok(found)
    }

    fn complete(&self, r: &Record) -> Outcome {
        let mut s = self.0.lock().unwrap();
        if s.complete_down {
            return Outcome::Unavailable;
        }
        if !s.consumed.insert(r.transaction.clone()) {
            return Outcome::NotPending;
        }
        s.associations.push(Association {
            account: r.account.clone(),
            key: r.new_key.clone(),
            purpose: r.purpose.clone(),
        });
        Outcome::Completed
    }
}

struct Harness {
    addr: SocketAddr,
    enroller: Arc<Enroller>,
    svc: Arc<Service>,
    clock: Arc<AtomicU64>,
}

fn harness() -> Harness {
    let svc = Arc::new(Service::default());
    let clock = Arc::new(AtomicU64::new(T0));
    let at = Arc::clone(&clock);
    let n = Arc::new(AtomicU8::new(0));
    let enroller = Arc::new(
        Enroller::new(
            AUDIENCE,
            Arc::clone(&svc) as Arc<dyn Integration>,
            Box::new(move || at.load(Ordering::SeqCst)),
            Box::new(move |b: &mut [u8]| {
                b.fill(n.fetch_add(1, Ordering::SeqCst) + 1);
                Ok(())
            }),
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let e = Arc::clone(&enroller);
    // The accept loop is never joined: it lives until the test binary exits.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let e = Arc::clone(&e);
            std::thread::spawn(move || serve(&e, stream));
        }
    });
    Harness {
        addr,
        enroller,
        svc,
        clock,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn status(code: u16) -> Response {
    Response {
        status: code,
        body: Vec::new(),
        headers: Vec::new(),
    }
}

/// The service's completion route.
fn serve(enroller: &Enroller, mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let response = (|| {
        let head = http::parse_head(&buf[..head_end]).map_err(|_| status(400))?;
        if head.method != "POST" || head.target != "/enroll/complete" {
            return Err(status(404));
        }
        let want = head.content_length().map_err(|_| status(400))?;
        let mut body = buf[head_end + 4..].to_vec();
        while body.len() < want {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
        body.truncate(want);
        let session = head
            .header("cookie")
            .and_then(|c| c.split(';').find_map(|p| p.trim().strip_prefix("session=")))
            .unwrap_or("");
        let json: serde_json::Value = serde_json::from_slice(&body).map_err(|_| status(400))?;
        let field = |name: &str| json.get(name).and_then(|v| v.as_str()).and_then(unhex);
        let (Some(transaction), Some(proof)) = (field("transaction"), field("proof")) else {
            return Err(status(400));
        };
        enroller
            .complete(&transaction, &proof, session.as_bytes())
            .map_err(|r| r.response())?;
        Ok(status(204))
    })()
    .unwrap_or_else(|refusal| refusal);
    let _ = stream.write_all(&http::write_response(&response));
}

/// The service's begin route, after it validated the session: prepare, persist, challenge.
fn begin(h: &Harness, session: &str) -> Challenge {
    let (record, challenge) = h
        .enroller
        .prepare(&Begin {
            authorization: session.as_bytes().to_vec(),
            account: b"acct-1".to_vec(),
            purpose: "add-key".to_string(),
            new_key: crypto::public_key_from_seed(&KEY_SEED).to_vec(),
            intent: INTENT.to_vec(),
        })
        .unwrap();
    h.svc.persist(record);
    challenge
}

/// The client: the proof by `seed` over the challenge, with `edit` applied to what it signs.
fn prove(seed: &[u8; 32], ch: &Challenge, edit: impl FnOnce(&mut Request, &mut String)) -> Vec<u8> {
    let mut req = Request {
        nonce: ch.nonce.clone(),
        transaction: ch.transaction.clone(),
        purpose: ch.purpose.clone(),
        new_key: crypto::public_key_from_seed(seed).to_vec(),
        intent_digest: ch.intent_digest.clone(),
    };
    let mut audience = ch.audience.clone();
    edit(&mut req, &mut audience);
    sdk::prove(seed, &audience, &req).unwrap().to_vec()
}

fn honest(seed: &[u8; 32], ch: &Challenge) -> Vec<u8> {
    prove(seed, ch, |_, _| {})
}

fn complete(h: &Harness, session: &str, transaction: &[u8], proof: &[u8]) -> u16 {
    let body = format!(
        r#"{{"transaction":"{}","proof":"{}"}}"#,
        hex(transaction),
        hex(proof)
    );
    let cookie = if session.is_empty() {
        String::new()
    } else {
        format!("Cookie: session={session}\r\n")
    };
    let mut stream = TcpStream::connect(h.addr).unwrap();
    let request = format!(
        "POST /enroll/complete HTTP/1.1\r\nHost: dawn.example\r\n{cookie}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let _ = stream.shutdown(Shutdown::Write);
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    text.strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no response: {text:?}"))
}

#[test]
fn an_enrollment_completes_once_with_the_records_association() {
    let h = harness();
    let ch = begin(&h, "s1");
    assert_eq!(
        complete(&h, "s1", &ch.transaction, &honest(&KEY_SEED, &ch)),
        204
    );
    assert_eq!(
        h.svc.recorded(),
        vec![Association {
            account: b"acct-1".to_vec(),
            key: crypto::public_key_from_seed(&KEY_SEED).to_vec(),
            purpose: "add-key".to_string(),
        }]
    );
    assert_eq!(ch.audience, AUDIENCE);
    assert_eq!(ch.intent_digest, Sha256::digest(INTENT).to_vec());
    assert!(ch.nonce.len() >= 16);
    assert_eq!(ch.expires, T0 + DEFAULT_TTL_SECS);
}

#[test]
fn an_enroller_refuses_an_audience_the_binding_does_not_accept() {
    // The integration is a required argument — an enroller without one does not compile, which
    // is this lane's "no possession-alone mode". The audience is checked at construction.
    let built = Enroller::new(
        "",
        Arc::new(Service::default()),
        Box::new(|| T0),
        Box::new(|_: &mut [u8]| Ok(())),
    );
    assert!(built.is_err());
}

#[test]
fn nothing_can_be_substituted() {
    type Run = fn(&Harness) -> u16;
    let cases: Vec<(&str, Run, u16)> = vec![
        (
            "another key proves for the record's key",
            |h| {
                let ch = begin(h, "s1");
                complete(h, "s1", &ch.transaction, &honest(&OTHER_SEED, &ch))
            },
            401,
        ),
        (
            "another transaction's proof",
            |h| {
                let (first, second) = (begin(h, "s1"), begin(h, "s1"));
                complete(h, "s1", &first.transaction, &honest(&KEY_SEED, &second))
            },
            401,
        ),
        (
            "a proof over another purpose",
            |h| {
                let ch = begin(h, "s1");
                let proof = prove(&KEY_SEED, &ch, |r, _| r.purpose = "recover".to_string());
                complete(h, "s1", &ch.transaction, &proof)
            },
            401,
        ),
        (
            "a proof for another audience",
            |h| {
                let ch = begin(h, "s1");
                let proof = prove(&KEY_SEED, &ch, |_, a| {
                    *a = "https://evil.example/api".to_string()
                });
                complete(h, "s1", &ch.transaction, &proof)
            },
            401,
        ),
        (
            "a proof over another intent",
            |h| {
                let ch = begin(h, "s1");
                let proof = prove(&KEY_SEED, &ch, |r, _| {
                    r.intent_digest = Sha256::digest(b"acct-2 add-key").to_vec()
                });
                complete(h, "s1", &ch.transaction, &proof)
            },
            401,
        ),
        (
            "a proof over another nonce",
            |h| {
                let ch = begin(h, "s1");
                let proof = prove(&KEY_SEED, &ch, |r, _| r.nonce = vec![0xee; 16]);
                complete(h, "s1", &ch.transaction, &proof)
            },
            401,
        ),
        (
            "another session completes",
            |h| {
                let ch = begin(h, "s1");
                complete(h, "s2", &ch.transaction, &honest(&KEY_SEED, &ch))
            },
            403,
        ),
        (
            "no session completes",
            |h| {
                let ch = begin(h, "s1");
                complete(h, "", &ch.transaction, &honest(&KEY_SEED, &ch))
            },
            403,
        ),
        (
            "an unknown transaction",
            |h| {
                let ch = begin(h, "s1");
                complete(h, "s1", &[0x77; 16], &honest(&KEY_SEED, &ch))
            },
            404,
        ),
    ];
    for (name, run, want) in cases {
        let h = harness();
        assert_eq!(run(&h), want, "{name}");
        assert!(
            h.svc.recorded().is_empty(),
            "{name}: an association was recorded"
        );
    }
}

#[test]
fn a_record_with_no_authorization_completes_for_no_one() {
    // prepare refuses to build one; a record the integration holds without one is still never
    // completed, least of all by a request that carries no session either.
    let h = harness();
    let ch = begin(&h, "s1");
    {
        let mut s = h.svc.0.lock().unwrap();
        s.records
            .get_mut(&ch.transaction)
            .unwrap()
            .authorization
            .clear();
    }
    assert_eq!(
        complete(&h, "", &ch.transaction, &honest(&KEY_SEED, &ch)),
        403
    );
    assert!(h.svc.recorded().is_empty());
}

#[test]
fn a_completed_enrollment_cannot_be_replayed() {
    let h = harness();
    let ch = begin(&h, "s1");
    let proof = honest(&KEY_SEED, &ch);
    assert_eq!(complete(&h, "s1", &ch.transaction, &proof), 204);
    assert_eq!(complete(&h, "s1", &ch.transaction, &proof), 409);
    // The same proof against a fresh transaction for the same key and session: its nonce and
    // transaction are not the ones the proof covers.
    let fresh = begin(&h, "s1");
    assert_eq!(complete(&h, "s1", &fresh.transaction, &proof), 401);
    assert_eq!(h.svc.recorded().len(), 1);
}

#[test]
fn concurrent_completions_record_one() {
    let h = Arc::new(harness());
    let ch = begin(&h, "s1");
    let proof = honest(&KEY_SEED, &ch);
    let threads: Vec<_> = (0..24)
        .map(|_| {
            let (h, t, p) = (Arc::clone(&h), ch.transaction.clone(), proof.clone());
            std::thread::spawn(move || complete(&h, "s1", &t, &p))
        })
        .collect();
    let statuses: Vec<u16> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        statuses.iter().filter(|&&s| s == 204).count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses.iter().all(|&s| s == 204 || s == 409),
        "{statuses:?}"
    );
    assert_eq!(h.svc.recorded().len(), 1);
}

#[test]
fn an_expired_enrollment_is_gone() {
    for (at, want) in [
        (T0 + DEFAULT_TTL_SECS - 1, 204),
        (T0 + DEFAULT_TTL_SECS, 404),
    ] {
        let h = harness();
        let ch = begin(&h, "s1");
        h.clock.store(at, Ordering::SeqCst);
        assert_eq!(
            complete(&h, "s1", &ch.transaction, &honest(&KEY_SEED, &ch)),
            want,
            "at T0+{}",
            at - T0
        );
    }
}

#[test]
fn an_integration_that_cannot_answer_fails_closed() {
    type Fault = fn(&mut State);
    let faults: Vec<(&str, Fault)> = vec![
        ("load down", |s| s.load_down = true),
        ("complete down", |s| s.complete_down = true),
        ("another transaction's record", |s| s.wrong_record = true),
    ];
    for (name, fault) in faults {
        let h = harness();
        let ch = begin(&h, "s1");
        let _ = begin(&h, "s1"); // a second record, for wrong_record to return
        fault(&mut h.svc.0.lock().unwrap());
        assert_eq!(
            complete(&h, "s1", &ch.transaction, &honest(&KEY_SEED, &ch)),
            503,
            "{name}"
        );
        assert!(h.svc.recorded().is_empty(), "{name}");
    }
}

#[test]
fn prepare_refuses_what_could_not_complete() {
    let h = harness();
    let good = Begin {
        authorization: b"s1".to_vec(),
        account: b"acct-1".to_vec(),
        purpose: "add-key".to_string(),
        new_key: crypto::public_key_from_seed(&KEY_SEED).to_vec(),
        intent: INTENT.to_vec(),
    };
    type Edit = fn(&mut Begin);
    let edits: Vec<(&str, Edit)> = vec![
        ("no authorization", |b| b.authorization.clear()),
        ("no account", |b| b.account.clear()),
        ("a short key", |b| b.new_key.truncate(31)),
        ("no purpose", |b| b.purpose.clear()),
        ("a control character", |b| {
            b.purpose = "add\nkey".to_string()
        }),
    ];
    for (name, edit) in edits {
        let mut b = good.clone();
        edit(&mut b);
        assert!(h.enroller.prepare(&b).is_err(), "{name}");
    }
    assert!(h.enroller.prepare(&good).is_ok());
}
