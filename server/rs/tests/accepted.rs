//! archon#93: the delegation is `[accepted_at, accepted_at + valid_for)`, and `accepted_at` is
//! the server's clock when it ACCEPTED the answer — taken once, handed to the law, and returned
//! with the collected answer. The same cases as the Go and TypeScript lanes'
//! (server/go/login/accepted_test.go, server/ts/test/accepted.test.ts): they go red if the time
//! is stamped at collection, if the law and the collecting client are told different instants,
//! or if a refused answer before the accepted one moves it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use archon_core::{crypto, keytext};
use archon_sdk::login;
use archon_server::{AdmitAuthority, Config, Handler, Request, COLLECT_HEADER};

const AUDIENCE: &str = "https://dawn.example/api";
const T0: u64 = 1_789_034_640;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn seed_for(b: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, s) in seed.iter_mut().enumerate() {
        *s = b.wrapping_add(i as u8);
    }
    seed
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

fn handler(admit: Option<AdmitAuthority>) -> (Handler, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let n = Arc::new(AtomicU64::new(0));
    let mut cfg = Config::new(AUDIENCE)
        .clock(Box::new(move || c.load(Ordering::SeqCst)))
        .entropy(Box::new(move |b: &mut [u8]| {
            b.fill(n.fetch_add(1, Ordering::SeqCst) as u8 + 1);
            Ok(())
        }));
    if let Some(a) = admit {
        cfg = cfg.admit(a);
    }
    (Handler::new(cfg).expect("Handler::new"), clock)
}

/// Begin, wait, answer `answers` times 4 s apart, wait, collect: the collected body.
fn accept_later(
    h: &Handler,
    clock: &AtomicU64,
    before_answer: u64,
    before_collect: u64,
    answers: usize,
) -> serde_json::Value {
    let (browser_seed, person_seed) = (seed_for(3), seed_for(150));
    let browser = crypto::public_key_from_seed(&browser_seed);
    let begun = h.handle(&req(
        "POST",
        "/",
        &format!(
            "{{\"browser\":\"{}\",\"scope\":[\"read:projects\"],\"valid_for\":3600}}",
            keytext::encode_key(&browser)
        ),
        &[],
    ));
    assert_eq!(begun.status, 201);
    let v: serde_json::Value = serde_json::from_slice(&begun.body).unwrap();
    let id = v["id"].as_str().unwrap().to_string();
    let request = login::Request {
        id: unhex(&id),
        nonce: unhex(v["nonce"].as_str().unwrap()),
        browser: browser.to_vec(),
        scope: vec!["read:projects".to_string()],
        valid_for: 3600,
    };
    let proof = login::prove(&person_seed, AUDIENCE, &request).unwrap();
    let answer = format!(
        "{{\"principal\":\"{}\",\"possession\":\"{}\"}}",
        keytext::encode_key(&crypto::public_key_from_seed(&person_seed)),
        hex(&proof)
    );
    clock.fetch_add(before_answer, Ordering::SeqCst);
    for _ in 0..answers {
        h.handle(&req("POST", &format!("/{id}/answer"), &answer, &[]));
        clock.fetch_add(4, Ordering::SeqCst);
    }
    clock.fetch_add(before_collect, Ordering::SeqCst);
    let collect = hex(&login::prove_collect(&browser_seed, AUDIENCE, &request).unwrap());
    let collected = h.handle(&req(
        "GET",
        &format!("/{id}/answer"),
        "",
        &[(COLLECT_HEADER, &collect)],
    ));
    assert_eq!(
        collected.status,
        200,
        "{}",
        String::from_utf8_lossy(&collected.body)
    );
    serde_json::from_slice(&collected.body).unwrap()
}

/// The RFC 3339 spelling the handler uses for every time on the wire.
fn rfc3339(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    // Civil-from-days (Howard Hinnant), for dates after 1970.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[test]
fn the_delegation_starts_when_the_answer_is_accepted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let (h, clock) = handler(Some(Box::new(move |_, _, _, req| {
        s.lock().unwrap().push(req.accepted_at);
        Ok(())
    })));
    let got = accept_later(&h, &clock, 7, 40, 1);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![T0 + 7],
        "the law is handed the instant the answer was accepted"
    );
    // Collected 44 s later than that, and still the acceptance instant.
    assert_eq!(got["accepted_at"], rfc3339(T0 + 7));
}

#[test]
fn a_refused_answer_does_not_start_the_delegation() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let c = Arc::clone(&calls);
    let (h, clock) = handler(Some(Box::new(move |_, _, _, req| {
        let mut calls = c.lock().unwrap();
        calls.push(req.accepted_at);
        if calls.len() == 1 {
            Err("not yet".to_string())
        } else {
            Ok(())
        }
    })));
    // Two answers 4 s apart: the law refuses the first and accepts the second.
    let got = accept_later(&h, &clock, 5, 10, 2);
    assert_eq!(*calls.lock().unwrap(), vec![T0 + 5, T0 + 9]);
    assert_eq!(
        got["accepted_at"],
        rfc3339(T0 + 9),
        "the answer that was STORED starts it"
    );
}

#[test]
fn a_proof_only_service_is_told_the_start_too() {
    // No law, so nothing is handed Admitted: the collected answer is how such a service learns it.
    let (h, clock) = handler(None);
    let got = accept_later(&h, &clock, 3, 20, 1);
    assert_eq!(got["accepted_at"], rfc3339(T0 + 3));
}

#[test]
fn the_helper_spells_times_as_the_handler_does() {
    // A known instant: the CLIs' statement fixtures show T0 + 8 h as 2026-09-10T18:04:00Z.
    assert_eq!(rfc3339(1_789_034_640), "2026-09-10T10:04:00Z");
}
