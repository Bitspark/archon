//! An OUTSIDE consumer of archon's server tier from crates.io (see ../Cargo.toml): begin, read,
//! answer with the sdk's proof, collect, through the PUBLISHED `bitspark-archon-server`, with a
//! law that checks the `Admitted` it is handed. Every `@bitspark/archon-server` on npm through
//! 0.8.1 shipped empty (archon#55) because nothing imported it; no release step depended on the
//! Rust server crate either.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use archon_core::{crypto, keytext};
use archon_sdk::login;
use archon_server::{Admitted, Config, Handler, Request, COLLECT_HEADER};
use serde_json::{json, Value};

const AUDIENCE: &str = "https://service.example/api";
const VALID_FOR: u32 = 60;

fn main() {
    let seed = [0x11u8; 32]; // P: the person's key
    let pk = crypto::public_key_from_seed(&seed);
    let k_seed = [0x22u8; 32]; // K: the key-less client's key
    let browser = crypto::public_key_from_seed(&k_seed);

    // The law sees exactly what the proof covered, or the login is refused.
    let law_saw = Arc::new(AtomicBool::new(false));
    let (saw, want_browser, want_principal) = (law_saw.clone(), browser.to_vec(), pk.to_vec());
    let cfg = Config::new(AUDIENCE).admit(Box::new(
        move |b: &[u8], p: &[u8], _authority: &[u8], req: &Admitted| {
            let ok = b == want_browser.as_slice()
                && p == want_principal.as_slice()
                && !req.id.is_empty()
                && req.scope == vec!["read:projects".to_string()]
                && req.valid_for == VALID_FOR;
            saw.store(ok, Ordering::SeqCst);
            if ok {
                Ok(())
            } else {
                Err("the law was handed something other than what the proof covered".to_string())
            }
        },
    ));
    let handler = Handler::new(cfg).unwrap_or_else(|e| fail(&format!("Handler::new: {e}")));

    // The handler is mounted at <audience>/login; these paths are relative to that mount.
    let call = |method: &str, path: &str, body: Option<Value>, headers: Vec<(String, String)>| {
        let mut headers = headers;
        let body = match body {
            Some(v) => {
                headers.push(("content-type".to_string(), "application/json".to_string()));
                v.to_string().into_bytes()
            }
            None => Vec::new(),
        };
        let resp = handler.handle(&Request {
            method: method.to_string(),
            path: path.to_string(),
            body,
            headers,
        });
        let parsed: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        (resp.status, parsed)
    };

    let (begin_status, begun) = call(
        "POST",
        "/",
        Some(
            json!({"browser": keytext::encode_key(&browser), "scope": ["read:projects"], "valid_for": VALID_FOR}),
        ),
        vec![],
    );
    let id = begun["id"].as_str().unwrap_or_default().to_string();
    let nonce = begun["nonce"].as_str().unwrap_or_default().to_string();

    let (read_status, shown) = call("GET", &format!("/{id}"), None, vec![]);
    let shown_scope: Vec<String> = shown["scope"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let shown_valid_for = shown["valid_for"].as_u64().unwrap_or(0) as u32;

    let req = login::Request {
        id: unhex(&id),
        nonce: unhex(&nonce),
        browser: browser.to_vec(),
        scope: shown_scope,
        valid_for: shown_valid_for,
    };
    let proof = login::prove(&seed, AUDIENCE, &req)
        .unwrap_or_else(|e| fail(&format!("sdk login::prove: {e}")));
    let (answer_status, _) = call(
        "POST",
        &format!("/{id}/answer"),
        Some(json!({"principal": keytext::encode_key(&pk), "possession": hex(&proof)})),
        vec![],
    );

    let collect_proof = login::prove_collect(&k_seed, AUDIENCE, &req)
        .unwrap_or_else(|e| fail(&format!("sdk login::prove_collect: {e}")));
    let (collect_status, answer) = call(
        "GET",
        &format!("/{id}/answer"),
        None,
        vec![(COLLECT_HEADER.to_string(), hex(&collect_proof))],
    );
    let verified = answer["principal"].as_str() == Some(keytext::encode_key(&pk).as_str())
        && login::verify(
            &pk,
            AUDIENCE,
            &req,
            &unhex(answer["possession"].as_str().unwrap_or_default()),
        );
    let saw = law_saw.load(Ordering::SeqCst);

    println!(
        "server: begin {begin_status}, read {read_status}, answer {answer_status}, collect {collect_status}; law saw the request={saw}; login verified={verified}"
    );
    if !(begin_status == 201
        && read_status == 200
        && answer_status == 204
        && collect_status == 200
        && saw
        && verified)
    {
        fail("the published bitspark-archon-server does not behave as the release claims");
    }
    println!("OK: bitspark-archon-server from crates.io");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

fn fail(msg: &str) -> ! {
    eprintln!("FAIL: {msg}");
    std::process::exit(1)
}
