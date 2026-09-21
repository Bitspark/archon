//! Conformance CLI (rs, sdk) — a dev/CI artifact, NOT part of the published lib API. Built
//! only under the `conformance-cli` feature. Same `conformance v1` protocol as the floor's
//! CLI: `conformance <family>` reads the whole vectors/sdk.json on stdin, selects its
//! family, recomputes each result from the case INPUTS, emits one NDJSON line per case.
//!
//!   possession_prove  : in `{name, seed, domain, nonce, binding}`          out `{"name","result":{"ok":"<128-hex>"}|{"error":true}}`
//!   possession_verify : in `{name, pubkey, domain, nonce, binding, sig}`   out `{"name","valid":<bool>}`
//!   envelope_seal     : in `{name, seed, domain, payload}`                 out `{"name","result":{"ok":"<hex>"}|{"error":true}}`
//!   envelope_open     : in `{name, envelope, domain}`                      out `{"name","result":{"ok":{"pubkey":"<hex>","payload":"<hex>"}}|{"error":true}}`

use archon_sdk::{envelope, login, possession};
use serde_json::{json, Value};
use std::io::Read;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("case input is not valid hex"))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The oracle distinguishes success-with-a-value from failure, never the message.
fn result_json(r: Result<Value, String>) -> Value {
    match r {
        Ok(v) => json!({ "ok": v }),
        Err(_) => json!({ "error": true }),
    }
}

/// The oracle's spelling of a login request (bytes as hex, scope entries as hex).
fn login_request(c: &Value) -> Result<login::Request, String> {
    let r = &c["request"];
    let s = |k: &str| r[k].as_str().unwrap_or("");
    let mut scope = Vec::new();
    for entry in r["scope"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
        let bytes = hex_decode(entry.as_str().unwrap_or(""));
        scope.push(String::from_utf8(bytes).map_err(|e| format!("scope entry is not UTF-8: {e}"))?);
    }
    Ok(login::Request {
        id: hex_decode(s("id")),
        nonce: hex_decode(s("nonce")),
        browser: hex_decode(s("browser")),
        scope,
        valid_for: r["valid_for"].as_u64().unwrap_or(0) as u32,
    })
}

/// A seed that may be the wrong size: the error result, not a panic.
fn seed32_checked(c: &Value) -> Result<[u8; 32], String> {
    let bytes = hex_decode(c["seed"].as_str().unwrap_or(""));
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("seed is {} bytes, want 32", bytes.len()))
}

fn main() {
    let family = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: conformance <family>");
        std::process::exit(2);
    });
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let doc: Value = serde_json::from_str(&input).expect("stdin is not valid JSON");
    let cases = doc
        .get(&family)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("unknown family: {family}"));

    for c in cases {
        let name = c["name"].as_str().unwrap_or("").to_string();
        let s = |k: &str| c[k].as_str().unwrap();
        let line = match family.as_str() {
            "possession_prove" => {
                let r = seed32_checked(c)
                    .and_then(|seed| {
                        possession::prove(
                            &seed,
                            s("domain"),
                            &hex_decode(s("nonce")),
                            &hex_decode(s("binding")),
                        )
                    })
                    .map(|sig| Value::from(hex_encode(&sig)));
                json!({ "name": name, "result": result_json(r) })
            }
            "possession_verify" => json!({ "name": name, "valid": possession::verify(
                &hex_decode(s("pubkey")), s("domain"), &hex_decode(s("nonce")), &hex_decode(s("binding")), &hex_decode(s("sig"))) }),
            "envelope_seal" => {
                let r = seed32_checked(c)
                    .and_then(|seed| envelope::seal(&seed, s("domain"), &hex_decode(s("payload"))))
                    .map(|e| Value::from(hex_encode(&e)));
                json!({ "name": name, "result": result_json(r) })
            }
            "envelope_open" => {
                let r = envelope::open(&hex_decode(s("envelope")), s("domain"))
                    .map(|o| json!({ "pubkey": hex_encode(&o.pubkey), "payload": hex_encode(&o.payload) }));
                json!({ "name": name, "result": result_json(r) })
            }
            // vectors/login.json — `request` is {id, nonce, browser, scope[hex], valid_for};
            // a scope entry that is not UTF-8 cannot become a String, which is the same
            // refusal the scheme would make, so it is reported as the error result.
            "login_audience" => {
                let r = login::derive_audience(s("url"))
                    .map(|(aud, id)| json!({ "audience": aud, "id": hex_encode(&id) }));
                json!({ "name": name, "result": result_json(r) })
            }
            "login_binding" => {
                let r = login_request(c)
                    .and_then(|req| {
                        login::binding(c["role"].as_u64().unwrap_or(0) as u8, s("audience"), &req)
                    })
                    .map(|b| Value::from(hex_encode(&b)));
                json!({ "name": name, "result": result_json(r) })
            }
            "login_prove" => {
                let r = seed32_checked(c)
                    .and_then(|seed| {
                        login_request(c).and_then(|req| login::prove(&seed, s("audience"), &req))
                    })
                    .map(|sig| Value::from(hex_encode(&sig)));
                json!({ "name": name, "result": result_json(r) })
            }
            "login_verify" => {
                let valid = login_request(c)
                    .map(|req| {
                        login::verify(
                            &hex_decode(s("pubkey")),
                            s("audience"),
                            &req,
                            &hex_decode(s("sig")),
                        )
                    })
                    .unwrap_or(false);
                json!({ "name": name, "valid": valid })
            }
            "login_collect_prove" => {
                let r = seed32_checked(c)
                    .and_then(|seed| {
                        login_request(c)
                            .and_then(|req| login::prove_collect(&seed, s("audience"), &req))
                    })
                    .map(|sig| Value::from(hex_encode(&sig)));
                json!({ "name": name, "result": result_json(r) })
            }
            "login_collect_verify" => {
                let valid = login_request(c)
                    .map(|req| login::verify_collect(s("audience"), &req, &hex_decode(s("sig"))))
                    .unwrap_or(false);
                json!({ "name": name, "valid": valid })
            }
            other => panic!("unknown family: {other}"),
        };
        println!("{line}");
    }
}
