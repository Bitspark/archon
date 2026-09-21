//! Conformance CLI (rs, cli) — a dev/CI artifact, not part of the command's surface. Same
//! `conformance v1` protocol as the floor's and the sdk's: `conformance <family>` reads the
//! whole `vectors/keystore.json` on stdin, selects its family, recomputes each result from
//! the case INPUTS, and writes one NDJSON line per case to stdout in input order.
//!
//! ```text
//! keystore_seal : in {name, seed, password, salt, nonce, m_kib, t, p}
//!                 out {"name","result":{"ok":{"file","public_key"}}|{"error":true}}
//! keystore_open : in {name, file, password}
//!                 out {"name","result":{"ok":{"seed"}}|{"error":true}}
//! keystore_name : in {name, input}
//!                 out {"name","result":{"ok":<bool>}}
//! ```
//!
//! `archon-cli` is deliberately a binary-only crate — a thin presentation layer, never a
//! library surface — so this bin includes the format module by path rather than importing
//! it. That keeps the store out of anyone's dependency graph.

#[path = "../keystore.rs"]
mod keystore;

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

fn str_of(c: &Value, k: &str) -> String {
    c.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn main() {
    let family = match std::env::args().nth(1) {
        Some(f) => f,
        None => {
            eprintln!("usage: conformance <family>");
            std::process::exit(2);
        }
    };
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .expect("could not read stdin");
    let doc: Value = serde_json::from_str(&raw).expect("stdin is not valid JSON");
    let cases = doc
        .get(&family)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("unknown family: {family}"));

    for c in cases {
        let name = str_of(c, "name");
        let result: Value = match family.as_str() {
            "keystore_seal" => {
                let p = keystore::KeyParams {
                    memory_kib: c["m_kib"].as_u64().unwrap_or(0) as u32,
                    time: c["t"].as_u64().unwrap_or(0) as u32,
                    parallelism: c["p"].as_u64().unwrap_or(0) as u8,
                };
                match keystore::seal(
                    &hex_decode(&str_of(c, "seed")),
                    str_of(c, "password").as_bytes(),
                    &hex_decode(&str_of(c, "salt")),
                    &hex_decode(&str_of(c, "nonce")),
                    p,
                ) {
                    Ok(blob) => json!({"ok": {
                        "file": hex_encode(&blob),
                        "public_key": hex_encode(&blob[30..62]),
                    }}),
                    Err(_) => json!({ "error": true }),
                }
            }
            "keystore_open" => match keystore::open(
                &hex_decode(&str_of(c, "file")),
                str_of(c, "password").as_bytes(),
            ) {
                Ok(seed) => json!({ "ok": { "seed": hex_encode(&seed) } }),
                Err(_) => json!({ "error": true }),
            },
            "keystore_name" => {
                json!({ "ok": keystore::validate_name(&str_of(c, "input")).is_ok() })
            }
            other => panic!("unknown family: {other}"),
        };
        println!("{}", json!({ "name": name, "result": result }));
    }
}
