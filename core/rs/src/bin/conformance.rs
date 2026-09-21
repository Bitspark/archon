//! Conformance CLI (rs) — a dev/CI artifact, NOT part of the published lib API. It is
//! built only under the `conformance-cli` feature, so the default build keeps archon's
//! austerity: `ed25519-dalek` and nothing else.
//!
//! Implements the `conformance v1` protocol archon inherits from thesmos ADR 0006:
//! `conformance <family>` reads the whole vectors/identity.json on stdin, selects its
//! family's cases, recomputes each result from the case INPUTS (ignoring the expected
//! value the oracle carries), and writes one NDJSON line per case to stdout in input
//! order. The language-agnostic harness (`conformance/harness.mjs`) drives this and the
//! go/ts CLIs as black boxes and asserts each line against the oracle.
//!
//!   pubkey_from_seed : in `{name, seed}`                out `{"name","pubkey":"<64-hex>"}`
//!   key_encode       : in `{name, pubkey}`              out `{"name","text":"<key text>"}`
//!   keycodec         : in `{name, kind, key?|pem?}`     out `{"name","result":{"ok":"<PEM|hex>"}|{"error":true}}`
//!   signature_verify : in `{name, pubkey, message, sig}` out `{"name","valid":<bool>}`
//!   hex_decode       : in `{name, kind, hex}`            out `{"name","result":{"ok":"<hex>"}|{"error":true}}`
//!   domain_sign      : in `{name, seed, domain, message}` out `{"name","result":{"ok":"<128-hex>"}|{"error":true}}`
//!   domain_verify    : in `{name, pubkey, domain, message, sig}` out `{"name","valid":<bool>}`

use archon_core::{crypto, hexbytes, keycodec, keytext};
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

/// Every codec conversion returns Result<_, String>; the oracle only distinguishes
/// success-with-a-value from failure, never the message, so errors collapse to
/// `{"error":true}`. That is deliberate: the reject *reason* is a core's own diagnostic,
/// the reject *decision* is what must agree byte-for-byte across three languages.
fn result_json(r: Result<String, String>) -> Value {
    match r {
        Ok(v) => json!({ "ok": v }),
        Err(_) => json!({ "error": true }),
    }
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
        let line = match family.as_str() {
            "pubkey_from_seed" => {
                let seed: [u8; 32] = hex_decode(c["seed"].as_str().unwrap())
                    .try_into()
                    .expect("seed is not 32 bytes");
                json!({ "name": name, "pubkey": hex_encode(&crypto::public_key_from_seed(&seed)) })
            }
            "key_encode" => {
                let pubkey = hex_decode(c["pubkey"].as_str().unwrap());
                json!({ "name": name, "text": keytext::encode_key(&pubkey) })
            }
            "keycodec" => {
                let kind = c["kind"].as_str().unwrap();
                let r = match kind {
                    "encode_pkcs8" => {
                        keycodec::seed_to_pkcs8_pem(&hex_decode(c["key"].as_str().unwrap()))
                    }
                    "encode_spki" => {
                        keycodec::pubkey_to_spki_pem(&hex_decode(c["key"].as_str().unwrap()))
                    }
                    "decode_pkcs8" => keycodec::pkcs8_pem_to_seed(c["pem"].as_str().unwrap())
                        .map(|k| hex_encode(&k)),
                    "decode_spki" => keycodec::spki_pem_to_pubkey(c["pem"].as_str().unwrap())
                        .map(|k| hex_encode(&k)),
                    other => panic!("unknown keycodec kind: {other}"),
                };
                json!({ "name": name, "result": result_json(r) })
            }
            "signature_verify" => {
                let pubkey = hex_decode(c["pubkey"].as_str().unwrap());
                let message = hex_decode(c["message"].as_str().unwrap());
                let sig = hex_decode(c["sig"].as_str().unwrap());
                json!({ "name": name, "valid": crypto::verify(&pubkey, &message, &sig) })
            }
            "hex_decode" => {
                let text = c["hex"].as_str().unwrap();
                let r = match c["kind"].as_str().unwrap() {
                    "seed" => hexbytes::seed_from_hex(text).map(|b| hexbytes::to_hex(&b)),
                    "pubkey" => hexbytes::pubkey_from_hex(text).map(|b| hexbytes::to_hex(&b)),
                    "signature" => hexbytes::signature_from_hex(text).map(|b| hexbytes::to_hex(&b)),
                    other => panic!("unknown hex_decode kind: {other}"),
                };
                json!({ "name": name, "result": result_json(r) })
            }
            "domain_sign" => {
                let seed: [u8; 32] = hex_decode(c["seed"].as_str().unwrap())
                    .try_into()
                    .expect("seed is not 32 bytes");
                let message = hex_decode(c["message"].as_str().unwrap());
                let r = crypto::sign_in_domain(&seed, c["domain"].as_str().unwrap(), &message)
                    .map(|s| hex_encode(&s));
                json!({ "name": name, "result": result_json(r) })
            }
            "domain_verify" => {
                let pubkey = hex_decode(c["pubkey"].as_str().unwrap());
                let message = hex_decode(c["message"].as_str().unwrap());
                let sig = hex_decode(c["sig"].as_str().unwrap());
                let domain = c["domain"].as_str().unwrap();
                json!({ "name": name, "valid": crypto::verify_in_domain(&pubkey, domain, &message, &sig) })
            }
            other => panic!("unknown family: {other}"),
        };
        println!("{line}");
    }
}
