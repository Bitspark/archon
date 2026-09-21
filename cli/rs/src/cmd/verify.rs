//! `archon verify` — verify a signature over raw bytes, raw or in a domain.
//!
//!   archon verify --pubkey <ed25519:...|hex> --sig <hex> [--domain <d>] [--in <file>]
//!
//! The message is the input, verbatim — stdin by default, `--in <file>` otherwise. Prints
//! `valid` (exit 0) or `invalid` (exit 1) on stdout: a verdict, not a usage error, so a
//! bad signature is silent on stderr. With `--domain`, the signature must have been made
//! in that domain; a raw signature over the same bytes is `invalid` there, and a domain
//! signature is `invalid` without `--domain`. Not thesmos's `verify` — that one verifies
//! facts, proofs and freshness. This one verifies bytes.

use archon_core::crypto::{verify, verify_in_domain};
use archon_core::hexbytes::{pubkey_from_hex, signature_from_hex};
use archon_core::keytext::decode_key;

use crate::io::{read_bytes, wants_help};

const USAGE: &str =
    "usage: archon verify --pubkey <ed25519:...|hex> --sig <hex> [--domain <d>] [--in <file>]\n  \
verifies the signature over the input bytes (stdin, or --in <file>); prints valid (exit 0) \
or invalid (exit 1). --domain checks a domain-separated signature.";

/// Entry point for `archon verify`.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    let mut pubkey: Option<Vec<u8>> = None;
    let mut sig: Option<[u8; 64]> = None;
    let mut domain: Option<String> = None;
    let mut in_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        let value = args
            .get(i + 1)
            .filter(|v| !v.is_empty() || flag == "--domain")
            .ok_or_else(|| format!("flag {flag:?} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--pubkey" => pubkey = Some(parse_pubkey(value)?),
            "--sig" => sig = Some(signature_from_hex(value).map_err(|e| format!("--sig: {e}"))?),
            "--domain" => domain = Some(value.clone()),
            "--in" => in_path = Some(value.clone()),
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        i += 2;
    }
    let (Some(pubkey), Some(sig)) = (pubkey, sig) else {
        return Err(format!("--pubkey and --sig are required\n{USAGE}"));
    };
    let message = read_bytes(in_path.as_deref())?;
    let ok = match domain.as_deref() {
        Some(d) => verify_in_domain(&pubkey, d, &message, &sig),
        None => verify(&pubkey, &message, &sig),
    };
    if ok {
        println!("valid");
        Ok(())
    } else {
        // A verdict, not a usage error: report on stdout and exit 1 without an
        // "archon verify:" line on stderr.
        println!("invalid");
        std::process::exit(1);
    }
}

/// A public key as canonical key text (`ed25519:<hex>`) or bare hex.
fn parse_pubkey(value: &str) -> Result<Vec<u8>, String> {
    if value.starts_with("ed25519:") {
        decode_key(value).map_err(|e| format!("--pubkey: {e}"))
    } else {
        pubkey_from_hex(value)
            .map(|k| k.to_vec())
            .map_err(|e| format!("--pubkey: {e}"))
    }
}
