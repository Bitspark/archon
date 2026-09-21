//! `archon sign` — sign raw bytes, raw or in a domain.
//!
//!   archon sign (--key-file <pkcs8.pem> | --seed <hex>) [--domain <d>] [--in <file>]
//!
//! The message is the input, verbatim — stdin by default, `--in <file>` otherwise. The
//! signature is printed as 128 lowercase hex characters. With `--domain`, the signature is
//! domain-separated (Ed25519ph with the domain as RFC 8032 context) and will verify only
//! in that domain; without it, the signature is raw Ed25519 over the bytes, and separation
//! is the caller's problem. This is NOT thesmos's `sign` — that one signs a *fact* and
//! knows what a fact is. This one knows nothing.

use archon_core::crypto::{sign, sign_in_domain};
use archon_core::hexbytes::to_hex;

use crate::cmd::resolve_seed;
use crate::io::{read_bytes, wants_help};

const USAGE: &str =
    "usage: archon sign (--key-file <pkcs8.pem> | --seed <hex>) [--domain <d>] [--in <file>]\n  \
signs the input bytes (stdin, or --in <file>) and prints the signature as hex. --domain \
makes the signature domain-separated: it verifies in that domain and nowhere else.";

/// Entry point for `archon sign`.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    let mut key_file: Option<String> = None;
    let mut seed_hex: Option<String> = None;
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
            "--key-file" => key_file = Some(value.clone()),
            "--seed" => seed_hex = Some(value.clone()),
            "--domain" => domain = Some(value.clone()),
            "--in" => in_path = Some(value.clone()),
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        i += 2;
    }
    if key_file.is_none() && seed_hex.is_none() {
        return Err(format!("one of --key-file or --seed is required\n{USAGE}"));
    }
    let seed = resolve_seed(seed_hex.as_deref(), key_file.as_deref(), USAGE)?;
    let message = read_bytes(in_path.as_deref())?;
    let sig = match domain.as_deref() {
        Some(d) => sign_in_domain(&seed, d, &message)?,
        None => sign(&seed, &message),
    };
    println!("{}", to_hex(&sig));
    Ok(())
}
