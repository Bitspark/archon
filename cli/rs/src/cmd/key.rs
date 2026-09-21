//! `archon key` — convert between raw key bytes and the canonical key text, or between
//! raw key/seed bytes and the standard PEM containers (PKCS#8 v1 / SPKI).
//!
//!   - `archon key encode <pubkey-hex>` → prints `encode_key(bytes)` to stdout.
//!   - `archon key decode <ed25519:…>`  → prints the decoded bytes as hex to stdout.
//!   - `archon key pkcs8 encode <seed-hex>` → prints the PKCS#8 v1 PEM to stdout.
//!   - `archon key pkcs8 decode` (PEM on stdin) → prints the seed bytes as hex.
//!   - `archon key spki encode <pubkey-hex>`  → prints the SPKI PEM to stdout.
//!   - `archon key spki decode` (PEM on stdin) → prints the pubkey bytes as hex.
//!   - `archon key pub [--in <file>|--seed <hex>] [--format spki|text|hex]` → the public
//!     key of a private key.
//!
//! Every hex input goes through the floor's typed decoders (`hexbytes`), so a 31-byte
//! "public key" is refused here exactly as the library refuses it. PEM decode is total: a
//! malformed block is a clean error to stderr and a non-zero exit, never a panic.

use archon_core::crypto::public_key_from_seed;
use archon_core::hexbytes::{pubkey_from_hex, seed_from_hex, to_hex};
use archon_core::keycodec::{
    pkcs8_pem_to_seed, pubkey_to_spki_pem, seed_to_pkcs8_pem, spki_pem_to_pubkey,
};
use archon_core::keytext::{decode_key, encode_key};

use crate::cmd::key_store;
use crate::io::{read_text, take_in_flag, wants_help};
use crate::pubrender::{parse_pub_format, render_pubkey, PubFormat};

const USAGE: &str = "usage: archon key <encode <pubkey-hex>|decode <ed25519:...>|\
pkcs8 <encode <seed-hex>|decode>|spki <encode <pubkey-hex>|decode>|\
pub [--in <file>|--seed <hex>] [--format spki|text|hex]|\
add <name> [--seed <hex>|--seed-file <file>|--pkcs8 <file>]|list [--json]|\
rm <name> [--force]|default [<name>]|export <name> --reveal --out <file>>\n  \
pkcs8/spki decode read a PEM block on stdin (or --in <file>); \
pub derives the public key from a private key, default --format text.\n  \
add/list/rm/default/export are the password-protected seed store (ADR 0007 §A); \
keys live in $ARCHON_HOME/keys, default ~/.archon.";

/// Entry point for `archon key`.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    match args {
        // The store (ADR 0007 §A). Siblings of the codec arms below: `key
        // encode` converts bytes it is handed, `key add` keeps a seed. They share
        // the noun and nothing else.
        [op, rest @ ..] if op == "add" => key_store::run_add(rest),
        [op, rest @ ..] if op == "list" => key_store::run_list(rest),
        [op, rest @ ..] if op == "rm" => key_store::run_rm(rest),
        [op, rest @ ..] if op == "default" => key_store::run_default(rest),
        [op, rest @ ..] if op == "export" => key_store::run_export(rest),
        [op] if op == "list" => key_store::run_list(&[]),
        [op] if op == "default" => key_store::run_default(&[]),
        [op, value] if op == "encode" => {
            println!("{}", encode_key(&pubkey_from_hex(value)?));
            Ok(())
        }
        [op, value] if op == "decode" => {
            println!("{}", to_hex(&decode_key(value)?));
            Ok(())
        }
        [container, rest @ ..] if container == "pkcs8" => pkcs8(rest),
        [container, rest @ ..] if container == "spki" => spki(rest),
        [op, rest @ ..] if op == "pub" => pubkey(rest),
        _ => Err(USAGE.to_string()),
    }
}

/// `pkcs8 <encode <seed-hex>|decode>`: seed ⇄ PKCS#8 v1 PEM.
fn pkcs8(args: &[String]) -> Result<(), String> {
    match args {
        [op, seed_hex] if op == "encode" => {
            // keycodec emits the PEM with its own single trailing newline; print verbatim.
            print!("{}", seed_to_pkcs8_pem(&seed_from_hex(seed_hex)?)?);
            Ok(())
        }
        [op, rest @ ..] if op == "decode" => {
            let (rest, in_path) = take_in_flag(rest)?;
            if !rest.is_empty() {
                return Err(USAGE.to_string());
            }
            println!(
                "{}",
                to_hex(&pkcs8_pem_to_seed(&read_text(in_path.as_deref())?)?)
            );
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

/// `spki <encode <pubkey-hex>|decode>`: pubkey ⇄ SPKI PEM.
fn spki(args: &[String]) -> Result<(), String> {
    match args {
        [op, pubkey_hex] if op == "encode" => {
            print!("{}", pubkey_to_spki_pem(&pubkey_from_hex(pubkey_hex)?)?);
            Ok(())
        }
        [op, rest @ ..] if op == "decode" => {
            let (rest, in_path) = take_in_flag(rest)?;
            if !rest.is_empty() {
                return Err(USAGE.to_string());
            }
            println!(
                "{}",
                to_hex(&spki_pem_to_pubkey(&read_text(in_path.as_deref())?)?)
            );
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

/// `pub [--in <file>|--seed <hex>] [--format spki|text|hex]`: derive the PUBLIC key from a
/// PRIVATE key. `--format` is validated at parse time, so a bad format errors before any
/// input is read.
fn pubkey(args: &[String]) -> Result<(), String> {
    let mut in_path: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut fmt = PubFormat::Text;
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("flag {flag:?} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--in" if value.is_empty() => {
                return Err(format!("flag {flag:?} needs a value\n{USAGE}"));
            }
            "--in" => in_path = Some(value.clone()),
            "--seed" => seed_hex = Some(value.clone()),
            "--format" => fmt = parse_pub_format(value)?,
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        i += 2;
    }
    if in_path.is_some() && seed_hex.is_some() {
        return Err(format!("--in and --seed are mutually exclusive\n{USAGE}"));
    }
    let seed = match seed_hex {
        Some(hex) => seed_from_hex(&hex).map_err(|e| format!("--seed: {e}"))?,
        None => pkcs8_pem_to_seed(&read_text(in_path.as_deref())?)?,
    };
    print!("{}", render_pubkey(&public_key_from_seed(&seed), &fmt)?);
    Ok(())
}
