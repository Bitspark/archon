//! `archon keygen` — generate (or deterministically derive) an Ed25519 key pair.
//!
//! Draws a 32-byte seed from the OS CSPRNG (or `--seed <hex>` for a deterministic
//! derivation), derives the public key, and prints:
//!   - the canonical **public key** (`encode_key`) to **stdout** — the shareable part;
//!   - the **private key as a PKCS#8 v1 PEM**, either to a file (`--out <file>` — the
//!     recommended path, keeping the key out of terminal scrollback) or, by default, to
//!     **stderr** behind a clear SECRET warning. Never the raw seed hex.
//!
//! The RNG is the one deliberately-unpinned edge, and it lives here, in the CLI: the
//! library takes a seed it is given and never invents one (ADR 0002). This is not custody
//! in stele's sense — nothing is named, stored or managed; a file you name is written
//! and forgotten.

use std::fs;

use archon_core::crypto::{public_key_from_seed, SEED_SIZE};
use archon_core::hexbytes::seed_from_hex;
use archon_core::keycodec::seed_to_pkcs8_pem;
use archon_core::keytext::encode_key;

use crate::cmd::key_store;
use crate::io::wants_help;
use crate::pubrender::{parse_pub_format, render_pubkey, PubFormat};

const USAGE: &str = "usage: archon keygen [--seed <hex>] [--store <name>] [--out <file>] [--pub-out <file>] [--pub-format spki|text|hex]\n  \
prints the public key (canonical text) on stdout; writes the PKCS#8 PEM private key to \
<file> (--out) or, by default, to stderr behind a SECRET warning; --pub-out writes the \
public key (--pub-format spki|text|hex, default spki) to a file. --seed derives the key \
deterministically. --store <name> keeps the new seed in the password-protected \
store (ADR 0007 §A) instead of writing a PEM; it is mutually exclusive with \
--out.";

/// Entry point for `archon keygen`.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    let (args, store_name) = take_store_flag(args)?;
    let (args, pw_fd) = key_store::take_password_fd(&args)?;
    // Validated before anything is generated or printed: a bad name should cost nothing.
    if let Some(name) = store_name.as_deref() {
        crate::keystore::validate_name(name)?;
    }
    let opts = Opts::parse(&args)?;
    if store_name.is_some() && opts.out.is_some() {
        return Err(
            "--store and --out are mutually exclusive: one keeps the seed, the other writes it out"
                .to_string(),
        );
    }
    let pubkey = public_key_from_seed(&opts.seed);

    println!("{}", encode_key(&pubkey));

    // --store: the seed stays in the store and no PEM is produced at all. Same seal path
    // `key add` uses (seal_and_write), reached from the command that owns the CSPRNG.
    if let Some(name) = store_name.as_deref() {
        key_store::store_generated(name, &opts.seed, pw_fd)?;
        if let Some(path) = opts.pub_out.as_deref() {
            let rendered = render_pubkey(&pubkey, &opts.pub_format)?;
            fs::write(path, &rendered)
                .map_err(|e| format!("could not write public key to {path:?}: {e}"))?;
            eprintln!("wrote public key ({}) to {path}", opts.pub_format.name());
        }
        return Ok(());
    }

    let pem = seed_to_pkcs8_pem(&opts.seed)?;
    match opts.out.as_deref() {
        Some(path) => {
            fs::write(path, &pem).map_err(|e| format!("could not write key to {path:?}: {e}"))?;
            eprintln!("wrote PKCS#8 private key PEM to {path}");
        }
        None => {
            eprintln!("SECRET — do not share. Anyone with this private key controls the identity:");
            eprint!("{pem}");
        }
    }

    if let Some(path) = opts.pub_out.as_deref() {
        let rendered = render_pubkey(&pubkey, &opts.pub_format)?;
        fs::write(path, &rendered)
            .map_err(|e| format!("could not write public key to {path:?}: {e}"))?;
        eprintln!("wrote public key ({}) to {path}", opts.pub_format.name());
    }
    Ok(())
}

struct Opts {
    seed: [u8; SEED_SIZE],
    out: Option<String>,
    pub_out: Option<String>,
    pub_format: PubFormat,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Opts, String> {
        let mut seed: Option<[u8; SEED_SIZE]> = None;
        let mut out: Option<String> = None;
        let mut pub_out: Option<String> = None;
        let mut pub_format = PubFormat::Spki;
        let mut i = 0;
        while i < args.len() {
            let flag = &args[i];
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("flag {flag:?} needs a value\n{USAGE}"))?;
            match flag.as_str() {
                "--seed" => seed = Some(seed_from_hex(value).map_err(|e| format!("--seed: {e}"))?),
                "--out" => out = Some(value.clone()),
                "--pub-out" => pub_out = Some(value.clone()),
                // Validated at parse time so a bad format never leaves a private key behind.
                "--pub-format" => pub_format = parse_pub_format(value)?,
                other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
            }
            i += 2;
        }
        let seed = match seed {
            Some(s) => s,
            None => random_seed()?,
        };
        Ok(Opts {
            seed,
            out,
            pub_out,
            pub_format,
        })
    }
}

/// Draw a fresh 32-byte seed from the operating system's CSPRNG.
fn random_seed() -> Result<[u8; SEED_SIZE], String> {
    let mut seed = [0u8; SEED_SIZE];
    getrandom::fill(&mut seed).map_err(|e| format!("could not read OS randomness: {e}"))?;
    Ok(seed)
}

/// Scans for `--store <name>` and removes it, the same shape as `take_in_flag`.
fn take_store_flag(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut name = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--store" {
            let v = args
                .get(i + 1)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "flag \"--store\" needs a value".to_string())?;
            name = Some(v.clone());
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    Ok((rest, name))
}
