//! The `archon` subcommands, one module (one file) each. Every module exposes a single
//! `pub fn run(args: &[String]) -> Result<(), String>` registered in `main`'s dispatch.

pub mod key;
pub mod key_store;
pub mod keygen;
pub mod login;
pub mod sign;
pub mod verify;
pub mod version;

use archon_core::crypto::SEED_SIZE;
use archon_core::hexbytes::seed_from_hex;
use archon_core::keycodec::pkcs8_pem_to_seed;

use crate::io::read_text;

/// Resolve a private key from the two ways every signing command accepts one: `--seed
/// <hex>` (a raw 32-byte seed) or a PKCS#8 PEM from `--key-file <file>` / stdin. The two
/// are mutually exclusive.
pub fn resolve_seed(
    seed_hex: Option<&str>,
    key_file: Option<&str>,
    usage: &str,
) -> Result<[u8; SEED_SIZE], String> {
    match (seed_hex, key_file) {
        (Some(_), Some(_)) => Err(format!(
            "--seed and --key-file are mutually exclusive\n{usage}"
        )),
        (Some(hex), None) => seed_from_hex(hex).map_err(|e| format!("--seed: {e}")),
        (None, key_file) => pkcs8_pem_to_seed(&read_text(key_file)?),
    }
}
