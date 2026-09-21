//! The archon key store's file format — `docs/keystore.md`, ADR 0007 §A.
//!
//! A fixed 134-byte layout, identical across `cli/{rs,go,ts}` and pinned by
//! `vectors/keystore.json`:
//!
//! ```text
//! "arck" ‖ version ‖ u32be(m KiB) ‖ u32be(t) ‖ u8(p) ‖ salt[16] ‖ pubkey[32]   header, 62
//! nonce[24]
//! XChaCha20Poly1305(seed[32], aad = header)                                     48 with the tag
//! ```
//!
//! This module is the format and nothing else: no paths, no prompts, no policy. Custody is
//! the command's (ADR 0007 §A) and nothing in `core/` or `sdk/` learns a password — but
//! that cuts both ways, so the format does not learn a directory either.

use archon_core::crypto::{public_key_from_seed, PUBLIC_KEY_SIZE, SEED_SIZE};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use unicode_normalization::UnicodeNormalization;

/// Follows the envelope's `"arcn" ‖ version` (`sdk/{go,rs,ts}`). It is what stops a
/// 134-byte non-key file being LISTED as a key: `key list` reads the header without a
/// password, so it is the one place a wrong file would be believed.
pub const MAGIC: &[u8; 4] = b"arck";
pub const VERSION: u8 = 0x01;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 24;
pub const HEADER_SIZE: usize = 4 + 1 + 4 + 4 + 1 + SALT_SIZE + PUBLIC_KEY_SIZE;
pub const FILE_SIZE: usize = HEADER_SIZE + NONCE_SIZE + SEED_SIZE + 16;

/// The shipping default, measured rather than assumed (`docs/keystore.md` §3): `p=4` buys
/// nothing in any lane we ship and costs two of three external oracles.
pub const DEFAULT_MEMORY_KIB: u32 = 65536;
pub const DEFAULT_TIME: u32 = 3;
pub const DEFAULT_PARALLELISM: u8 = 1;

/// Argon2id cost parameters. They live in the header and are READ, never assumed, which is
/// what lets the defaults change without a format version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyParams {
    pub memory_kib: u32,
    pub time: u32,
    pub parallelism: u8,
}

impl Default for KeyParams {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            time: DEFAULT_TIME,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

/// The authenticated prefix of a key file. `public_key` is readable without a password —
/// that is what `key list` prints — but it is only a CLAIM until an unlock verifies the tag
/// over this header and re-derives it from the seed.
#[derive(Clone, Debug)]
pub struct KeyHeader {
    pub params: KeyParams,
    pub salt: [u8; SALT_SIZE],
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

/// Both ends refuse an empty password: a store sealed under one is a plaintext store that
/// looks encrypted, and refusing at OPEN too keeps a file made by a lenient writer from
/// ever being trusted.
pub const EMPTY_PASSWORD: &str = "an empty password is refused: it would look encrypted and not be";

/// Derives the file key. The password is UTF-8, normalised NFC so the same characters typed
/// on different platforms derive the same key.
fn derive_key(password: &[u8], salt: &[u8], p: KeyParams) -> Result<[u8; 32], String> {
    let normalised: Vec<u8> = match std::str::from_utf8(password) {
        Ok(text) => text.nfc().collect::<String>().into_bytes(),
        // Not valid UTF-8: there is nothing to normalise, so the bytes are used as given
        // rather than mangled. The other lanes reach the same bytes the same way.
        Err(_) => password.to_vec(),
    };
    let params = Params::new(p.memory_kib, p.time, p.parallelism as u32, Some(32))
        .map_err(|e| format!("argon2id parameters are not usable: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&normalised, salt, &mut out)
        .map_err(|e| format!("argon2id: {e}"))?;
    Ok(out)
}

pub fn encode_header(h: &KeyHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&h.params.memory_kib.to_be_bytes());
    out.extend_from_slice(&h.params.time.to_be_bytes());
    out.push(h.params.parallelism);
    out.extend_from_slice(&h.salt);
    out.extend_from_slice(&h.public_key);
    out
}

/// Reads the header of a key file WITHOUT a password. Every refusal here is cheap and
/// happens before any crypto runs.
pub fn parse_header(file: &[u8]) -> Result<KeyHeader, String> {
    if file.len() != FILE_SIZE {
        return Err(format!("not {FILE_SIZE} bytes (got {})", file.len()));
    }
    if &file[..4] != MAGIC {
        return Err("bad magic: not an archon key file".to_string());
    }
    if file[4] != VERSION {
        return Err(format!("unknown key file version {}", file[4]));
    }
    let params = KeyParams {
        memory_kib: u32::from_be_bytes([file[5], file[6], file[7], file[8]]),
        time: u32::from_be_bytes([file[9], file[10], file[11], file[12]]),
        parallelism: file[13],
    };
    if params.memory_kib == 0 || params.time == 0 || params.parallelism == 0 {
        return Err("argon2id parameters in the header are not usable".to_string());
    }
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&file[14..30]);
    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    public_key.copy_from_slice(&file[30..HEADER_SIZE]);
    Ok(KeyHeader {
        params,
        salt,
        public_key,
    })
}

/// Produces the 134 bytes. `salt` and `nonce` are ARGUMENTS: the randomness is the
/// command's, never this function's, which is what makes the format pinnable.
pub fn seal(
    seed: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    p: KeyParams,
) -> Result<Vec<u8>, String> {
    if seed.len() != SEED_SIZE {
        return Err(format!("seed must be {SEED_SIZE} bytes"));
    }
    if password.is_empty() {
        return Err(EMPTY_PASSWORD.to_string());
    }
    if salt.len() != SALT_SIZE {
        return Err(format!("salt must be {SALT_SIZE} bytes"));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(format!("nonce must be {NONCE_SIZE} bytes"));
    }
    let mut seed_fixed = [0u8; SEED_SIZE];
    seed_fixed.copy_from_slice(seed);
    let mut salt_fixed = [0u8; SALT_SIZE];
    salt_fixed.copy_from_slice(salt);
    let header = encode_header(&KeyHeader {
        params: p,
        salt: salt_fixed,
        public_key: public_key_from_seed(&seed_fixed),
    });
    let key = derive_key(password, salt, p)?;
    let aead = XChaCha20Poly1305::new(&Key::from(key));
    let xnonce =
        XNonce::try_from(nonce).map_err(|_| format!("nonce must be {NONCE_SIZE} bytes"))?;
    let ciphertext = aead
        .encrypt(
            &xnonce,
            Payload {
                msg: seed,
                aad: &header,
            },
        )
        .map_err(|_| "could not seal the key".to_string())?;
    let mut out = Vec::with_capacity(FILE_SIZE);
    out.extend_from_slice(&header);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reverses [`seal`] and then checks the decrypted seed against the header's public key.
/// The tag proves the bytes are ours; that check proves they are CONSISTENT — a file can
/// verify and still be refused.
pub fn open(file: &[u8], password: &[u8]) -> Result<[u8; SEED_SIZE], String> {
    let header = parse_header(file)?;
    if password.is_empty() {
        return Err(EMPTY_PASSWORD.to_string());
    }
    let key = derive_key(password, &header.salt, header.params)?;
    let aead = XChaCha20Poly1305::new(&Key::from(key));
    let nonce = &file[HEADER_SIZE..HEADER_SIZE + NONCE_SIZE];
    let xnonce =
        XNonce::try_from(nonce).map_err(|_| format!("nonce must be {NONCE_SIZE} bytes"))?;
    let seed = aead
        .decrypt(
            &xnonce,
            Payload {
                msg: &file[HEADER_SIZE + NONCE_SIZE..],
                aad: &file[..HEADER_SIZE],
            },
        )
        // One message for a wrong password and a tampered file alike: which of the two it
        // was is not something the holder of a bad password should learn.
        .map_err(|_| "could not open: wrong password, or the file has been altered".to_string())?;
    if seed.len() != SEED_SIZE {
        return Err("the sealed plaintext is not a seed".to_string());
    }
    let mut out = [0u8; SEED_SIZE];
    out.copy_from_slice(&seed);
    if public_key_from_seed(&out) != header.public_key {
        return Err("the sealed seed does not derive the public key in the header".to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Names — docs/keystore.md §5.
// ---------------------------------------------------------------------------

pub const NAME_MAX_BYTES: usize = 64;

/// Refused bare AND with any extension: Windows treats `CON.key` as the device `CON`, so
/// `archon key add CON.key` would name a file nobody can open.
const RESERVED_DEVICE_NAMES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Restricts rather than escapes: a name is a path segment on three operating systems, and
/// quoting it correctly on all of them is a harder problem than refusing the characters
/// that make it interesting.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a key name may not be empty".to_string());
    }
    if name.len() > NAME_MAX_BYTES {
        return Err(format!(
            "a key name may be at most {NAME_MAX_BYTES} bytes (got {})",
            name.len()
        ));
    }
    if name.starts_with('.') {
        return Err("a key name may not begin with \".\": it would hide the key".to_string());
    }
    if name.ends_with('.') {
        // Windows strips a trailing dot, so `alice.` and `alice` would be one file on one
        // OS and two on another.
        return Err("a key name may not end with \".\"".to_string());
    }
    for b in name.bytes() {
        let ok = b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-';
        if !ok {
            if b < 0x20 || b == 0x7f {
                return Err("a key name may not contain control characters".to_string());
            }
            return Err(
                "a key name may contain only letters, digits, \".\", \"_\" and \"-\"".to_string(),
            );
        }
    }
    let stem = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    if RESERVED_DEVICE_NAMES.contains(&stem.as_str()) {
        return Err(format!(
            "{name:?} is a reserved device name on Windows, with or without an extension"
        ));
    }
    Ok(())
}
