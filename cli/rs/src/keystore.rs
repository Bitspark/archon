//! The archon key store's file format — `docs/keystore.md`, ADR 0007 §A.
//!
//! Identical across `cli/{rs,go,ts}` and pinned by `vectors/keystore.json`. Version 2 (§8),
//! the only one written:
//!
//! ```text
//! "arck" ‖ 0x02 ‖ u32be(m KiB) ‖ u32be(t) ‖ u8(p) ‖ salt[16] ‖ pubkey[32]
//!   ‖ u8(mode) ‖ u8(n) ‖ n × (u8(len) ‖ context)                               header, H
//! nonce[24]
//! XChaCha20Poly1305(seed[32], aad = header)                                     48 with the tag
//! ```
//!
//! Version 1 (§2) is the same without the policy, a fixed 134 bytes; it is still read.
//!
//! This module is the format and nothing else: no paths, no prompts, no policy. Custody is
//! the command's (ADR 0007 §A) and nothing in `core/` or `sdk/` learns a password — but
//! that cuts both ways, so the format does not learn a directory either.

use archon_core::crypto::{public_key_from_seed, PUBLIC_KEY_SIZE, SEED_SIZE};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Follows the envelope's `"arcn" ‖ version` (`sdk/{go,rs,ts}`). It is what stops a
/// 134-byte non-key file being LISTED as a key: `key list` reads the header without a
/// password, so it is the one place a wrong file would be believed.
pub const MAGIC: &[u8; 4] = b"arck";
/// The fixed 134-byte file of `docs/keystore.md` §2. It is still PARSED, so that `key list`,
/// `key rm` and `key policy` can name and convert it, and nothing signs with it.
pub const VERSION_1: u8 = 0x01;
/// Adds the context policy of §8; the only version written.
pub const VERSION_2: u8 = 0x02;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 24;
/// The fields every version shares, up to and including the public key.
const COMMON_SIZE: usize = 4 + 1 + 4 + 4 + 1 + SALT_SIZE + PUBLIC_KEY_SIZE;
const SEAL_SIZE: usize = SEED_SIZE + 16;
/// Version 1 is exactly this long.
pub const V1_FILE_SIZE: usize = COMMON_SIZE + NONCE_SIZE + SEAL_SIZE;

/// Version 2's policy: a mode, a count, then length-prefixed contexts (§8.1).
pub const POLICY_UNRESTRICTED: u8 = 0x00;
pub const POLICY_ALLOWLIST: u8 = 0x01;
pub const MAX_CONTEXTS: usize = 16;
pub const MAX_CONTEXT_SIZE: usize = 255;
pub const MIN_V2_FILE_SIZE: usize = COMMON_SIZE + 2 + NONCE_SIZE + SEAL_SIZE;
pub const MAX_V2_FILE_SIZE: usize =
    COMMON_SIZE + 2 + MAX_CONTEXTS * (1 + MAX_CONTEXT_SIZE) + NONCE_SIZE + SEAL_SIZE;

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

/// The ceilings a header's parameters must stay under (docs/keystore.md §2). They exist only so
/// that a header someone else wrote cannot make an unlock unbounded, and they are generous on
/// purpose: RFC 9106's first recommended setting (2 GiB, t=1, p=4) still opens.
pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
pub const MAX_TIME: u32 = 10;

impl KeyParams {
    /// Refuses parameters no lane may derive with. The lower bounds are RFC 9106's validity
    /// rules and nothing more (t ≥ 1, p ≥ 1, m ≥ 8p), so a weak but valid file keeps opening:
    /// its weakness is its writer's. Stated here, once, before any derivation, so all three
    /// lanes refuse the same headers at the same step whatever their Argon2 library does.
    fn check(&self) -> Result<(), String> {
        let floor = 8 * u32::from(self.parallelism);
        if self.time == 0 || self.parallelism == 0 {
            Err("argon2id parameters are not usable: t and p must be at least 1".to_string())
        } else if self.memory_kib < floor {
            Err(format!(
                "argon2id parameters are not usable: m={} KiB is below 8*p={floor}",
                self.memory_kib
            ))
        } else if self.memory_kib > MAX_MEMORY_KIB {
            Err(format!(
                "argon2id parameters are not usable: m={} KiB is above {MAX_MEMORY_KIB}",
                self.memory_kib
            ))
        } else if self.time > MAX_TIME {
            Err(format!(
                "argon2id parameters are not usable: t={} is above {MAX_TIME}",
                self.time
            ))
        } else {
            Ok(())
        }
    }
}

/// The authenticated prefix of a key file. `public_key` is readable without a password —
/// that is what `key list` prints — but it is only a CLAIM until an unlock verifies the tag
/// over this header and re-derives it from the seed.
#[derive(Clone, Debug)]
pub struct KeyHeader {
    pub version: u8,
    pub params: KeyParams,
    pub salt: [u8; SALT_SIZE],
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    /// `None` for a version-1 file, which has none.
    pub policy: Option<Policy>,
    /// The header's length: the AEAD's associated data is `file[..size]`.
    pub size: usize,
}

/// A refusal of the file itself, before any derivation. `kind` is the machine-mode category
/// the command reports (`docs/keystore.md` §8.2): `unsupported` for a version byte this binary
/// does not know, `malformed` for everything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatError {
    pub kind: &'static str,
    pub message: String,
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<FormatError> for String {
    fn from(e: FormatError) -> String {
        e.message
    }
}

fn malformed(message: impl Into<String>) -> FormatError {
    FormatError {
        kind: "malformed",
        message: message.into(),
    }
}

/// A version-2 entry's context policy (§8.1): unrestricted, or an allowlist of contexts in
/// strictly ascending byte order. An empty allowlist denies every context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub unrestricted: bool,
    pub contexts: Vec<String>,
}

impl Policy {
    pub fn unrestricted() -> Self {
        Policy {
            unrestricted: true,
            contexts: Vec::new(),
        }
    }

    /// Builds an allowlist from the contexts a person named: each a domain by ADR 0008 §2
    /// (1..255 bytes of well-formed UTF-8), no duplicates, at most [`MAX_CONTEXTS`]. It sorts
    /// them, so one policy has one encoding.
    pub fn allowlist(contexts: &[String]) -> Result<Self, String> {
        if contexts.len() > MAX_CONTEXTS {
            return Err(format!(
                "at most {MAX_CONTEXTS} contexts (got {})",
                contexts.len()
            ));
        }
        let mut sorted = contexts.to_vec();
        sorted.sort();
        for (i, c) in sorted.iter().enumerate() {
            check_context(c.as_bytes())?;
            if i > 0 && sorted[i - 1] == *c {
                return Err(format!("context {c:?} is named twice"));
            }
        }
        Ok(Policy {
            unrestricted: false,
            contexts: sorted,
        })
    }

    /// Byte-exact membership: no prefix, no wildcard, no normalisation.
    pub fn permits(&self, domain: &str) -> bool {
        self.unrestricted || self.contexts.iter().any(|c| c == domain)
    }

    fn encode(&self) -> Vec<u8> {
        if self.unrestricted {
            return vec![POLICY_UNRESTRICTED, 0];
        }
        let mut out = vec![POLICY_ALLOWLIST, self.contexts.len() as u8];
        for c in &self.contexts {
            out.push(c.len() as u8);
            out.extend_from_slice(c.as_bytes());
        }
        out
    }
}

/// The policy as the command prints it.
impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.unrestricted {
            f.write_str("unrestricted")
        } else if self.contexts.is_empty() {
            f.write_str("allow nothing")
        } else {
            let quoted: Vec<String> = self.contexts.iter().map(|c| quote(c)).collect();
            write!(f, "allow {}", quoted.join(", "))
        }
    }
}

/// Spells a context by the JSON string rule, so a context holding ", " cannot read as two. The
/// same rule in the three lanes: `"` and `\` escaped, C0 controls as \u00xx.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn check_context(c: &[u8]) -> Result<(), String> {
    if c.is_empty() || c.len() > MAX_CONTEXT_SIZE {
        return Err(format!(
            "a context is 1 to {MAX_CONTEXT_SIZE} bytes (got {})",
            c.len()
        ));
    }
    let Ok(text) = std::str::from_utf8(c) else {
        return Err("a context is well-formed UTF-8".to_string());
    };
    // A policy is shown to the person (`key policy`, `key list`, the refusals), so a context
    // holds nothing a terminal would not show as itself (docs/login.md §5's set). Refused on
    // write and on read, so nothing is written that cannot be read, and nothing read that cannot
    // be shown.
    if let Some(ch) = text.chars().find(|&ch| archon_sdk::login::display_unsafe(ch)) {
        return Err(format!(
            "a context may not contain U+{:04X}: it would not be shown as itself",
            ch as u32
        ));
    }
    Ok(())
}

/// Both ends refuse an empty password: a store sealed under one is a plaintext store that
/// looks encrypted, and refusing at OPEN too keeps a file made by a lenient writer from
/// ever being trusted.
pub const EMPTY_PASSWORD: &str = "an empty password is refused: it would look encrypted and not be";

/// Derives the file key. The password is UTF-8, normalised NFC so the same characters typed
/// on different platforms derive the same key.
///
/// The normalised password and the key are `Zeroizing`, as are the seeds below
/// (docs/keystore.md §4, #53): wiped on drop, best-effort. A copy the compiler makes when a
/// value moves, or the one the cipher keeps of its key, is not reached — which is why §4
/// calls this worth doing and not a security claim.
fn derive_key(password: &[u8], salt: &[u8], p: KeyParams) -> Result<Zeroizing<[u8; 32]>, String> {
    let normalised = Zeroizing::new(match std::str::from_utf8(password) {
        Ok(text) => text.nfc().collect::<String>().into_bytes(),
        // Not valid UTF-8: there is nothing to normalise, so the bytes are used as given
        // rather than mangled. The other lanes reach the same bytes the same way.
        Err(_) => password.to_vec(),
    });
    let params = Params::new(p.memory_kib, p.time, p.parallelism as u32, Some(32))
        .map_err(|e| format!("argon2id parameters are not usable: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&normalised, salt, &mut out[..])
        .map_err(|e| format!("argon2id: {e}"))?;
    Ok(out)
}

/// A version-2 header: the only version written (§8).
fn encode_header(p: KeyParams, salt: &[u8], public_key: &[u8], policy: &Policy) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMON_SIZE + 2);
    out.extend_from_slice(MAGIC);
    out.push(VERSION_2);
    out.extend_from_slice(&p.memory_kib.to_be_bytes());
    out.extend_from_slice(&p.time.to_be_bytes());
    out.push(p.parallelism);
    out.extend_from_slice(salt);
    out.extend_from_slice(public_key);
    out.extend_from_slice(&policy.encode());
    out
}

/// Reads the header of a key file WITHOUT a password, version 1 or 2. Every refusal here is
/// cheap, happens before any crypto runs, and is a [`FormatError`].
pub fn parse_header(file: &[u8]) -> Result<KeyHeader, FormatError> {
    if file.len() < 5 || &file[..4] != MAGIC {
        return Err(malformed("bad magic: not an archon key file"));
    }
    let (policy, size) = match file[4] {
        VERSION_1 => {
            if file.len() != V1_FILE_SIZE {
                return Err(malformed(format!(
                    "not {V1_FILE_SIZE} bytes (got {})",
                    file.len()
                )));
            }
            (None, COMMON_SIZE)
        }
        VERSION_2 => {
            if file.len() < MIN_V2_FILE_SIZE || file.len() > MAX_V2_FILE_SIZE {
                return Err(malformed(format!(
                    "a version-2 key file is {MIN_V2_FILE_SIZE} to {MAX_V2_FILE_SIZE} bytes (got {})",
                    file.len()
                )));
            }
            let (policy, size) = parse_policy(file)?;
            (Some(policy), size)
        }
        v => {
            return Err(FormatError {
                kind: "unsupported",
                message: format!("unknown key file version {v}"),
            })
        }
    };
    let params = KeyParams {
        memory_kib: u32::from_be_bytes([file[5], file[6], file[7], file[8]]),
        time: u32::from_be_bytes([file[9], file[10], file[11], file[12]]),
        parallelism: file[13],
    };
    params.check().map_err(malformed)?;
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&file[14..30]);
    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    public_key.copy_from_slice(&file[30..COMMON_SIZE]);
    Ok(KeyHeader {
        version: file[4],
        params,
        salt,
        public_key,
        policy,
        size,
    })
}

/// Reads §8.1's policy and returns it with the header's length. The file must be exactly that
/// header, the nonce and the seal: nothing missing, nothing trailing.
fn parse_policy(file: &[u8]) -> Result<(Policy, usize), FormatError> {
    let (mode, n) = (file[COMMON_SIZE], file[COMMON_SIZE + 1] as usize);
    let unrestricted = match mode {
        POLICY_UNRESTRICTED if n == 0 => true,
        POLICY_UNRESTRICTED => {
            return Err(malformed(format!(
                "an unrestricted policy lists no contexts (got {n})"
            )))
        }
        POLICY_ALLOWLIST if n > MAX_CONTEXTS => {
            return Err(malformed(format!(
                "at most {MAX_CONTEXTS} contexts (got {n})"
            )))
        }
        POLICY_ALLOWLIST => false,
        m => return Err(malformed(format!("unknown policy mode {m}"))),
    };
    let end = file.len() - NONCE_SIZE - SEAL_SIZE;
    let mut off = COMMON_SIZE + 2;
    let mut contexts: Vec<String> = Vec::with_capacity(n);
    for _ in 0..n {
        if off >= end || off + 1 + file[off] as usize > end {
            return Err(malformed("the policy runs past the header"));
        }
        let size = file[off] as usize;
        let raw = &file[off + 1..off + 1 + size];
        check_context(raw).map_err(|e| malformed(format!("policy: {e}")))?;
        let c = String::from_utf8(raw.to_vec()).map_err(|_| malformed("policy: not UTF-8"))?;
        if let Some(prev) = contexts.last() {
            if prev.as_bytes() >= c.as_bytes() {
                return Err(malformed(
                    "policy contexts are not in strictly ascending order",
                ));
            }
        }
        contexts.push(c);
        off += 1 + size;
    }
    if off != end {
        return Err(malformed(
            "the file is not exactly the header it declares, a nonce and a seal",
        ));
    }
    Ok((
        Policy {
            unrestricted,
            contexts,
        },
        off,
    ))
}

/// Produces a version-2 file. `salt` and `nonce` are ARGUMENTS: the randomness is the
/// command's, never this function's, which is what makes the format pinnable.
pub fn seal(
    seed: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    p: KeyParams,
    policy: &Policy,
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
    p.check()?;
    // The writer's half of §8.1: the same rules the reader enforces, so nothing is written that
    // would not be read back.
    if policy.unrestricted {
        if !policy.contexts.is_empty() {
            return Err("an unrestricted policy lists no contexts".to_string());
        }
    } else {
        Policy::allowlist(&policy.contexts)?;
        if policy.contexts.windows(2).any(|w| w[0] > w[1]) {
            return Err(
                "policy contexts must be sorted: build them with Policy::allowlist".to_string(),
            );
        }
    }
    let mut seed_fixed = Zeroizing::new([0u8; SEED_SIZE]);
    seed_fixed.copy_from_slice(seed);
    let header = encode_header(p, salt, &public_key_from_seed(&seed_fixed), policy);
    let key = derive_key(password, salt, p)?;
    let aead = XChaCha20Poly1305::new(&Key::from(*key));
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
    let mut out = Vec::with_capacity(header.len() + NONCE_SIZE + SEAL_SIZE);
    out.extend_from_slice(&header);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// `key policy`'s step 4 (§8.3): opens `file` — version 1 or 2 — and seals the same seed under
/// the same salt and parameters, the new policy and a fresh nonce. Always version 2.
pub fn reseal(
    file: &[u8],
    password: &[u8],
    nonce: &[u8],
    policy: &Policy,
) -> Result<Vec<u8>, String> {
    let header = parse_header(file)?;
    let seed = open(file, password)?;
    seal(
        &seed[..],
        password,
        &header.salt,
        nonce,
        header.params,
        policy,
    )
}

/// Reverses [`seal`], for version 1 or 2, and then checks the decrypted seed against the
/// header's public key. The tag proves the bytes are ours, policy included; that check proves
/// they are CONSISTENT — a file can verify and still be refused. Whether a version-1 seed may
/// be USED is the command's decision (§8.2), not this function's.
pub fn open(file: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; SEED_SIZE]>, String> {
    let header = parse_header(file)?;
    if password.is_empty() {
        return Err(EMPTY_PASSWORD.to_string());
    }
    let key = derive_key(password, &header.salt, header.params)?;
    let aead = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = &file[header.size..header.size + NONCE_SIZE];
    let xnonce =
        XNonce::try_from(nonce).map_err(|_| format!("nonce must be {NONCE_SIZE} bytes"))?;
    let seed = Zeroizing::new(
        aead.decrypt(
            &xnonce,
            Payload {
                msg: &file[header.size + NONCE_SIZE..],
                aad: &file[..header.size],
            },
        )
        // One message for a wrong password and a tampered file alike: which of the two it
        // was is not something the holder of a bad password should learn.
        .map_err(|_| "could not open: wrong password, or the file has been altered".to_string())?,
    );
    if seed.len() != SEED_SIZE {
        return Err("the sealed plaintext is not a seed".to_string());
    }
    let mut out = Zeroizing::new([0u8; SEED_SIZE]);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #53: the unlocked seed and the derived key leave this module wiped-on-drop. Written
    /// as types, so a change back to a bare array fails to compile here instead of passing
    /// quietly. The command's side — the password, the store unlock, the login seed — is
    /// pinned the same way in `cmd::login`'s tests; this file is also built into the
    /// conformance binary, which has no `cmd`.
    #[test]
    fn secrets_leave_as_zeroizing() {
        type Secret<const N: usize> = Result<Zeroizing<[u8; N]>, String>;
        let _: fn(&[u8], &[u8]) -> Secret<SEED_SIZE> = open;
        let _: fn(&[u8], &[u8], KeyParams) -> Secret<32> = derive_key;
    }
}
