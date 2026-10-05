//! `archon enroll`'s formats (`docs/enroll.md` §2–§3, ADR 0013): the intent in format 1, which a
//! service builds and the command renders, and the two tokens a person carries by hand between
//! the signed-in page and the command. The proof never reads an intent; these are for the
//! command, which must show the person which account a key joins before it signs.
//!
//! Pinned by `vectors/enroll.json`.

use archon_core::crypto::PUBLIC_KEY_SIZE;
use sha2::{Digest, Sha256};

use super::{put_field, Request, MAX_TRANSACTION_SIZE};
use crate::login::display_unsafe;
use crate::possession;

/// The first byte of an intent in format 1.
pub const INTENT_FORMAT: u8 = 0x01;
/// The shortest blind: 128 bits, so the digest cannot confirm a guess.
pub const MIN_BLIND_SIZE: usize = 16;
/// The longest blind.
pub const MAX_BLIND_SIZE: usize = 64;
/// The longest account id, account name, purpose or restriction, in bytes.
pub const MAX_TEXT_SIZE: usize = 255;
/// The most restrictions an intent holds.
pub const MAX_RESTRICTIONS: usize = 32;

/// The challenge token's prefix.
pub const CHALLENGE_PREFIX: &str = "archon-enroll-challenge-1:";
/// The proof token's prefix.
pub const PROOF_PREFIX: &str = "archon-enroll-proof-1:";
/// The longest token, in bytes of text, surrounding whitespace excluded.
pub const MAX_TOKEN_SIZE: usize = 65536;
/// The longest nonce a challenge token carries.
pub const MAX_NONCE_SIZE: usize = 255;
/// The longest intent a challenge token carries.
pub const MAX_INTENT_SIZE: usize = 0xffff;
/// The possession signature's length.
pub const PROOF_SIZE: usize = 64;
/// 9999-12-31T23:59:59Z in Unix seconds: every lane renders it, and none needs more than 53 bits.
pub const MAX_DEADLINE: u64 = 253_402_300_799;

/// An enrollment intent in format 1. The service builds it from its own validated records; the
/// command decodes it and shows it. Every text field is `1..=MAX_TEXT_SIZE` bytes with no
/// display-unsafe code point ([`display_unsafe`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// `MIN_BLIND_SIZE..=MAX_BLIND_SIZE` bytes from a CSPRNG, fresh for every intent.
    pub blind: Vec<u8>,
    /// The service's identifier for the account.
    pub account_id: String,
    /// The account's unique name, such as its sign-in handle: never a free display name.
    pub account_name: String,
    /// The binding's purpose.
    pub purpose: String,
    /// `0..=MAX_RESTRICTIONS` lines, in order.
    pub restrictions: Vec<String>,
}

/// Writes `intent` in format 1, refusing any field outside its bounds.
pub fn encode_intent(intent: &Intent) -> Result<Vec<u8>, String> {
    check_blind(&intent.blind)?;
    check_shown("account id", &intent.account_id)?;
    check_shown("account name", &intent.account_name)?;
    check_shown("purpose", &intent.purpose)?;
    if intent.restrictions.len() > MAX_RESTRICTIONS {
        return Err(format!(
            "enroll: {} restrictions, want at most {MAX_RESTRICTIONS}",
            intent.restrictions.len()
        ));
    }
    for (n, r) in intent.restrictions.iter().enumerate() {
        check_shown(&format!("restriction {n}"), r)?;
    }
    let mut out = vec![INTENT_FORMAT];
    put_field(&mut out, &intent.blind);
    put_field(&mut out, intent.account_id.as_bytes());
    put_field(&mut out, intent.account_name.as_bytes());
    put_field(&mut out, intent.purpose.as_bytes());
    out.push(intent.restrictions.len() as u8);
    for r in &intent.restrictions {
        put_field(&mut out, r.as_bytes());
    }
    Ok(out)
}

/// Reads an intent in format 1. Refuses an unknown format, any field outside its bounds,
/// display-unsafe or non-UTF-8 text, and any byte left over.
pub fn decode_intent(bytes: &[u8]) -> Result<Intent, String> {
    let mut r = Reader::new(bytes);
    let format = r.take(1)?[0];
    if format != INTENT_FORMAT {
        return Err(format!(
            "enroll: intent format 0x{format:02x}, want 0x{INTENT_FORMAT:02x}"
        ));
    }
    let blind = r.field()?.to_vec();
    check_blind(&blind)?;
    let account_id = shown_text(&mut r, "account id")?;
    let account_name = shown_text(&mut r, "account name")?;
    let purpose = shown_text(&mut r, "purpose")?;
    let count = r.take(1)?[0] as usize;
    if count > MAX_RESTRICTIONS {
        return Err(format!(
            "enroll: {count} restrictions, want at most {MAX_RESTRICTIONS}"
        ));
    }
    let mut restrictions = Vec::with_capacity(count);
    for n in 0..count {
        restrictions.push(shown_text(&mut r, &format!("restriction {n}"))?);
    }
    r.end()?;
    Ok(Intent {
        blind,
        account_id,
        account_name,
        purpose,
        restrictions,
    })
}

/// The challenge token's content: what the service hands the person, for the command. `intent`
/// is the exact intent bytes; the token's codec checks only its own fields, and
/// [`Challenge::request`] decodes the intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub audience: String,
    /// `1..=MAX_TRANSACTION_SIZE` bytes.
    pub transaction: Vec<u8>,
    /// `possession::MIN_NONCE_SIZE..=MAX_NONCE_SIZE` bytes.
    pub nonce: Vec<u8>,
    /// The key the record enrolls.
    pub new_key: Vec<u8>,
    /// `1..=MAX_INTENT_SIZE` bytes.
    pub intent: Vec<u8>,
    /// The record's expiry in Unix seconds, at most [`MAX_DEADLINE`].
    pub deadline: u64,
}

impl Challenge {
    /// The enrollment request this token yields (`docs/enroll.md` §3): the token's nonce,
    /// transaction and new key, the intent's purpose, and SHA-256 of the token's intent bytes,
    /// with the decoded intent. Refuses an intent that is not format 1. It is the one derivation
    /// of what an `archon enroll` proof binds, so what the command shows is what it binds.
    pub fn request(&self) -> Result<(Request, Intent), String> {
        self.check()?;
        let intent = decode_intent(&self.intent)?;
        let request = Request {
            nonce: self.nonce.clone(),
            transaction: self.transaction.clone(),
            purpose: intent.purpose.clone(),
            new_key: self.new_key.clone(),
            intent_digest: Sha256::digest(&self.intent).to_vec(),
        };
        Ok((request, intent))
    }

    fn check(&self) -> Result<(), String> {
        // Stricter than the binding's audience rule (C0 and DEL only): a command that refuses a
        // token prints its audience, so nothing display-unsafe may get that far.
        if self.audience.is_empty() || self.audience.len() > 0xffff {
            return Err(format!(
                "enroll: audience is {} bytes, want 1..=65535",
                self.audience.len()
            ));
        }
        if let Some(c) = self.audience.chars().find(|c| display_unsafe(*c)) {
            return Err(format!(
                "enroll: audience carries a code point that cannot be shown, U+{:04X}",
                c as u32
            ));
        }
        if self.transaction.is_empty() || self.transaction.len() > MAX_TRANSACTION_SIZE {
            return Err(format!(
                "enroll: transaction is {} bytes, want 1..={MAX_TRANSACTION_SIZE}",
                self.transaction.len()
            ));
        }
        if self.nonce.len() < possession::MIN_NONCE_SIZE || self.nonce.len() > MAX_NONCE_SIZE {
            return Err(format!(
                "enroll: nonce is {} bytes, want {}..={MAX_NONCE_SIZE}",
                self.nonce.len(),
                possession::MIN_NONCE_SIZE
            ));
        }
        if self.new_key.len() != PUBLIC_KEY_SIZE {
            return Err(format!(
                "enroll: new key is {} bytes, want {PUBLIC_KEY_SIZE}",
                self.new_key.len()
            ));
        }
        if self.intent.is_empty() || self.intent.len() > MAX_INTENT_SIZE {
            return Err(format!(
                "enroll: intent is {} bytes, want 1..={MAX_INTENT_SIZE}",
                self.intent.len()
            ));
        }
        if self.deadline > MAX_DEADLINE {
            return Err("enroll: deadline is after 9999-12-31T23:59:59Z".into());
        }
        Ok(())
    }
}

/// Writes `challenge` as a challenge token.
pub fn encode_challenge(challenge: &Challenge) -> Result<String, String> {
    challenge.check()?;
    let mut out = Vec::new();
    put_field(&mut out, challenge.audience.as_bytes());
    put_field(&mut out, &challenge.transaction);
    put_field(&mut out, &challenge.nonce);
    out.extend_from_slice(&challenge.new_key);
    put_field(&mut out, &challenge.intent);
    out.extend_from_slice(&challenge.deadline.to_be_bytes());
    let text = format!("{CHALLENGE_PREFIX}{}", hex(&out));
    if text.len() > MAX_TOKEN_SIZE {
        return Err(format!(
            "enroll: challenge token is {} bytes, over {MAX_TOKEN_SIZE}",
            text.len()
        ));
    }
    Ok(text)
}

/// Reads a challenge token. Surrounding tabs, line feeds, carriage returns and spaces are
/// ignored; anything else that is not exactly the prefix and lowercase hex of the fields, with
/// no byte left over, is refused.
pub fn decode_challenge(text: &str) -> Result<Challenge, String> {
    let bytes = unwrap(text, CHALLENGE_PREFIX)?;
    let mut r = Reader::new(&bytes);
    let audience = std::str::from_utf8(r.field()?)
        .map_err(|_| "enroll: audience is not valid UTF-8".to_string())?
        .to_string();
    let transaction = r.field()?.to_vec();
    let nonce = r.field()?.to_vec();
    let new_key = r.take(PUBLIC_KEY_SIZE)?.to_vec();
    let intent = r.field()?.to_vec();
    let deadline = u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes"));
    r.end()?;
    let challenge = Challenge {
        audience,
        transaction,
        nonce,
        new_key,
        intent,
        deadline,
    };
    challenge.check()?;
    Ok(challenge)
}

/// The proof token's content: what the command prints and the service reads back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// `1..=MAX_TRANSACTION_SIZE` bytes.
    pub transaction: Vec<u8>,
    /// The key that proved.
    pub new_key: Vec<u8>,
    /// The possession signature, [`PROOF_SIZE`] bytes.
    pub proof: Vec<u8>,
}

impl Proof {
    fn check(&self) -> Result<(), String> {
        if self.transaction.is_empty() || self.transaction.len() > MAX_TRANSACTION_SIZE {
            return Err(format!(
                "enroll: transaction is {} bytes, want 1..={MAX_TRANSACTION_SIZE}",
                self.transaction.len()
            ));
        }
        if self.new_key.len() != PUBLIC_KEY_SIZE {
            return Err(format!(
                "enroll: new key is {} bytes, want {PUBLIC_KEY_SIZE}",
                self.new_key.len()
            ));
        }
        if self.proof.len() != PROOF_SIZE {
            return Err(format!(
                "enroll: proof is {} bytes, want {PROOF_SIZE}",
                self.proof.len()
            ));
        }
        Ok(())
    }
}

/// Writes `proof` as a proof token.
pub fn encode_proof(proof: &Proof) -> Result<String, String> {
    proof.check()?;
    let mut out = Vec::new();
    put_field(&mut out, &proof.transaction);
    out.extend_from_slice(&proof.new_key);
    out.extend_from_slice(&proof.proof);
    Ok(format!("{PROOF_PREFIX}{}", hex(&out)))
}

/// Reads a proof token, under [`decode_challenge`]'s rules.
pub fn decode_proof(text: &str) -> Result<Proof, String> {
    let bytes = unwrap(text, PROOF_PREFIX)?;
    let mut r = Reader::new(&bytes);
    let proof = Proof {
        transaction: r.field()?.to_vec(),
        new_key: r.take(PUBLIC_KEY_SIZE)?.to_vec(),
        proof: r.take(PROOF_SIZE)?.to_vec(),
    };
    r.end()?;
    proof.check()?;
    Ok(proof)
}

fn check_blind(blind: &[u8]) -> Result<(), String> {
    if blind.len() < MIN_BLIND_SIZE || blind.len() > MAX_BLIND_SIZE {
        return Err(format!(
            "enroll: blind is {} bytes, want {MIN_BLIND_SIZE}..={MAX_BLIND_SIZE}",
            blind.len()
        ));
    }
    Ok(())
}

/// The rule for text the command shows: `1..=MAX_TEXT_SIZE` bytes with no display-unsafe code
/// point. The code point is named, never echoed.
fn check_shown(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_TEXT_SIZE {
        return Err(format!(
            "enroll: {what} is {} bytes, want 1..={MAX_TEXT_SIZE}",
            s.len()
        ));
    }
    if let Some(c) = s.chars().find(|c| display_unsafe(*c)) {
        return Err(format!(
            "enroll: {what} carries a code point that cannot be shown, U+{:04X}",
            c as u32
        ));
    }
    Ok(())
}

fn shown_text(r: &mut Reader<'_>, what: &str) -> Result<String, String> {
    let s = std::str::from_utf8(r.field()?)
        .map_err(|_| format!("enroll: {what} is not valid UTF-8"))?;
    check_shown(what, s)?;
    Ok(s.to_string())
}

/// Strips the surrounding whitespace the token rules allow and decodes the hex after `prefix`:
/// lowercase only, even length, nothing else.
fn unwrap(text: &str, prefix: &str) -> Result<Vec<u8>, String> {
    let t = text.trim_matches(|c| matches!(c, '\t' | '\n' | '\r' | ' '));
    if t.len() > MAX_TOKEN_SIZE {
        return Err(format!(
            "enroll: token is {} bytes, over {MAX_TOKEN_SIZE}",
            t.len()
        ));
    }
    let h = t
        .strip_prefix(prefix)
        .ok_or_else(|| format!("enroll: not a token beginning {prefix:?}"))?
        .as_bytes();
    if h.len() % 2 != 0 {
        return Err("enroll: token hex has an odd length".into());
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    h.chunks(2)
        .map(|pair| match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => Ok(hi << 4 | lo),
            _ => Err("enroll: token is not lowercase hex".to_string()),
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Takes length-prefixed fields off a byte slice, refusing anything that runs past it.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.bytes.len() - self.pos {
            return Err("enroll: truncated".into());
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn field(&mut self) -> Result<&'a [u8], String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")) as usize;
        self.take(n)
    }

    fn end(&self) -> Result<(), String> {
        if self.pos != self.bytes.len() {
            return Err(format!(
                "enroll: {} bytes left over",
                self.bytes.len() - self.pos
            ));
        }
        Ok(())
    }
}
