//! Typed, fail-closed hex spellings for the three fixed-size values the floor deals in.
//!
//! Every consumer hand-wrote these — `hex_to_bytes`, `seed32`, `seed_from_hex` — around
//! its archon calls, ~30 definitions per lane, each one a place for a length bug. The
//! value here is not hex (every language has hex) but the *fixed size*: a decoder that
//! returns exactly 32 or 64 bytes or fails, never a `Vec` the caller must re-check.
//! Encoding is always lowercase; decoding accepts either case. No `0x` prefix, no
//! whitespace — a spelling is a spelling.

use crate::crypto::{PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE};

/// Render bytes as lowercase hex, two digits per byte.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode the hex spelling of a 32-byte Ed25519 seed. Errors on odd length, any
/// non-hex character, or a decoded length other than 32.
pub fn seed_from_hex(text: &str) -> Result<[u8; SEED_SIZE], String> {
    fixed::<SEED_SIZE>(text, "seed")
}

/// Decode the hex spelling of a 32-byte Ed25519 public key. Same failure rules as
/// [`seed_from_hex`].
pub fn pubkey_from_hex(text: &str) -> Result<[u8; PUBLIC_KEY_SIZE], String> {
    fixed::<PUBLIC_KEY_SIZE>(text, "public key")
}

/// Decode the hex spelling of a 64-byte Ed25519 signature. Same failure rules as
/// [`seed_from_hex`].
pub fn signature_from_hex(text: &str) -> Result<[u8; SIGNATURE_SIZE], String> {
    fixed::<SIGNATURE_SIZE>(text, "signature")
}

/// Decode hex into exactly `N` bytes or fail. The length is checked on the text before
/// any byte is decoded, so a wrong-sized input never allocates.
fn fixed<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!(
            "{what} hex is {} characters, expected {}",
            text.len(),
            N * 2
        ));
    }
    let bytes = text.as_bytes();
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_digit(bytes[2 * i])?;
        let lo = hex_digit(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// Map one ASCII hex digit (either case) to its nibble value.
fn hex_digit(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character {:?}", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_lowercases() {
        let seed = [0xabu8; SEED_SIZE];
        let text = to_hex(&seed);
        assert_eq!(text, "ab".repeat(32));
        assert_eq!(seed_from_hex(&text).unwrap(), seed);
        assert_eq!(seed_from_hex(&text.to_uppercase()).unwrap(), seed);
        let sig = [0x5au8; SIGNATURE_SIZE];
        assert_eq!(signature_from_hex(&to_hex(&sig)).unwrap(), sig);
    }

    #[test]
    fn fails_closed_on_size_and_alphabet() {
        assert!(seed_from_hex(&"ab".repeat(31)).is_err()); // short
        assert!(seed_from_hex(&"ab".repeat(33)).is_err()); // long
        assert!(seed_from_hex(&format!("{}a", "ab".repeat(31))).is_err()); // odd
        assert!(seed_from_hex(&format!("{}zz", "ab".repeat(31))).is_err()); // non-hex
        assert!(seed_from_hex(&format!("0x{}", "ab".repeat(31))).is_err()); // 0x prefix
        assert!(pubkey_from_hex("").is_err());
        assert!(signature_from_hex(&"ab".repeat(32)).is_err()); // a key is not a signature
    }
}
