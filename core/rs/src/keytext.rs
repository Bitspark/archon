//! Canonical key text — the v1 wire form for a public key.
//!
//! A public key is rendered as `"ed25519:" + lowercaseHex(pubkeyBytes)` and parsed
//! by stripping that prefix and hex-decoding the body. This is the one
//! human/CLI-facing spelling of a key; the cores agree on it byte-for-byte so a key
//! printed by one core round-trips through any other.

/// The v1 key-text scheme prefix. Exactly one scheme exists today (Ed25519).
const ED25519_PREFIX: &str = "ed25519:";

/// The fixed length, in bytes, of an Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;

/// Encode public-key bytes as the canonical key text `ed25519:<lowercase-hex>`.
///
/// Accepts any byte slice (callers pass a 32-byte Ed25519 public key); the bytes are
/// rendered verbatim as lowercase hex with the scheme prefix.
pub fn encode_key(pubkey: &[u8]) -> String {
    let mut s = String::with_capacity(ED25519_PREFIX.len() + pubkey.len() * 2);
    s.push_str(ED25519_PREFIX);
    for b in pubkey {
        // Lowercase, fixed two hex digits per byte.
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode canonical key text back to its raw public-key bytes.
///
/// Strips the `ed25519:` prefix and hex-decodes the body. Returns an error string —
/// never panics — when the prefix is missing, the body is not even-length lowercase
/// or uppercase hex, or the decoded length is not 32 bytes.
pub fn decode_key(text: &str) -> Result<Vec<u8>, String> {
    let body = text
        .strip_prefix(ED25519_PREFIX)
        .ok_or_else(|| format!("missing '{ED25519_PREFIX}' prefix"))?;
    if body.len() % 2 != 0 {
        return Err("key body has an odd number of hex digits".to_string());
    }
    let mut out = Vec::with_capacity(body.len() / 2);
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    if out.len() != PUBLIC_KEY_LEN {
        return Err(format!(
            "decoded key is {} bytes, expected {PUBLIC_KEY_LEN}",
            out.len()
        ));
    }
    Ok(out)
}

/// Map one ASCII hex digit (either case) to its nibble value.
fn hex_digit(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("non-hex character {:?} in key body", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_fixed_form() {
        assert_eq!(
            encode_key(&[0x11; 32]),
            format!("ed25519:{}", "11".repeat(32))
        );
    }

    #[test]
    fn round_trip() {
        let key: Vec<u8> = (0..32).collect();
        let text = encode_key(&key);
        assert_eq!(decode_key(&text), Ok(key));
    }

    #[test]
    fn decode_uppercase_hex_is_accepted() {
        let lower = format!("ed25519:{}", "ab".repeat(32));
        let upper = format!("ed25519:{}", "AB".repeat(32));
        assert_eq!(decode_key(&upper), decode_key(&lower));
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        assert!(decode_key(&"11".repeat(32)).is_err());
    }

    #[test]
    fn decode_rejects_odd_length_body() {
        assert!(decode_key("ed25519:111").is_err());
    }

    #[test]
    fn decode_rejects_non_hex_body() {
        assert!(decode_key(&format!("ed25519:{}", "zz".repeat(32))).is_err());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        // 31 bytes of 0x11 — valid hex, valid prefix, wrong decoded length.
        assert!(decode_key(&format!("ed25519:{}", "11".repeat(31))).is_err());
        // 33 bytes.
        assert!(decode_key(&format!("ed25519:{}", "11".repeat(33))).is_err());
    }
}
