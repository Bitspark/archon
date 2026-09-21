//! PKCS#8/SPKI PEM key codec (`ed25519-key-codec-v1`, spec Appendix A.8).
//!
//! Pure, IO-free conversions between raw 32-byte Ed25519 keys/seeds and the two standard
//! PEM containers — PKCS#8 v1 (private) and SPKI (public). A byte codec, NOT key custody
//! (archon ADR 0002): no key is held, no file is read, no randomness is drawn. The DER is
//! fixed-size, so encode is a constant prefix followed by the 32 key bytes and decode is a
//! bounded template match. Decode is PEM-only and total — any shape it does not recognize is
//! a clean `Err`, never a panic. PKCS#8 is v1-only (no embedded public key); v2 is rejected.
//! Byte-pinned across the three cores by the `keycodec` conformance family.

/// The fixed length, in bytes, of an Ed25519 public key — and of a seed.
const KEY_LEN: usize = 32;

/// SubjectPublicKeyInfo header for an Ed25519 public key (the first 12 bytes of the 44-byte
/// DER): `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING(0 unused) { pubkey } }`. The
/// trailing `0x00` is the unused-bits octet.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// PKCS#8 v1 PrivateKeyInfo header for an Ed25519 seed (the first 16 bytes of the 48-byte
/// DER): `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING
/// { seed } } }`. Version 0 = v1 (no embedded public key).
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const PEM_PUBLIC: &str = "PUBLIC KEY";
const PEM_PRIVATE: &str = "PRIVATE KEY";

/// Encode a 32-byte Ed25519 public key as SPKI PEM (`-----BEGIN PUBLIC KEY-----`).
pub fn pubkey_to_spki_pem(pubkey: &[u8]) -> Result<String, String> {
    encode(pubkey, &SPKI_PREFIX, PEM_PUBLIC)
}

/// Encode a 32-byte Ed25519 seed as PKCS#8 v1 PEM (`-----BEGIN PRIVATE KEY-----`).
pub fn seed_to_pkcs8_pem(seed: &[u8]) -> Result<String, String> {
    encode(seed, &PKCS8_PREFIX, PEM_PRIVATE)
}

/// Decode SPKI PEM back to the raw 32-byte Ed25519 public key.
pub fn spki_pem_to_pubkey(pem: &str) -> Result<[u8; KEY_LEN], String> {
    decode(pem, &SPKI_PREFIX, PEM_PUBLIC)
}

/// Decode PKCS#8 v1 PEM back to the raw 32-byte Ed25519 seed.
pub fn pkcs8_pem_to_seed(pem: &str) -> Result<[u8; KEY_LEN], String> {
    decode(pem, &PKCS8_PREFIX, PEM_PRIVATE)
}

/// `prefix || key` (key must be 32 bytes) base64'd into a single PEM line. The body is
/// 44/48 bytes -> 60/64 base64 chars, so it is always one line of at most 64 columns; the
/// framing is LF-terminated with exactly one trailing newline (spec A.8).
fn encode(key: &[u8], prefix: &[u8], pem_type: &str) -> Result<String, String> {
    if key.len() != KEY_LEN {
        return Err(format!(
            "keycodec: key must be {KEY_LEN} bytes, got {}",
            key.len()
        ));
    }
    let mut der = Vec::with_capacity(prefix.len() + KEY_LEN);
    der.extend_from_slice(prefix);
    der.extend_from_slice(key);
    let body = base64_encode(&der);
    Ok(format!(
        "-----BEGIN {pem_type}-----\n{body}\n-----END {pem_type}-----\n"
    ))
}

/// PEM-only, total decode: accept exactly the canonical fixed template for `pem_type`
/// (`prefix || 32 bytes`), tolerating `\r\n` and trailing newlines; reject anything else.
fn decode(pem: &str, prefix: &[u8], pem_type: &str) -> Result<[u8; KEY_LEN], String> {
    let normalized = pem.replace("\r\n", "\n");
    let trimmed = normalized.trim_end_matches('\n');
    let begin = format!("-----BEGIN {pem_type}-----");
    let end = format!("-----END {pem_type}-----");
    let lines: Vec<&str> = trimmed.split('\n').collect();
    if lines.len() < 3 || lines[0] != begin || lines[lines.len() - 1] != end {
        return Err(format!("keycodec: not a {pem_type:?} PEM block"));
    }
    let body: String = lines[1..lines.len() - 1].concat();
    let der = base64_decode(&body)?;
    if der.len() != prefix.len() + KEY_LEN || &der[..prefix.len()] != prefix {
        return Err(format!(
            "keycodec: DER does not match the {pem_type} ed25519-key-codec-v1 template"
        ));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&der[prefix.len()..]);
    Ok(out)
}

// ----- base64 (RFC 4648 standard alphabet, with padding) — no external dependency -----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = *chunk.get(1).unwrap_or(&0) as usize;
        let b2 = *chunk.get(2).unwrap_or(&0) as usize;
        out.push(B64[b0 >> 2] as char);
        out.push(B64[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 {
            B64[((b1 & 0x0f) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("keycodec: base64 length is not a multiple of 4".to_string());
    }
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!(
                "keycodec: invalid base64 character {:?}",
                c as char
            )),
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let (c0, c1, c2, c3) = (bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
        let v0 = val(c0)?;
        let v1 = val(c1)?;
        out.push((v0 << 2) | (v1 >> 4));
        if c2 == b'=' {
            if c3 != b'=' || i + 4 != bytes.len() {
                return Err("keycodec: malformed base64 padding".to_string());
            }
        } else {
            let v2 = val(c2)?;
            out.push((v1 << 4) | (v2 >> 2));
            if c3 == b'=' {
                if i + 4 != bytes.len() {
                    return Err("keycodec: malformed base64 padding".to_string());
                }
            } else {
                let v3 = val(c3)?;
                out.push((v2 << 6) | v3);
            }
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }
    const PUB: [u8; 32] = [0xab; 32];

    fn pem_wrap(t: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {t}-----\n{}\n-----END {t}-----\n",
            base64_encode(der)
        )
    }

    #[test]
    fn round_trips() {
        let p = seed_to_pkcs8_pem(&seed()).unwrap();
        assert_eq!(pkcs8_pem_to_seed(&p).unwrap(), seed());
        let s = pubkey_to_spki_pem(&PUB).unwrap();
        assert_eq!(spki_pem_to_pubkey(&s).unwrap(), PUB);
    }

    #[test]
    fn encode_emits_canonical_single_line_pem() {
        let p = seed_to_pkcs8_pem(&seed()).unwrap();
        assert!(p.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(p.ends_with("\n-----END PRIVATE KEY-----\n"));
        assert_eq!(p.lines().count(), 3); // header, one base64 line, footer
    }

    #[test]
    fn encode_rejects_non_32() {
        assert!(seed_to_pkcs8_pem(&[0u8; 31]).is_err());
        assert!(pubkey_to_spki_pem(&[0u8; 33]).is_err());
        assert!(seed_to_pkcs8_pem(&[]).is_err());
    }

    #[test]
    fn decode_tolerates_crlf_and_trailing_newlines() {
        let p = seed_to_pkcs8_pem(&seed()).unwrap();
        assert_eq!(pkcs8_pem_to_seed(&p.replace('\n', "\r\n")).unwrap(), seed());
        assert_eq!(pkcs8_pem_to_seed(&format!("{p}\n\n")).unwrap(), seed());
        assert_eq!(pkcs8_pem_to_seed(p.trim_end_matches('\n')).unwrap(), seed());
    }

    #[test]
    fn decode_rejects_malformed() {
        let valid_spki = pubkey_to_spki_pem(&PUB).unwrap();
        let valid_pkcs8 = seed_to_pkcs8_pem(&seed()).unwrap();
        // cross-template: each decoder rejects the other's PEM (header label).
        assert!(spki_pem_to_pubkey(&valid_pkcs8).is_err());
        assert!(pkcs8_pem_to_seed(&valid_spki).is_err());
        // bare DER (no armor), bad base64, empty.
        assert!(
            spki_pem_to_pubkey(&base64_encode(&[&SPKI_PREFIX[..], &PUB[..]].concat())).is_err()
        );
        assert!(
            spki_pem_to_pubkey("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n")
                .is_err()
        );
        assert!(spki_pem_to_pubkey("").is_err());
        // wrong length (prefix + 31 bytes).
        assert!(spki_pem_to_pubkey(&pem_wrap(
            PEM_PUBLIC,
            &[&SPKI_PREFIX[..], &PUB[..31]].concat()
        ))
        .is_err());
        // wrong OID (X25519: 0x70 -> 0x6e at index 8).
        let mut bad_oid = SPKI_PREFIX;
        bad_oid[8] = 0x6e;
        assert!(
            spki_pem_to_pubkey(&pem_wrap(PEM_PUBLIC, &[&bad_oid[..], &PUB[..]].concat())).is_err()
        );
    }

    #[test]
    fn base64_round_trips() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
        }
    }
}
