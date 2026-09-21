//! Hex and JSON helpers. Small on purpose: the wire format is §4's and is spelled where the
//! routes are, not abstracted behind builders that would hide it.

use crate::{ERR_INVALID_REQUEST, MAX_BODY_BYTES, MIN_CODE_HEX};

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("odd length ({})", text.len()));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Parses a request body strictly: capped, and with UNKNOWN FIELDS REFUSED.
///
/// The refusal is deliberate and is the same rule the CLI applies in the other direction. A
/// caller sending a field this crate does not know is speaking a different version of the
/// protocol, and half-reading their message is how two peers come to disagree about what was
/// agreed. Refusing says so at the door — and in particular refuses an `audience` field,
/// which is exactly the value Finding 1 forbids trusting.
pub(crate) fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err(format!(
            "body is {} bytes, over the {MAX_BODY_BYTES} cap",
            body.len()
        ));
    }
    let mut de = serde_json::Deserializer::from_slice(body);
    let value = serde_path_to_error::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// The error body of §4: exactly `{"error": "<code>"}` and nothing else. No description, no
/// echoed id — a client that guessed an id learns only that it is not pending, which is the
/// same thing it learns for an id that never existed.
pub(crate) fn error_body(code: &str) -> Vec<u8> {
    format!("{{\"error\":\"{code}\"}}").into_bytes()
}

/// The body for a request that could not be parsed at all.
pub(crate) fn malformed() -> Vec<u8> {
    error_body(ERR_INVALID_REQUEST)
}

/// Refuses a code that is not what §4.1 says a code is: lowercase hex of even length, at
/// least [`MIN_CODE_HEX`] characters (≥ 16 bytes of the prover's own entropy). The offer route
/// answers `400` to a refusal; begin's `offer` member and the read route answer `404`, because
/// a registered code is always well-formed and so a malformed one is unknown by construction
/// — a stranger learns nothing from the difference (the same rule as an unknown versus an
/// expired id).
pub(crate) fn check_code(code: &str) -> Result<(), String> {
    if code.len() < MIN_CODE_HEX || !code.len().is_multiple_of(2) {
        return Err(format!(
            "a code is lowercase hex of even length, at least {MIN_CODE_HEX} characters"
        ));
    }
    if !code
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("a code is lowercase hex".to_string());
    }
    Ok(())
}

/// Refuses what the CLI could not display faithfully: an empty entry, invalid UTF-8, or a
/// control character (§3.1).
///
/// Rust needs no UTF-8 arm — a `String` cannot hold invalid UTF-8, so `serde_json` has
/// already refused that on this crate's behalf. Go and TypeScript check it explicitly,
/// because their string types can.
///
/// The scheme refuses these too, at `binding`. Refusing HERE as well is not redundancy for
/// its own sake: the scheme's refusal happens when a proof is made, which is AFTER the person
/// has read the statement — so a request that could lie on screen would already have been
/// shown. Checking at the door means it never exists to be shown.
pub(crate) fn check_scope_entry(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("a scope entry is empty".to_string());
    }
    for c in entry.chars() {
        if (c as u32) < 0x20 || c as u32 == 0x7f {
            return Err(format!("a scope entry carries a control character ({c:?})"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // THE DOOR CHECK, tested on the function rather than through the route.
    //
    // Through `begin` this is invisible: the scheme's own `binding` refuses the same strings,
    // so a malformed scope entry answers 400 either way and a route-level test cannot tell
    // which check fired. That is not a guess -- the call was removed from `begin` and the
    // whole suite stayed green, which is how this test came to exist.
    //
    // It still belongs at the door. The scheme refuses when a proof is MADE, which is AFTER
    // the person has read the statement, so an entry that could repaint the terminal would
    // already have been shown. Checking here means it never exists to be shown.
    #[test]
    fn a_scope_entry_that_could_lie_on_screen_is_refused_at_the_door() {
        assert!(check_scope_entry("").is_err(), "an empty entry");
        // ESC [ 2 J is "clear the screen" -- the whole reason this check exists.
        assert!(check_scope_entry("read:\u{1b}[2Jx").is_err(), "ESC");
        assert!(check_scope_entry("read:\u{0}").is_err(), "NUL");
        assert!(check_scope_entry("read:\u{7f}").is_err(), "DEL");
        assert!(check_scope_entry("read:\r\nX-Evil: 1").is_err(), "CRLF");
        // Ordinary text passes, astral characters included: refusing every emoji would be a
        // different bug wearing the same clothes.
        assert!(check_scope_entry("read:projects").is_ok());
        assert!(
            check_scope_entry("read:\u{1f680}").is_ok(),
            "an astral character"
        );
    }

    // THE CODE PREDICATE, one function behind three routes (offer 400, begin's `offer` and the
    // poll 404). Tested on the function so the shape rule is visible: through the routes a
    // malformed code and an unknown one answer alike by design.
    #[test]
    fn a_code_is_lowercase_hex_of_even_length_and_at_least_sixteen_bytes() {
        let good = "ab".repeat(16);
        assert!(check_code(&good).is_ok());
        assert!(check_code(&"ab".repeat(24)).is_ok(), "longer is fine");
        assert!(check_code(&good[..30]).is_err(), "too short");
        assert!(check_code(&good[..31]).is_err(), "odd length");
        assert!(check_code(&good.to_uppercase()).is_err(), "uppercase");
        assert!(check_code(&format!("zz{}", &good[2..])).is_err(), "not hex");
        assert!(check_code("").is_err(), "empty");
    }

    // Hex is refused rather than half-read -- and 8f3c is TWO BYTES, not the four ASCII
    // characters that spell it. Binding the ASCII was the bug caa found across all three
    // CLI lanes; pinning the decode here is where that lesson lives in this crate.
    #[test]
    fn hex_is_refused_rather_than_half_read() {
        assert!(from_hex("abc").is_err(), "odd length");
        assert!(from_hex("zz").is_err(), "not hex at all");
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
        assert_eq!(from_hex("8f3c").unwrap(), vec![0x8f, 0x3c]);
        assert_ne!(
            from_hex("8f3c").unwrap(),
            b"8f3c".to_vec(),
            "the ASCII is not the bytes"
        );
        assert_eq!(to_hex(&[0x8f, 0x3c]), "8f3c");
    }
}
