//! Shared public-key rendering — one place so every entry point that emits a public key
//! agrees byte-for-byte across the three lanes (pinned by cli/smoke.mjs).
//!
//! Three formats, each a total `Result`:
//!   - `spki` → the keycodec SPKI PEM, returned VERBATIM (it carries its own single trailing
//!     newline — callers print it with `print!`, never `println!`).
//!   - `text` → the canonical key text `ed25519:<hex>` + one `\n`.
//!   - `hex`  → the raw 32-byte pubkey as lowercase hex + one `\n`.

use archon_core::hexbytes::to_hex;
use archon_core::keycodec::pubkey_to_spki_pem;
use archon_core::keytext::encode_key;

/// The output format selected by `--format` / `--pub-format`.
pub enum PubFormat {
    Spki,
    Text,
    Hex,
}

impl PubFormat {
    pub fn name(&self) -> &'static str {
        match self {
            PubFormat::Spki => "spki",
            PubFormat::Text => "text",
            PubFormat::Hex => "hex",
        }
    }
}

/// Parse a format name. Validating at flag-parse time means a bad format errors before
/// any input is read or any key is written.
pub fn parse_pub_format(s: &str) -> Result<PubFormat, String> {
    match s {
        "spki" => Ok(PubFormat::Spki),
        "text" => Ok(PubFormat::Text),
        "hex" => Ok(PubFormat::Hex),
        other => Err(format!("unknown --format {other:?} (want spki|text|hex)")),
    }
}

/// Render a 32-byte public key in the selected format, returning the exact bytes to print.
pub fn render_pubkey(pk: &[u8], fmt: &PubFormat) -> Result<String, String> {
    match fmt {
        PubFormat::Spki => pubkey_to_spki_pem(pk),
        PubFormat::Text => Ok(format!("{}\n", encode_key(pk))),
        PubFormat::Hex => Ok(format!("{}\n", to_hex(pk))),
    }
}
