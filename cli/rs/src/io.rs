//! Input plumbing shared by every subcommand: stdin-or-`--in <file>`, as bytes or text.
//!
//! `--in <file>` exists because PowerShell has no `<` input redirection; when absent,
//! behaviour is byte-identical to the stdin default. An empty `--in ""` is rejected as
//! "no value" so all three lanes fail the same way.

use std::io::Read;

/// Read the whole input as raw bytes: the file when `in_path` is given, else stdin.
pub fn read_bytes(in_path: Option<&str>) -> Result<Vec<u8>, String> {
    match in_path {
        Some(p) => std::fs::read(p).map_err(|e| format!("could not read {p:?}: {e}")),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("could not read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

/// Read the whole input as UTF-8 text (PEM blocks).
pub fn read_text(in_path: Option<&str>) -> Result<String, String> {
    String::from_utf8(read_bytes(in_path)?).map_err(|_| "input is not UTF-8".to_string())
}

/// Scan args for an optional `--in <file>` pair, returning args with that pair removed and
/// the path (`None` when absent). A trailing or empty `--in` is a clean error.
pub fn take_in_flag(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut in_path = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--in" {
            let p = args
                .get(i + 1)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "flag \"--in\" needs a value".to_string())?;
            in_path = Some(p.clone());
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    Ok((rest, in_path))
}

/// True when the args request this command's help — `<cmd> --help` / `<cmd> -h`, with the
/// flag as the first token. Help is success (usage to STDOUT, exit 0), distinct from the
/// error path (usage to stderr, exit non-zero).
/// A JSON string literal by the one rule the three binaries share, so machine output is
/// byte-identical across them: `"` and `\` are escaped, every C0 control is `\u00xx` in
/// lowercase hex, and everything else — U+2028 included, which Go's encoder would escape — is
/// written as itself.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn wants_help(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("--help" | "-h"))
}
