//! `archon version` — print the version + build info: one line `archon <semver> (<commit>)`.
//! The commit is `ARCHON_GIT_COMMIT` when a build stamps it, else "unknown" — so the value
//! is pinned only by SHAPE (a leading `archon <semver>`), never byte-for-byte.

use crate::io::wants_help;

const USAGE: &str = "usage: archon version  (prints version + build info)";

/// The single line both `archon version` and the top-level `--version` print.
pub fn version_line() -> String {
    let commit = option_env!("ARCHON_GIT_COMMIT").unwrap_or("unknown");
    format!("archon {} ({commit})", env!("CARGO_PKG_VERSION"))
}

/// Entry point for `archon version`.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    println!("{}", version_line());
    Ok(())
}
