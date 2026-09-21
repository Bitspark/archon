//! `archon` — the human-facing CLI for the Rust lane.
//!
//! A thin presentation + I/O layer over the public `archon-core` API. The shape is fixed:
//! `archon <subcommand> [args]`. Each subcommand lives in its own [`cmd`] file behind a
//! single `run(args)` entry point; [`main`] only routes the subcommand name to its
//! handler. Results go to stdout; diagnostics, usage, and the `keygen` secret-key warning
//! go to stderr; any error exits non-zero.

#![forbid(unsafe_code)]

mod cmd;
mod io;
mod keystore;
mod pubrender;

use std::process::ExitCode;

/// One usage line listing every subcommand, printed to stderr on an unknown or missing
/// subcommand (exit 2).
const USAGE: &str = "usage: archon <keygen|key|login|sign|verify|version> [args]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    // Top-level help is success, not an error: `archon --help` / `-h` prints the
    // subcommand summary to STDOUT and exits 0. Per-command help is each command's own.
    if command == "--help" || command == "-h" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if command == "--version" {
        println!("{}", cmd::version::version_line());
        return ExitCode::SUCCESS;
    }

    let result = match command.as_str() {
        "keygen" => cmd::keygen::run(rest),
        "key" => cmd::key::run(rest),
        "login" => cmd::login::run(rest),
        "sign" => cmd::sign::run(rest),
        "verify" => cmd::verify::run(rest),
        "version" => cmd::version::run(rest),
        other => {
            eprintln!("archon: unknown subcommand {other:?}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("archon {command}: {err}");
            ExitCode::FAILURE
        }
    }
}
