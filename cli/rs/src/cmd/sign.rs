//! `archon sign` — sign raw bytes, raw or in a domain.
//!
//!   archon sign (--key-file <pkcs8.pem> | --seed <hex> | --key <name> --domain <d>)
//!               [--domain <d>] [--expect <principal>] [--in <file>] [--password-fd <n>] [--json]
//!
//! The message is the input, verbatim — stdin by default, `--in <file>` otherwise. The
//! signature is printed as 128 lowercase hex characters. With `--domain`, the signature is
//! domain-separated (Ed25519ph with the domain as RFC 8032 context) and will verify only
//! in that domain; without it, the signature is raw Ed25519 over the bytes, and separation
//! is the caller's problem. This is NOT thesmos's `sign` — that one signs a *fact* and
//! knows what a fact is. This one knows nothing.
//!
//! `--key` signs with a key in archon's store, and is the boundary ADR 0009 §5 draws for a
//! tool that is not archon: the seed never leaves this process. With `--key` the domain is
//! REQUIRED — the store does not sign raw — and so is `--expect`, the principal the caller
//! read from `archon key list --json` and built its bytes around. A header that names another
//! key is refused before the password is asked for, and the opened seed is checked again
//! before signing, so a mismatched key never produces a signature. Every signature, whatever
//! the key source, is verified against the requested key, scheme and bytes before it is
//! printed.

use archon_core::crypto::{
    public_key_from_seed, sign, sign_in_domain, verify, verify_in_domain, SEED_SIZE,
};
use archon_core::hexbytes::to_hex;
use archon_core::keytext::{decode_key, encode_key};
use sha2::{Digest, Sha256};

use crate::cmd::key_store::{read_password, take_password_fd, usable_key};
use crate::cmd::resolve_seed;
use crate::io::{json_string, read_bytes, wants_help};
use crate::keystore;

const USAGE: &str =
    "usage: archon sign (--key-file <pkcs8.pem> | --seed <hex> | --key <name> --domain <d>) \
[--domain <d>] [--expect <principal>] [--in <file>] [--password-fd <n>] [--json]\n  \
signs the input bytes (stdin, or --in <file>) and prints the signature as hex. --domain \
makes the signature domain-separated: it verifies in that domain and nowhere else. --key \
signs with a key in archon's store, in a domain only, and needs --expect: the principal \
`archon key list --json` shows for it. --json prints one versioned record instead.";

/// A refusal with the machine mode's category: what a caller branches on, where the human
/// sentence on stderr is free to change.
struct Failure {
    category: &'static str,
    message: String,
}

fn refuse(category: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        category,
        message: message.into(),
    }
}

/// Marks archon's own protocol domains (`archon-login/1`, `archon-request/1`,
/// `archon-enroll/1`). Those signatures are made only by the commands that show the person what
/// they mean; `sign` shows a length and a digest, so it refuses them for every key source,
/// before anything is read. The prefix is compared byte for byte, like a domain itself (ADR 0008
/// §2): `Archon-x` is not reserved.
const RESERVED_DOMAIN_PREFIX: &str = "archon-";

/// Gives a plain error the category.
fn as_<T>(category: &'static str, r: Result<T, String>) -> Result<T, Failure> {
    r.map_err(|message| Failure { category, message })
}

/// Entry point for `archon sign`.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    let json = args.iter().any(|a| a == "--json");
    let rest: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    sign_with(&rest, json).map_err(|f| {
        if json {
            println!("{{\"version\":1,\"error\":{}}}", json_string(f.category));
        }
        f.message
    })
}

fn sign_with(argv: &[String], json: bool) -> Result<(), Failure> {
    let (args, fd) = as_("usage", take_password_fd(argv))?;
    let mut key_file: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut key_name: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut expect_text: Option<String> = None;
    let mut in_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        let value = args
            .get(i + 1)
            .filter(|v| !v.is_empty() || flag == "--domain")
            .ok_or_else(|| refuse("usage", format!("flag {flag:?} needs a value\n{USAGE}")))?;
        match flag.as_str() {
            "--key-file" => key_file = Some(value.clone()),
            "--seed" => seed_hex = Some(value.clone()),
            "--key" => key_name = Some(value.clone()),
            "--domain" => domain = Some(value.clone()),
            "--expect" => expect_text = Some(value.clone()),
            "--in" => in_path = Some(value.clone()),
            other => return Err(refuse("usage", format!("unknown flag {other:?}\n{USAGE}"))),
        }
        i += 2;
    }
    let sources = [&key_file, &seed_hex, &key_name]
        .iter()
        .filter(|s| s.is_some())
        .count();
    if sources == 0 {
        return Err(refuse(
            "usage",
            format!("one of --key-file, --seed or --key is required\n{USAGE}"),
        ));
    }
    if sources > 1 {
        return Err(refuse(
            "usage",
            format!("--key-file, --seed and --key are mutually exclusive\n{USAGE}"),
        ));
    }
    if key_name.is_some() {
        if domain.is_none() {
            return Err(refuse(
                "usage",
                format!("--key needs --domain: archon's store does not sign raw\n{USAGE}"),
            ));
        }
        if expect_text.is_none() {
            return Err(refuse(
                "usage",
                format!(
                    "--key needs --expect <principal>: `archon key list --json` shows it\n{USAGE}"
                ),
            ));
        }
    } else if fd.is_some() {
        return Err(refuse(
            "usage",
            format!("--password-fd applies only to --key\n{USAGE}"),
        ));
    }

    // The domain is checked by the core's own rule before anything is read or asked for:
    // signing nothing with a throwaway key refuses exactly what ADR 0008 §2 refuses, and no
    // copy of that rule lives here to drift from it.
    if let Some(d) = domain.as_deref() {
        as_("domain", sign_in_domain(&[0u8; SEED_SIZE], d, &[]))?;
        if d.starts_with(RESERVED_DOMAIN_PREFIX) {
            return Err(refuse(
                "domain",
                format!(
                    "domain {} is reserved: {RESERVED_DOMAIN_PREFIX}* domains are signed only by \
archon's own commands, which show what they sign",
                    json_string(d)
                ),
            ));
        }
    }
    let expected = match expect_text.as_deref() {
        Some(text) => Some(as_("usage", decode_key(text))?),
        None => None,
    };

    if let (Some(name), Some(expected), Some(d)) =
        (key_name.as_deref(), expected.as_deref(), domain.as_deref())
    {
        // One read of the file: the header checked here is the header the tag authenticates at
        // unlock, policy included (docs/keystore.md §8.2, ADR 0012 §4).
        let (file, header) = usable_key(name).map_err(|r| refuse(r.category, r.message))?;
        let claimed = header.public_key;
        if claimed[..] != expected[..] {
            return Err(refuse(
                "key-mismatch",
                format!(
                    "key {name} is {}, not the expected {}; refusing to sign",
                    encode_key(&claimed),
                    encode_key(expected)
                ),
            ));
        }
        // Refused before the message is read or a password is asked for.
        // Fails closed on its own: an entry without a policy is refused here, whatever
        // usable_key already refused.
        match &header.policy {
            Some(p) if p.permits(d) => {}
            Some(p) => {
                return Err(refuse(
                    "policy",
                    format!(
                        "key {name} may not sign in domain {}: its policy is {p}",
                        json_string(d)
                    ),
                ))
            }
            None => {
                return Err(refuse(
                    "policy",
                    format!("key {name} carries no policy; refusing to sign"),
                ))
            }
        }
        let message = as_("input", read_bytes(in_path.as_deref()))?;
        let preamble = format!(
            "signing {} bytes (sha256 {}) in domain {} with {name} ({})\n",
            message.len(),
            to_hex(&Sha256::digest(&message)),
            json_string(d),
            encode_key(expected)
        );
        let password = as_("password", read_password(fd, false, &preamble))?;
        let seed = as_("unlock-failed", keystore::open(&file, &password))?;
        let principal = public_key_from_seed(&seed);
        if principal[..] != *expected {
            return Err(refuse(
                "key-mismatch",
                format!("key {name} did not open to the expected key; refusing to sign"),
            ));
        }
        return emit(&seed, &principal, Some(d), &message, json);
    }

    let seed = as_(
        "input",
        resolve_seed(seed_hex.as_deref(), key_file.as_deref(), USAGE),
    )?;
    let principal = public_key_from_seed(&seed);
    if let Some(expected) = expected.as_deref() {
        if principal[..] != *expected {
            return Err(refuse(
                "key-mismatch",
                format!(
                    "the key is {}, not the expected {}; refusing to sign",
                    encode_key(&principal),
                    encode_key(expected)
                ),
            ));
        }
    }
    let message = as_("input", read_bytes(in_path.as_deref()))?;
    emit(&seed, &principal, domain.as_deref(), &message, json)
}

/// Signs, checks the signature against what was REQUESTED, and prints it.
fn emit(
    seed: &[u8; SEED_SIZE],
    principal: &[u8],
    domain: Option<&str>,
    message: &[u8],
    json: bool,
) -> Result<(), Failure> {
    let (sig, ok) = match domain {
        Some(d) => {
            let sig = as_("domain", sign_in_domain(seed, d, message))?;
            let ok = verify_in_domain(principal, d, message, &sig);
            (sig, ok)
        }
        None => {
            let sig = sign(seed, message);
            let ok = verify(principal, message, &sig);
            (sig, ok)
        }
    };
    if !ok {
        return Err(refuse(
            "internal",
            "the signature did not verify; nothing was printed",
        ));
    }
    if !json {
        println!("{}", to_hex(&sig));
        return Ok(());
    }
    let (scheme, domain_member) = match domain {
        Some(d) => (
            "ed25519ph-context",
            format!(",\"domain\":{}", json_string(d)),
        ),
        None => ("ed25519-raw", String::new()),
    };
    println!(
        "{{\"version\":1,\"principal\":{},\"scheme\":{}{domain_member},\"signature\":{}}}",
        json_string(&encode_key(principal)),
        json_string(scheme),
        json_string(&to_hex(&sig))
    );
    Ok(())
}
