//! `archon key add|list|rm|default|export` — the password-protected seed store of
//! ADR 0007 §A. The format lives in [`crate::keystore`]; this file is the command: flags,
//! prompts, paths, and the lines we print about what we did.
//!
//! Every operation that destroys, reveals or creates key material says so IN SCOPE
//! (`docs/keystore.md` §6): archon speaks for its own store and never for anyone else's,
//! so an empty result means "nothing visible here", never "nothing exists". The wording is
//! pinned in `cli/smoke.mjs`.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use archon_core::crypto::{public_key_from_seed, SEED_SIZE};
use archon_core::hexbytes::{pubkey_from_hex, seed_from_hex};
use archon_core::keycodec::{pkcs8_pem_to_seed, seed_to_pkcs8_pem};
use archon_core::keytext::encode_key;

use crate::keystore;
use zeroize::Zeroizing;

pub const USAGE: &str =
    "usage: archon key <add <name> [--seed <hex>|--seed-file <file>|--pkcs8 <file>] \
(--allow <context>...|--unrestricted)|list [--json]|rm <name> [--force]|default [<name>]|\
export <name> --reveal --out <file>|policy <name> [--allow <context>...|--unrestricted]>\n  \
the password-protected seed store; keys live in $ARCHON_HOME/keys (default ~/.archon). \
Every key names the contexts it may sign in (--allow, repeatable) or --unrestricted. \
Password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv; \
changing a policy takes the terminal only.";

/// Removes `--allow <context>` (repeatable) and `--unrestricted` from `args` and returns the
/// policy they name (`docs/keystore.md` §8.3). There is no default: `None` when neither
/// appears, and the caller decides whether that is allowed.
pub fn take_policy_flags(
    args: &[String],
) -> Result<(Vec<String>, Option<keystore::Policy>), String> {
    let (mut rest, mut allow, mut unrestricted) = (Vec::new(), Vec::new(), false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--allow" => {
                let c = args
                    .get(i + 1)
                    .ok_or_else(|| "--allow needs a context".to_string())?;
                allow.push(c.clone());
                i += 2;
            }
            "--unrestricted" => {
                unrestricted = true;
                i += 1;
            }
            _ => {
                rest.push(args[i].clone());
                i += 1;
            }
        }
    }
    match (unrestricted, allow.is_empty()) {
        (true, false) => Err("--allow and --unrestricted are mutually exclusive".to_string()),
        (true, true) => Ok((rest, Some(keystore::Policy::unrestricted()))),
        (false, true) => Ok((rest, None)),
        (false, false) => Ok((
            rest,
            Some(keystore::Policy::allowlist(&allow).map_err(|e| format!("--allow: {e}"))?),
        )),
    }
}

/// The refusal for a new key that names no policy: there is no default.
pub fn policy_needed(name: &str) -> String {
    format!(
        "say which contexts {name} may sign in: --allow <context> (repeatable), or --unrestricted"
    )
}

/// A refusal of a named entry with its machine-mode category (§8.2).
#[derive(Debug)]
pub struct StoreRefusal {
    pub category: &'static str,
    pub message: String,
}

impl From<StoreRefusal> for String {
    fn from(r: StoreRefusal) -> String {
        r.message
    }
}

// ---------------------------------------------------------------------------
// Where the store lives — docs/keystore.md §1.
// ---------------------------------------------------------------------------

fn archon_home() -> Result<PathBuf, String> {
    if let Ok(h) = std::env::var("ARCHON_HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "could not resolve the home directory (set ARCHON_HOME)".to_string())?;
    Ok(PathBuf::from(home).join(".archon"))
}

fn store_dir() -> Result<PathBuf, String> {
    Ok(archon_home()?.join("keys"))
}

fn key_path(name: &str) -> Result<PathBuf, String> {
    keystore::validate_name(name)?;
    Ok(store_dir()?.join(name))
}

/// Writes atomically: a temp file in the SAME directory, then a rename, so a crash
/// mid-write can never leave a half key where a whole one was.
fn write_key_file(path: &Path, blob: &[u8]) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "the key path has no directory".to_string())?;
    fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".tmp-{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| format!("could not create {}: {e}", tmp.display()))?;
        f.write_all(blob)
            .map_err(|e| format!("could not write: {e}"))?;
        f.sync_all().map_err(|e| format!("could not flush: {e}"))?;
    }
    set_owner_only(&tmp)?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("could not place {}: {e}", path.display())
    })
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not set permissions: {e}"))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), String> {
    // Windows has no mode bits; the file inherits the ACL of $ARCHON_HOME/keys, which is
    // the user's own profile directory. Saying so beats pretending 0600 happened.
    Ok(())
}

fn list_key_names() -> Result<Vec<String>, String> {
    let dir = store_dir()?;
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        // A missing store directory is an empty store, not an error: nothing added yet.
        Err(_) => return Ok(Vec::new()),
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with(".tmp-"))
        .collect();
    names.sort();
    Ok(names)
}

// ---------------------------------------------------------------------------
// Passwords — docs/keystore.md §4. Never argv.
// ---------------------------------------------------------------------------

/// Scans for `--password-fd <n>` and removes it. The password never travels in argv, so
/// this carries a descriptor number rather than the secret.
pub fn take_password_fd(args: &[String]) -> Result<(Vec<String>, Option<i32>), String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut fd = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--password-fd" {
            let v = args
                .get(i + 1)
                .ok_or_else(|| "flag \"--password-fd\" needs a value".to_string())?;
            let n: i32 = v
                .parse()
                .map_err(|_| format!("--password-fd: {v:?} is not a file descriptor"))?;
            fd = Some(n);
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    Ok((rest, fd))
}

/// In place, so the password is never copied to a buffer nothing will wipe.
fn trim_newline(b: &mut Vec<u8>) {
    while matches!(b.last(), Some(b'\n') | Some(b'\r')) {
        b.pop();
    }
}

/// The one wording for "nowhere to prompt", shared by every command that unlocks or creates a
/// key.
pub const NO_TERMINAL: &str =
    "no password: there is no terminal to prompt on — set ARCHON_KEY_PASSWORD or pass --password-fd <n>";

/// Whether there is a CONTROLLING TERMINAL to prompt on: `/dev/tty`, or the Windows console.
/// rpassword prompts and reads there, never on fd 0 — which may be carrying the very message
/// being signed (ADR 0009 §5) — so this asks the same devices rather than `stdin()`.
fn has_terminal() -> bool {
    let device = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .is_ok()
}

/// Sources the password: `--password-fd`, then `ARCHON_KEY_PASSWORD`, then an interactive
/// prompt on the controlling terminal. `confirm` asks twice when a key is being created,
/// where a typo would otherwise be discovered only at the next unlock. `preamble` is shown on
/// that terminal before the prompt, and only when there is a prompt.
///
/// `Zeroizing`, as every unlocked seed is (docs/keystore.md §4, #53): wiped on drop,
/// best-effort. The environment's own copy of `ARCHON_KEY_PASSWORD` is not ours to wipe.
pub fn read_password(
    fd: Option<i32>,
    confirm: bool,
    preamble: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if let Some(n) = fd {
        let mut buf = Zeroizing::new(Vec::new());
        read_from_fd(n, &mut buf)?;
        trim_newline(&mut buf);
        return Ok(buf);
    }
    if let Ok(v) = std::env::var("ARCHON_KEY_PASSWORD") {
        return Ok(Zeroizing::new(v.into_bytes()));
    }
    if !has_terminal() {
        return Err(NO_TERMINAL.to_string());
    }
    let first = Zeroizing::new(
        rpassword::prompt_password(format!("{preamble}password: "))
            .map_err(|e| format!("could not read the password: {e}"))?,
    );
    if confirm {
        let second = Zeroizing::new(
            rpassword::prompt_password("password (again): ")
                .map_err(|e| format!("could not read the password: {e}"))?,
        );
        if *first != *second {
            return Err("the two passwords differ".to_string());
        }
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

#[cfg(unix)]
fn read_from_fd(n: i32, buf: &mut Vec<u8>) -> Result<(), String> {
    // Via /dev/fd rather than FromRawFd: this crate is #![forbid(unsafe_code)] (main.rs),
    // and taking ownership of a descriptor the caller still owns needs `unsafe` and closes
    // it out from under them. /dev/fd/<n> is the same descriptor, opened safely, and it
    // exists on both Linux and macOS.
    //
    // fd 0 goes the SAME way as every other descriptor, so the #33 mode rule reaches it:
    // `--password-fd 0 < pw.txt` is a regular file on stdin, and go and ts check its mode.
    // This lane used to short-circuit 0 to `stdin()` and skip the check (lane A's, found
    // while wiring `login --key`). A pipe or a tty on fd 0 has no mode and passes, as before.
    let path = format!("/dev/fd/{n}");
    let mut f =
        fs::File::open(&path).map_err(|e| format!("--password-fd: could not open {path}: {e}"))?;
    refuse_loose_password_file(&f)?;
    f.read_to_end(buf)
        .map_err(|e| format!("--password-fd: could not read: {e}"))?;
    Ok(())
}

/// Refuses a password file that anyone but its owner can read (ADR 0007 §A). Only a
/// REGULAR file is checked: a pipe, a terminal or a process substitution has no meaningful
/// mode, and `--password-fd 0` fed by a heredoc is a pipe, so checking those would refuse
/// the ordinary non-interactive case for nothing.
#[cfg(unix)]
fn refuse_loose_password_file(f: &fs::File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    // Undecidable metadata refuses nothing rather than guessing; the read that follows
    // produces the real error if the descriptor is unusable.
    let Ok(meta) = f.metadata() else {
        return Ok(());
    };
    if !meta.is_file() {
        return Ok(());
    }
    let perm = meta.permissions().mode() & 0o777;
    if perm & 0o077 != 0 {
        return Err(format!(
            "--password-fd: the password file is readable by others (mode {perm:04o}); chmod 600 it"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_from_fd(n: i32, buf: &mut Vec<u8>) -> Result<(), String> {
    // Windows has no fd table to borrow from; 0 is the one descriptor a shell can point
    // at us portably, and pretending otherwise would silently read the wrong thing.
    if n != 0 {
        return Err(format!(
            "--password-fd {n} is not available on this platform; use 0 (stdin) or ARCHON_KEY_PASSWORD"
        ));
    }
    std::io::stdin()
        .read_to_end(buf)
        .map_err(|e| format!("--password-fd: could not read: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// What the store lets another command ask of it — `login --key`'s seams.
// ---------------------------------------------------------------------------

/// The store's own "is there a key called that, and can it be used": a validated name and a
/// header read — opening nothing, asking for no password. Shared by `key default <name>` and by
/// `login`'s pre-network check, so both refuse a missing, unreadable or version-1 key with one
/// wording (§8.2).
pub fn require_named_key(name: &str) -> Result<keystore::KeyHeader, String> {
    Ok(usable_key(name)?.1)
}

/// The ONE reader of the default pointer (`$ARCHON_HOME/default`), shared by `key default`
/// and by `login`'s fallback so the two can never disagree about what "the default" is.
/// Absent, unreadable, or present-but-empty all read as `None` — there is no default — and
/// the caller says what that means for it.
pub fn read_default_key_name() -> Result<Option<String>, String> {
    let pointer = archon_home()?.join("default");
    let Ok(raw) = fs::read_to_string(&pointer) else {
        return Ok(None);
    };
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    Ok(Some(name.to_string()))
}

/// Opens the key called `name`: the path, the file, the password — sourced the store's one
/// way (`--password-fd`, then `ARCHON_KEY_PASSWORD`, then a prompt) — and the seal. It is
/// the ONE unlock path, shared by `key export` and `login --key`, so no two commands can
/// ask for a password differently.
pub fn unlock_named_key(name: &str, fd: Option<i32>) -> Result<Zeroizing<[u8; SEED_SIZE]>, String> {
    let (raw, _) = usable_key(name)?;
    let password = read_password(fd, false, "")?;
    keystore::open(&raw, &password)
}

/// A stored key's file and its header as the header CLAIMS it — public key, version, policy —
/// opening nothing and asking for no password. The claim is what `sign --key --expect` checks
/// before the prompt; it is proven only when the seal opens, because `keystore::open` verifies
/// the tag over the header and refuses a seed that does not derive the public key.
///
/// Every refusal carries its category: `no-key` when no file has that name, else the header's.
pub fn read_named_key(name: &str) -> Result<(Vec<u8>, keystore::KeyHeader), StoreRefusal> {
    let no_key = |message: String| StoreRefusal {
        category: "no-key",
        message,
    };
    let path = key_path(name).map_err(no_key)?;
    let raw =
        fs::read(&path).map_err(|_| no_key(format!("no key named {name:?} in archon's store")))?;
    let header = keystore::parse_header(&raw).map_err(|e| StoreRefusal {
        category: e.kind,
        message: format!("{name}: {e}"),
    })?;
    Ok((raw, header))
}

/// [`read_named_key`] for a command that will sign, log in, export or make a key the default:
/// only a version-2 entry may (§8.2). A version-1 entry is refused with the command that
/// converts it, named in full, so a person can act on the line they read.
pub fn usable_key(name: &str) -> Result<(Vec<u8>, keystore::KeyHeader), StoreRefusal> {
    let (raw, header) = read_named_key(name)?;
    if header.version != keystore::VERSION_2 {
        return Err(StoreRefusal {
            category: "migration-required",
            message: format!(
                "{name} is a version-1 key file, which this archon no longer uses: convert it once \
with `archon key policy {name} --allow <context>` (repeatable), or `--unrestricted`"
            ),
        });
    }
    Ok((raw, header))
}

// ---------------------------------------------------------------------------
// The commands.
// ---------------------------------------------------------------------------

/// The one place a key is written, shared by `key add` and `keygen --store` so the two
/// cannot drift apart. Salt and nonce are drawn HERE, in the command: the format takes
/// them as arguments and never sources randomness, which is what makes it pinnable.
pub fn seal_and_write(
    path: &Path,
    seed: &[u8],
    password: &[u8],
    policy: &keystore::Policy,
) -> Result<String, String> {
    let mut salt = [0u8; keystore::SALT_SIZE];
    let mut nonce = [0u8; keystore::NONCE_SIZE];
    getrandom::fill(&mut salt).map_err(|e| format!("could not read OS randomness: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("could not read OS randomness: {e}"))?;
    let blob = keystore::seal(
        seed,
        password,
        &salt,
        &nonce,
        keystore::KeyParams::default(),
        policy,
    )?;
    write_key_file(path, &blob)?;
    let mut fixed = Zeroizing::new([0u8; SEED_SIZE]);
    fixed.copy_from_slice(seed);
    Ok(encode_key(&public_key_from_seed(&fixed)))
}

/// `keygen --store <name>`: the same seal path as `key add`, reached from the command that
/// already owns the CSPRNG.
pub fn store_generated(
    name: &str,
    seed: &[u8],
    fd: Option<i32>,
    policy: &keystore::Policy,
) -> Result<(), String> {
    keystore::validate_name(name)?;
    let path = key_path(name)?;
    if path.exists() {
        return Err(format!(
            "a key named {name:?} already exists; remove it first (archon key rm {name})"
        ));
    }
    let password = read_password(fd, true, "")?;
    let principal = seal_and_write(&path, seed, &password, policy)?;
    println!("generated and stored {name} ({principal}).");
    Ok(())
}

/// Accepts the two shapes ADR 0007 §A names: a 32-byte seed as 64 hex, and the first consumer's
/// `ed25519.PrivateKey` shape as 128 hex (seed ‖ public key). The public half is CHECKED
/// against the seed rather than trusted — a mismatch means the file is not what its owner
/// thinks it is, and storing it would carry the confusion forward.
fn seed_from_hexish(s: &str) -> Result<[u8; SEED_SIZE], String> {
    let s = s.trim();
    match s.len() {
        64 => seed_from_hex(s),
        128 => {
            let seed = seed_from_hex(&s[..64])?;
            let claimed = pubkey_from_hex(&s[64..])?;
            if public_key_from_seed(&seed) != claimed {
                return Err(
                    "the public half does not match the seed: this is not a consistent private key"
                        .to_string(),
                );
            }
            Ok(seed)
        }
        n => Err(format!(
            "expected 64 hex characters (a seed) or 128 (seed then public key), got {n}"
        )),
    }
}

pub fn run_add(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or_else(|| USAGE.to_string())?.clone();
    keystore::validate_name(&name)?;
    let (rest, fd) = take_password_fd(&args[1..])?;
    let (rest, policy) = take_policy_flags(&rest)?;
    let policy = policy.ok_or_else(|| policy_needed(&name))?;

    let (mut seed_hex, mut seed_file, mut pkcs8_file) = (None, None, None);
    let mut i = 0;
    while i < rest.len() {
        let value = rest
            .get(i + 1)
            .ok_or_else(|| format!("flag {:?} needs a value\n{USAGE}", rest[i]))?;
        match rest[i].as_str() {
            "--seed" => seed_hex = Some(value.clone()),
            "--seed-file" => seed_file = Some(value.clone()),
            "--pkcs8" => pkcs8_file = Some(value.clone()),
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        i += 2;
    }
    if [&seed_hex, &seed_file, &pkcs8_file]
        .iter()
        .filter(|o| o.is_some())
        .count()
        > 1
    {
        return Err(format!(
            "--seed, --seed-file and --pkcs8 are mutually exclusive\n{USAGE}"
        ));
    }

    let path = key_path(&name)?;
    // Refused BEFORE a password is asked for: a key is never silently replaced, and there
    // is no reason to make someone type a password to find that out.
    if path.exists() {
        return Err(format!(
            "a key named {name:?} already exists; remove it first (archon key rm {name})"
        ));
    }

    let (seed, from) = match (&seed_hex, &seed_file, &pkcs8_file) {
        (Some(h), _, _) => (
            Zeroizing::new(seed_from_hexish(h).map_err(|e| format!("--seed: {e}"))?),
            Some("--seed".to_string()),
        ),
        (_, Some(f), _) => {
            let raw = Zeroizing::new(
                fs::read_to_string(f).map_err(|e| format!("could not read {f:?}: {e}"))?,
            );
            (
                Zeroizing::new(seed_from_hexish(&raw).map_err(|e| format!("{f}: {e}"))?),
                Some(f.clone()),
            )
        }
        (_, _, Some(f)) => {
            let raw = Zeroizing::new(
                fs::read_to_string(f).map_err(|e| format!("could not read {f:?}: {e}"))?,
            );
            (
                Zeroizing::new(pkcs8_pem_to_seed(&raw).map_err(|e| format!("{f}: {e}"))?),
                Some(f.clone()),
            )
        }
        _ => {
            let mut s = Zeroizing::new([0u8; SEED_SIZE]);
            getrandom::fill(&mut s[..])
                .map_err(|e| format!("could not read OS randomness: {e}"))?;
            (s, None)
        }
    };

    let password = read_password(fd, true, "")?;
    let principal = seal_and_write(&path, &seed[..], &password, &policy)?;
    match from {
        None => println!("generated and stored {name} ({principal})."),
        Some(src) => {
            println!("stored {name} ({principal}) from {src}; the source file is untouched.")
        }
    }
    Ok(())
}

/// Prints what each header CLAIMS. The claim is only proven at unlock, which is why this
/// never opens a key and never asks for a password.
pub fn run_list(args: &[String]) -> Result<(), String> {
    let mut as_json = false;
    for a in args {
        if a != "--json" {
            return Err(format!("unknown flag {a:?}\n{USAGE}"));
        }
        as_json = true;
    }
    // A row for every entry whose principal can be read (`docs/keystore.md` §8.4), so an entry
    // awaiting conversion is reported as that and not as absent. The policy is the header's
    // CLAIM, read without the password, and named as such. An entry whose principal cannot be
    // read is named on stderr, one line each, so a key never vanishes without a word.
    let mut json_rows: Vec<String> = Vec::new();
    let mut text_rows: Vec<String> = Vec::new();
    for n in list_key_names()? {
        // The magic is what keeps a stray file out of this list.
        let h = match read_named_key(&n) {
            Ok((_, h)) => h,
            Err(e) => {
                eprintln!("archon key list: skipped {n}: {}", e.message);
                continue;
            }
        };
        let principal = encode_key(&h.public_key);
        let (status, claimed, text) = match &h.policy {
            Some(p) if h.version == keystore::VERSION_2 => {
                ("usable", policy_json(p), p.to_string())
            }
            _ => (
                "migration-required",
                "null".to_string(),
                format!("version 1: convert with `archon key policy {n}`"),
            ),
        };
        json_rows.push(format!(
            "{{\"name\":{},\"principal\":\"{principal}\",\"status\":\"{status}\",\"claimed_policy\":{claimed}}}",
            json_string(&n)
        ));
        text_rows.push(format!("{n}\t{principal}\t{text}"));
    }
    if as_json {
        println!("[{}]", json_rows.join(","));
        return Ok(());
    }
    for row in text_rows {
        println!("{row}");
    }
    Ok(())
}

/// A policy as `key list --json` spells it (§8.4).
fn policy_json(p: &keystore::Policy) -> String {
    if p.unrestricted {
        return "{\"mode\":\"unrestricted\"}".to_string();
    }
    if p.contexts.is_empty() {
        return "{\"mode\":\"allowlist\"}".to_string();
    }
    let contexts: Vec<String> = p.contexts.iter().map(|c| json_string(c)).collect();
    format!(
        "{{\"mode\":\"allowlist\",\"contexts\":[{}]}}",
        contexts.join(",")
    )
}

/// Shows an entry's policy, or converts a version-1 entry or changes a version-2 one
/// (`docs/keystore.md` §8.3). The change form is ALWAYS interactive: it shows the old and the
/// new policy before asking for anything, asks y/N at the controlling terminal, and takes the
/// password from that terminal only — no `--yes`, no `ARCHON_KEY_PASSWORD`, no `--password-fd`.
/// That is a safeguard against a password a program inherited, not an authorization claim
/// (ADR 0012 §6): whoever can type the password can also decrypt the file.
pub fn run_policy(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or_else(|| USAGE.to_string())?.clone();
    let (rest, policy) = take_policy_flags(&args[1..])?;
    if let Some(flag) = rest.first() {
        return Err(format!("unknown flag {flag:?}\n{USAGE}"));
    }
    let path = key_path(&name)?;
    // One read: the bytes shown are the bytes unlocked and replaced (ADR 0012 §4).
    let (file, header) = read_named_key(&name)?;
    let principal = encode_key(&header.public_key);
    let current = match &header.policy {
        Some(p) if header.version == keystore::VERSION_2 => p.to_string(),
        _ => "version 1, no policy".to_string(),
    };
    let Some(policy) = policy else {
        println!("{name} ({principal}): {current} (claimed by the header; proven only at unlock)");
        return Ok(());
    };
    let refusal = "changing a key's policy needs a person at the controlling terminal: there is \
none, and ARCHON_KEY_PASSWORD and --password-fd are not accepted here";
    if !has_terminal() {
        return Err(refusal.to_string());
    }
    let (input, output) = if cfg!(windows) {
        ("CONIN$", "CONOUT$")
    } else {
        ("/dev/tty", "/dev/tty")
    };
    let mut tty_out = fs::OpenOptions::new()
        .write(true)
        .open(output)
        .map_err(|_| refusal.to_string())?;
    write!(
        tty_out,
        "{name} ({principal})\n  policy:  {current}\n  becomes: {policy}\nchange it? [y/N] "
    )
    .map_err(|e| format!("could not write to the terminal: {e}"))?;
    let tty_in = fs::File::open(input).map_err(|_| refusal.to_string())?;
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(tty_in), &mut answer)
        .map_err(|e| format!("could not read the answer: {e}"))?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        return Err("not changed".to_string());
    }
    let password = Zeroizing::new(
        rpassword::prompt_password("password: ")
            .map_err(|e| format!("could not read the password: {e}"))?
            .into_bytes(),
    );
    let mut nonce = [0u8; keystore::NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|e| format!("could not read OS randomness: {e}"))?;
    let blob = keystore::reseal(&file, &password, &nonce, &policy)?;
    write_key_file(&path, &blob)?;
    println!(
        "changed the policy of {name} ({principal}) to {policy}; any copy of this key outside archon's store is untouched."
    );
    Ok(())
}

/// Minimal JSON string escaping — the store's names are already restricted to a safe set
/// (§5), so this only has to be correct, not general.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Removes a key and says exactly what it removed, from where, and what it does NOT speak
/// for. An unparsable file is refused unless `--force`: deleting an unrecognised file
/// inside the store silently is what this rule exists to prevent.
pub fn run_rm(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or_else(|| USAGE.to_string())?;
    let mut force = false;
    for a in &args[1..] {
        if a != "--force" {
            return Err(format!("unknown flag {a:?}\n{USAGE}"));
        }
        force = true;
    }
    let path = key_path(name)?;
    let raw = fs::read(&path).map_err(|_| format!("no key named {name:?} in archon's store"))?;
    let parsed = keystore::parse_header(&raw);
    if let Err(why) = &parsed {
        if !force {
            return Err(format!("not an archon key file: {}: {why}", path.display()));
        }
    }
    fs::remove_file(&path).map_err(|e| format!("could not remove {}: {e}", path.display()))?;
    match parsed {
        Err(why) => println!(
            "removed {name} (unreadable header: {why}) from archon's store at {}; \
any copy of this key outside it is untouched.",
            path.display()
        ),
        Ok(h) => println!(
            "removed {name} ({}) from archon's store at {}; \
any copy of this key outside it is untouched.",
            encode_key(&h.public_key),
            path.display()
        ),
    }
    Ok(())
}

/// Sets or shows the default key. Selection is by NAME, never by principal text
/// (ADR 0007 §A). The pointer lives beside `keys/`, not in it, so it can never collide
/// with a key name.
pub fn run_default(args: &[String]) -> Result<(), String> {
    let pointer = archon_home()?.join("default");
    match args.len() {
        0 => {
            let name =
                read_default_key_name()?.ok_or_else(|| "no default key is set".to_string())?;
            println!("{name}");
            Ok(())
        }
        1 => {
            let name = &args[0];
            require_named_key(name)?;
            if let Some(dir) = pointer.parent() {
                fs::create_dir_all(dir)
                    .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
            }
            fs::write(&pointer, format!("{name}\n"))
                .map_err(|e| format!("could not write {}: {e}", pointer.display()))?;
            println!("default key is now {name}.");
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

/// Writes the seed out. Refuses without `--reveal`, and refuses stdout unless `--out -`
/// says so: a seed should never land in a pipe by accident.
pub fn run_export(args: &[String]) -> Result<(), String> {
    let name = args.first().ok_or_else(|| USAGE.to_string())?.clone();
    let (rest, fd) = take_password_fd(&args[1..])?;
    let (mut reveal, mut out) = (false, String::new());
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reveal" => {
                reveal = true;
                i += 1;
            }
            "--out" => {
                out = rest
                    .get(i + 1)
                    .ok_or_else(|| format!("flag \"--out\" needs a value\n{USAGE}"))?
                    .clone();
                i += 2;
            }
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
    }
    if !reveal {
        return Err("refusing to export a seed without --reveal".to_string());
    }
    if out.is_empty() {
        return Err(
            "refusing to write a seed to stdout: pass --out <file>, or --out - to mean it"
                .to_string(),
        );
    }
    // An allowlisted entry's seed is not written out (§8.2): its policy would not travel with
    // it. A backup is the encrypted file itself. Refused from the header, before the password.
    // Fails closed on its own: only an entry whose policy is unrestricted is exported.
    match usable_key(&name)?.1.policy {
        Some(p) if p.unrestricted => {}
        Some(p) => {
            return Err(format!(
                "refusing to export {name}: its policy allows only listed contexts ({p}), and a \
plaintext seed would carry none of it; back up the encrypted file instead"
            ))
        }
        None => return Err(format!("refusing to export {name}: it carries no policy")),
    }
    let seed = unlock_named_key(&name, fd)?;
    let pem = Zeroizing::new(seed_to_pkcs8_pem(&seed[..])?);
    if out == "-" {
        print!("{}", pem.as_str());
        eprintln!("wrote the seed of {name} to stdout; the store's copy remains.");
        return Ok(());
    }
    fs::write(&out, pem.as_bytes()).map_err(|e| format!("could not write {out:?}: {e}"))?;
    set_owner_only(Path::new(&out))?;
    println!("wrote the seed of {name} to {out}; the store's copy remains.");
    Ok(())
}
