//! `archon login` — prove possession of your key to a service, so a browser key it names
//! may act for you within a scope you are shown BEFORE signing.
//!
//!   archon login <url> [--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>]
//!                      [--authority-file <file>] [--yes]
//!   archon login --audience <base> [--scope <entry>]... --valid-for <seconds> [custody] [--authority-file <file>]
//!
//! This module owns the TRANSPORT (HTTP/JSON), the DISPLAY (the statement the person
//! confirms), and the FLOW. It owns NO scheme: the binding layout and the proof are
//! `sdk/rs/login`'s (archon#16, seat:cca authorship comment 2026-09-10T13:01Z), reached
//! through the single seam [`prove_login`]. Nothing here computes signed bytes — a binding
//! written twice is a binding that drifts.
//!
//! TWO FORMS, one command. With a URL (docs/login.md §4) the page started and the person
//! finishes here: the audience is DERIVED FROM THE INVOCATION URL, never read from the wire
//! (archon#16 Finding 1: a server that may name its own audience can name someone else's),
//! the statement is shown, and nothing is signed until the person says yes. With no URL
//! (§4.1, the offers form) the CLI starts and the page finishes: the audience is the CLI's
//! OWN configuration, the CLI offers exactly what was typed, answers only the request that
//! took its offer, asks no confirmation, and prints the ledger of that decision afterwards.

use std::io::{BufRead, Write};

use archon_core::crypto::{public_key_from_seed, SEED_SIZE};
use archon_core::keytext::{decode_key, encode_key};
use archon_sdk::login;

use crate::cmd::key_store::{
    read_default_key_name, require_named_key, take_password_fd, unlock_named_key,
};
use crate::cmd::resolve_seed;
use crate::io::wants_help;

const USAGE: &str =
    "usage: archon login <url> [--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] \
[--authority-file <file>] [--yes]\n       \
archon login --audience <base> [--scope <entry>]... --valid-for <seconds> \
[--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] [--authority-file <file>]\n  \
proves possession of your key to the service at <url> so the browser key it names may act for you. \
<url> is the invocation URL <audience>/login/<id>; the audience is derived from it, never taken from the server. \
--key names a key in the store and is the default (archon key default); --key-file is a PKCS#8 file. \
Store password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv.\n  \
with no URL, the CLI OFFERS what you typed and the page finishes: the audience is --audience or ARCHON_AUDIENCE, \
never a page's word; the code and the page address go to stderr, the ledger to stdout after the service answers; \
no confirmation is asked — what you typed is what you sign.";

// The signing domain (`archon-login/1`) is deliberately NOT declared here. It is the
// scheme's, applied inside `sdk/rs/login`, and a copy in the CLI would be a second place
// it could drift from.

/// The SCHEME's floor, cited rather than restated: `possession::MIN_NONCE_SIZE` is where it
/// is decided, and a local 16 would be a second place it could move from. It is checked
/// HERE, and not only at signing time, because a short nonce must be refused before the
/// person is asked to confirm — the check's POSITION is this lane's, its VALUE is not.
const MIN_NONCE_SIZE: usize = archon_sdk::possession::MIN_NONCE_SIZE;

/// Stands in the scope position when the request delegates nothing.
const NO_SCOPE_LINE: &str = "(no scope entries — the service asks only for proof of your key)";

/// How long to wait on the service, in seconds. Two requests, both small; a login that
/// cannot get an answer in this long has a problem the person should be told about rather
/// than waited out.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// What the service answers on `GET <audience>/login/<id>`.
///
/// NOTE the absent field: there is no `audience` here, by design. See Finding 1 above.
/// `deny_unknown_fields` is what turns that design into a refusal — a service that sends
/// an audience is speaking a protocol we do not, and is rejected rather than half-read.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub id: String,
    /// hex
    pub nonce: String,
    /// canonical key text, `ed25519:<hex>`
    pub browser: String,
    /// ordered, verbatim, displayed to the person
    pub scope: Vec<String>,
    /// seconds
    pub valid_for: u32,
    /// RFC 3339; when the REQUEST dies, not the delegation.
    ///
    /// Never read, and it must still be declared: `deny_unknown_fields` would otherwise
    /// REFUSE a service that sends it, and services do. Kept as the explicit record that
    /// this field is accepted and ignored, rather than deleted and thereby made fatal.
    #[allow(dead_code)]
    #[serde(default)]
    pub expires: String,
}

/// What we POST to `<audience>/login/<id>/answer`.
#[derive(Debug, serde::Serialize)]
pub struct LoginAnswer {
    /// canonical key text of the person's key
    pub principal: String,
    /// hex
    pub possession: String,
    /// hex; empty when no authority payload was given
    pub authority: String,
}

/// WHICH custody will sign. Decided at flag-parse time — before the audience is derived —
/// so the statement can name it and a bad choice is refused before anything is fetched or
/// shown.
#[derive(Debug, Default)]
pub struct LoginSource {
    pub seed_hex: Option<String>,
    pub key_file: Option<String>,
    pub seed_file: Option<String>,
    /// A NAME in the store, never a principal (ADR 0007 §A). Set by `--key`, or by the
    /// store's default pointer when no source flag was given.
    pub store_key: Option<String>,
}

impl LoginSource {
    /// Settles the source: exactly one flag, or none and the store's default. It never
    /// guesses a seed file — the only fallback is the pointer the person set with
    /// `archon key default`. A named store key is checked to EXIST here (a stat, opening
    /// nothing), so a typo is refused before a pointless fetch; the password and the unlock
    /// still wait for consent.
    pub fn decide(&mut self) -> Result<(), String> {
        let given = [
            &self.seed_hex,
            &self.key_file,
            &self.seed_file,
            &self.store_key,
        ]
        .iter()
        .filter(|o| o.is_some())
        .count();
        if given > 1 {
            return Err(format!(
                "--key, --seed, --key-file and --seed-file are mutually exclusive\n{USAGE}"
            ));
        }
        if given == 0 {
            let Some(name) = read_default_key_name()? else {
                return Err("no default key is set\n  pass --key <name>, --seed <hex>, --key-file <file> or --seed-file <file>, \
or choose one with: archon key default <name>"
                    .to_string());
            };
            self.store_key = Some(name);
        }
        if let Some(name) = &self.store_key {
            require_named_key(name)?;
        }
        Ok(())
    }
}

/// Entry point for `archon login`. The order is the security order and is not an accident:
/// derive the audience, fetch, validate, SHOW, confirm, only then unlock and sign.
///
/// Everything decidable WITHOUT the network — which custody signs, whether the flags agree,
/// whether a named store key exists, whether the authority file is readable — is decided
/// first, so those refusals land before a request is made and before the person reads a
/// statement they could not have signed.
pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    let Some(raw_url) = args.first() else {
        return Err(USAGE.to_string());
    };
    if raw_url.starts_with("--") {
        // No URL: the offers form (docs/login.md §4.1). The CLI starts, the page finishes.
        let mut out = std::io::stdout();
        let mut err = std::io::stderr();
        let sleep = |secs: u64| std::thread::sleep(std::time::Duration::from_secs(secs));
        let mut io = LoginIo {
            out: &mut out,
            err: &mut err,
            sleep: &sleep,
            now: &now_unix,
        };
        return run_offer(args, &mut io);
    }
    // The password descriptor is the STORE's flag, taken out first exactly as `key add`
    // does, so login sources a password the one way the store does.
    let (rest, fd) = take_password_fd(&args[1..])?;
    let mut src = LoginSource::default();
    let mut authority_file: Option<String> = None;
    let mut assume_yes = false;
    let mut i = 0;
    while i < rest.len() {
        let flag = &rest[i];
        if flag == "--yes" {
            assume_yes = true;
            i += 1;
            continue;
        }
        let value = rest
            .get(i + 1)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("flag {flag:?} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--key" => src.store_key = Some(value.clone()),
            "--seed" => src.seed_hex = Some(value.clone()),
            "--key-file" => src.key_file = Some(value.clone()),
            "--seed-file" => src.seed_file = Some(value.clone()),
            "--authority-file" => authority_file = Some(value.clone()),
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        i += 2;
    }
    src.decide()?;
    // --password-fd belongs to the store. Beside a seed file it would be silently ignored,
    // and a flag that does nothing is a flag someone will come to rely on.
    if fd.is_some() && src.store_key.is_none() {
        return Err(format!(
            "--password-fd applies only to a store key (--key, or the default)\n{USAGE}"
        ));
    }
    // `confirm` reads stdin, so a password on fd 0 would be read by the prompt first. The
    // store's own commands never confirm; this is the one place the two meet.
    if fd == Some(0) && !assume_yes {
        return Err(
            "--password-fd 0 puts the password on stdin, which the sign? prompt reads first; pass --yes with it"
                .to_string(),
        );
    }
    // Read here, not after consent: a missing authority file is refused before the person
    // has read a statement and said yes to it. The payload stays opaque (see read_authority).
    let authority = read_authority(authority_file.as_deref())?;

    // THE DERIVATION IS THE SCHEME'S (docs/login.md §2.1, sdk/rs/login). It used to live in
    // this file, in three lanes, and the three disagreed: net/url decoded the path and kept a
    // default port, the WHATWG URL dropped the port, this hand-rolled split kept userinfo.
    // The audience is the FIRST FIELD OF THE BINDING, so one URL must yield one audience
    // everywhere — which makes it the scheme's job and not a CLI's.
    let (audience, id_bytes) = login::derive_audience(raw_url)?;
    // The id crosses the wire as hex (§4) and is bound as bytes. Re-encoding what the scheme
    // handed back is exact rather than convenient: the grammar admits only lowercase hex, so
    // this round-trips the URL's own segment and is the value the service will echo.
    let id = to_hex(&id_bytes);
    let request = fetch_login_request(&audience, &id)?;
    validate_login_request(&request, &id)?;

    // SHOW BEFORE SIGN. The person confirms the statement, not the URL.
    let key_source = describe_key_source(&src);
    print!(
        "{}",
        render_statement(&audience, &request, now_unix(), &key_source)
    );
    if !assume_yes {
        let stdin = std::io::stdin();
        let mut locked = stdin.lock();
        if !confirm(&mut locked)? {
            println!("refused. nothing was signed.");
            return Ok(());
        }
    }

    // ONLY NOW is the key touched. For a store key this is where the password is asked for.
    let seed = resolve_login_seed(&src, fd)?;
    let (possession, principal) = prove_login(&seed, &audience, &request)?;
    let principal_shown = principal.clone();
    post_login_answer(
        &audience,
        &id,
        &LoginAnswer {
            principal,
            possession: to_hex(&possession),
            authority: to_hex(&authority),
        },
    )?;
    println!("signed as {principal_shown}. the browser is in.");
    Ok(())
}

/// Refuse a malformed request BEFORE anything is displayed, so the person is never shown a
/// statement built from junk. Every refusal names the field.
pub fn validate_login_request(r: &LoginRequest, want_id: &str) -> Result<(), String> {
    if r.id != want_id {
        return Err(format!(
            "login: the service answered for request {:?}, not {want_id:?}",
            r.id
        ));
    }
    let nonce = from_hex(&r.nonce).map_err(|e| format!("login: nonce is not hex: {e}"))?;
    if nonce.len() < MIN_NONCE_SIZE {
        return Err(format!(
            "login: nonce is {} bytes, min {MIN_NONCE_SIZE} — refusing a guessable challenge",
            nonce.len()
        ));
    }
    decode_key(&r.browser).map_err(|e| {
        format!(
            "login: browser key {:?} is not canonical key text: {e}",
            r.browser
        )
    })?;
    for (i, entry) in r.scope.iter().enumerate() {
        if entry.is_empty() {
            return Err(format!("login: scope entry {i} is empty"));
        }
        refuse_undisplayable(&format!("scope entry {i}"), entry)?;
    }
    if r.valid_for == 0 {
        return Err("login: valid_for is 0 — a delegation dead on arrival".to_string());
    }
    Ok(())
}

/// Reject anything that cannot be shown to the person faithfully: C0/DEL control
/// characters. A scope entry carrying an escape sequence can repaint the terminal and hide
/// what is really being signed, so display safety is a validation concern rather than a
/// cosmetic one.
///
/// This MIRRORS the scheme's own `check_text` (docs/login.md §3.2), deliberately and with
/// the duplication acknowledged: the scheme refuses these at `binding`, which is AFTER the
/// person has been shown the statement and said yes. Refusing here means a request that
/// could lie on screen never reaches the confirm prompt at all.
///
/// Rust needs no UTF-8 check to go with it — `String` cannot hold invalid UTF-8, so
/// `serde_json` has already refused that on this lane's behalf. Go and TypeScript check it
/// explicitly, because their string types can.
fn refuse_undisplayable(field: &str, s: &str) -> Result<(), String> {
    for c in s.chars() {
        if (c as u32) < 0x20 || c as u32 == 0x7f {
            return Err(format!(
                "login: {field} contains a control character ({:?}) — refusing",
                c
            ));
        }
    }
    Ok(())
}

/// EXACTLY what the person is asked to approve, and the text all three lanes must print
/// byte-identically. `now_unix` is a parameter so the wall-clock end is testable rather
/// than dependent on when the suite runs.
pub fn render_statement(
    audience: &str,
    r: &LoginRequest,
    now_unix: i64,
    key_source: &str,
) -> String {
    let mut out = format!(
        "{audience} asks you to let browser key {} act as you:\n",
        r.browser
    );
    push_scope_and_validity(&mut out, r, now_unix);
    out.push_str(&format!("signing with {key_source}\n"));
    out
}

/// The offers form's counterpart (docs/login.md §4.1 rule 4): the same fields as the
/// statement, printed AFTER answering rather than before signing, because in that form nobody
/// confirmed — the person typed the scope and the audience is the CLI's own. It names K as the
/// request delivered it, the source that signed, and the service's verdict. Never the code: the
/// ledger goes to stdout, and stdout may be a log.
pub fn render_ledger(
    audience: &str,
    r: &LoginRequest,
    now_unix: i64,
    key_source: &str,
    verdict: Option<&str>,
) -> String {
    let mut out = format!(
        "you offered {audience} to let browser key {} act as you:\n",
        r.browser
    );
    push_scope_and_validity(&mut out, r, now_unix);
    out.push_str(&format!("signed with {key_source}\n"));
    match verdict {
        None => out.push_str("the service accepted the login. the browser is in.\n"),
        Some(code) => out.push_str(&format!(
            "the service refused the login ({code}). the browser is not in.\n"
        )),
    }
    out
}

/// The middle of both renderings — every scope entry verbatim, in order, then the validity as
/// a duration and as a wall-clock end — written once so the two forms cannot drift from each
/// other in the lines they share.
fn push_scope_and_validity(out: &mut String, r: &LoginRequest, now_unix: i64) {
    // An EMPTY scope is valid (docs/login.md §3.1: 0..=65535 entries) — a proof-only service
    // asks for possession and delegates nothing. It still gets a line, because a statement
    // that silently showed nothing where the scope goes would read as a rendering bug at
    // exactly the moment the person is deciding what to sign.
    if r.scope.is_empty() {
        out.push_str(&format!("  {NO_SCOPE_LINE}\n"));
    }
    for entry in &r.scope {
        out.push_str(&format!("  {entry}\n"));
    }
    out.push_str(&format!(
        "for {}, until {}\n",
        format_duration(r.valid_for),
        format_rfc3339_utc(now_unix + i64::from(r.valid_for))
    ));
}

/// Name the custody the signature will come from, for the last line of the statement
/// (seat:cca ruling, 2026-09-10).
///
/// It is the SOURCE and not the principal, on purpose: naming the principal would mean
/// unlocking the key before the person has agreed to sign — which, for a password-protected
/// store, means demanding a password in order to show someone what they are being asked to
/// approve. The source is known without touching the key at all.
///
/// A store key is named by its NAME, whether `--key` chose it or the default pointer did:
/// the statement says what will sign, and how the name was chosen is not part of what is
/// being approved. The pinned wording is cca's (2026-09-10 20:47Z).
pub fn describe_key_source(src: &LoginSource) -> String {
    match (&src.store_key, &src.seed_file, &src.key_file, &src.seed_hex) {
        (Some(name), _, _, _) => format!("the store key {name}"),
        (_, Some(path), _, _) => format!("the seed file {path}"),
        (_, _, Some(path), _) => format!("the key file {path}"),
        (_, _, _, Some(_)) => "the seed given on the command line".to_string(),
        _ => "an unspecified key".to_string(),
    }
}

/// Render seconds the same way in every lane. Written out explicitly so Go and TypeScript
/// reproduce it exactly — a shared format nobody has to reverse-engineer.
pub fn format_duration(seconds: u32) -> String {
    let (h, m, s) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// Format a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`. Written here rather than pulled from
/// a date crate: this is the only date this CLI renders, and the civil-from-days algorithm
/// is exact and total for every timestamp we can be handed.
pub fn format_rfc3339_utc(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days, shifted to a March-based year.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read a y/N answer. Default is NO: anything that is not an explicit yes refuses,
/// including EOF, so a login cannot be completed by a closed stdin.
pub fn confirm(input: &mut impl BufRead) -> Result<bool, String> {
    print!("sign? [y/N] ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if input.read_line(&mut line).is_err() {
        return Ok(false);
    }
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Obtains the seed for the source decided at flag-parse time. Runs ONLY after the person
/// has confirmed the statement: for a store key that is the moment the password is asked
/// for, and never before. Seed files stay beside the store permanently, so an agent's
/// non-interactive run and a person's login are the same code with two custody sources
/// (ADR 0007 §A; archon#16, answer 2).
fn resolve_login_seed(src: &LoginSource, fd: Option<i32>) -> Result<[u8; SEED_SIZE], String> {
    if let Some(name) = &src.store_key {
        return unlock_named_key(name, fd);
    }
    if let Some(path) = &src.seed_file {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("could not read {path:?}: {e}"))?;
        return seed_from_hex_file(&raw);
    }
    resolve_seed(src.seed_hex.as_deref(), src.key_file.as_deref(), USAGE)
}

/// Accept the two hex seed-file shapes in use: 64 hex characters (a raw 32-byte seed) and
/// 128 (seed followed by public key), the shape the first consumer's `key` files carry (archon#16,
/// answer 4).
pub fn seed_from_hex_file(text: &str) -> Result<[u8; SEED_SIZE], String> {
    let raw = from_hex(text.trim()).map_err(|e| format!("seed file is not hex: {e}"))?;
    match raw.len() {
        32 | 64 => {
            let mut seed = [0u8; SEED_SIZE];
            seed.copy_from_slice(&raw[..SEED_SIZE]);
            Ok(seed)
        }
        n => Err(format!(
            "seed file holds {n} bytes; want 32 (seed) or 64 (seed and public key)"
        )),
    }
}

/// Read the authority payload. It is OPAQUE to archon — the delegation's meaning is the
/// law's (thesmos), and this command must never parse it. Absent is empty, a valid answer
/// for a service whose law needs none.
fn read_authority(path: Option<&str>) -> Result<Vec<u8>, String> {
    match path {
        None => Ok(Vec::new()),
        Some(p) => std::fs::read(p).map_err(|e| format!("could not read {p:?}: {e}")),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("odd length ({})", text.len()));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// GET the request. The CLI owns HTTP; the SDK never opens a socket (archon#16: no network
/// code in the sdk).
fn fetch_login_request(audience: &str, id: &str) -> Result<LoginRequest, String> {
    let endpoint = format!("{audience}/login/{id}");
    let response = minreq::get(&endpoint)
        .with_timeout(HTTP_TIMEOUT_SECS)
        .send()
        .map_err(|e| format!("login: could not reach {endpoint}: {e}"))?;
    let body = read_body(&response, &endpoint)?;
    if response.status_code != 200 {
        return Err(login_http_error(response.status_code, &body));
    }
    serde_json::from_str(&body)
        .map_err(|e| format!("login: the service's request is not the expected JSON: {e}"))
}

/// Deliver the answer and report the service's verdict as an error, which is what the
/// confirmed form wants: a refusal ends the command.
fn post_login_answer(audience: &str, id: &str, answer: &LoginAnswer) -> Result<(), String> {
    let (status, body) = post_answer(audience, id, answer)?;
    if status != 204 && status != 200 {
        return Err(login_http_error(status, &body));
    }
    Ok(())
}

/// The POST itself, returning the service's status and body so the offers form can record a
/// refusal in its ledger rather than stop on it (§4.1 rule 4: the ledger is printed whether the
/// service accepted or refused). Only a failure to reach the service is an error here — then
/// nothing was answered, and there is nothing to record.
fn post_answer(audience: &str, id: &str, answer: &LoginAnswer) -> Result<(u16, String), String> {
    let endpoint = format!("{audience}/login/{id}/answer");
    let payload = serde_json::to_string(answer)
        .map_err(|e| format!("login: could not encode the answer: {e}"))?;
    let response = minreq::post(&endpoint)
        .with_header("content-type", "application/json")
        .with_body(payload)
        .with_timeout(HTTP_TIMEOUT_SECS)
        .send()
        .map_err(|e| format!("login: could not reach {endpoint}: {e}"))?;
    let body = response.as_str().unwrap_or("").to_string();
    Ok((response.status_code, body))
}

/// The response body as text. A body that is not UTF-8 is a service speaking something this
/// protocol does not, and is a clean error rather than a lossy conversion.
fn read_body(response: &minreq::Response, endpoint: &str) -> Result<String, String> {
    response
        .as_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("login: could not read the response from {endpoint}: {e}"))
}

/// Turn a non-success response into a diagnosis.
pub fn login_http_error(status: u16, body: &str) -> String {
    #[derive(serde::Deserialize)]
    struct Payload {
        #[serde(default)]
        error: String,
        #[serde(default)]
        error_description: String,
    }
    if let Ok(p) = serde_json::from_str::<Payload>(body) {
        if !p.error.is_empty() {
            return match p.error.as_str() {
                "expired_token" => {
                    "login: this request has expired — reload the page and run the new command"
                        .to_string()
                }
                "access_denied" => "login: the service refused the login".to_string(),
                other if !p.error_description.is_empty() => {
                    format!("login: {} ({other})", p.error_description)
                }
                other => format!("login: the service answered {other:?}"),
            };
        }
    }
    format!("login: the service answered HTTP {status}")
}

// ---------------------------------------------------------------------------
// THE OFFERS FORM (docs/login.md §4.1)
// ---------------------------------------------------------------------------
//
// `archon login` with no URL. The prover starts: it mints a code from its own entropy,
// registers what it is willing to delegate, prints the code where only the person can see it,
// waits for the page to take the offer, and answers ONLY the request that took it — after
// checking for itself that the request is what was offered. No confirmation is asked: the
// person typed the scope, the audience is the CLI's own, and the only request it will answer
// carries the code it minted a moment ago. Afterwards it prints the ledger of that decision,
// whether the service accepted or refused.

/// How much of the CLI's own entropy a code carries: 16 bytes, spelled as 32 lowercase hex
/// characters, the floor §4.1 sets. The code is confidential until the offer is taken.
const CODE_BYTES: usize = 16;

/// Where the offers form writes and how it waits, injected so a test can pin the ledger
/// byte-exactly on `out`, the code and the page mark on `err`, and the pacing on `sleep` —
/// without sleeping through it or reading libtest's captured stdout, which it cannot. `run`
/// hands the real stdout, stderr, `thread::sleep` and the clock.
pub struct LoginIo<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub sleep: &'a dyn Fn(u64),
    pub now: &'a dyn Fn() -> i64,
}

/// What the prover posts to `<audience>/login/offers`.
#[derive(Debug, serde::Serialize)]
struct OfferBody {
    code: String,
    scope: Vec<String>,
    valid_for: u32,
}

/// The service's answer to an offer. `page`, when the service has one, is the address the
/// person opens, carrying the code in its fragment. No audience here either — in this form the
/// audience is the prover's own configuration — and a response carrying one is refused.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferResponse {
    pub code: String,
    #[serde(default)]
    pub scope: Vec<String>,
    pub valid_for: u32,
    pub expires_in: u64,
    pub interval: u64,
    #[serde(default)]
    pub page: Option<String>,
}

/// `GET <audience>/login/offers/<code>`: `request` is null until the page has taken the offer,
/// then the id of the request that did.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferRead {
    #[allow(dead_code)]
    code: String,
    #[allow(dead_code)]
    #[serde(default)]
    scope: Vec<String>,
    #[allow(dead_code)]
    valid_for: u32,
    #[serde(default)]
    request: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    expires: String,
}

/// The offers form. The order is §4.1's, rule by rule, and the same before-any-network
/// discipline as the confirmed form: everything decidable without the service — the custody,
/// the authority file, the scope, the validity, the audience — is decided first, so those
/// refusals land before an offer exists.
pub fn run_offer(args: &[String], io: &mut LoginIo) -> Result<(), String> {
    // The password descriptor is the STORE's flag, taken out first exactly as `key add` does.
    // `--password-fd 0` needs no `--yes` here: nothing in this form reads stdin.
    let (rest, fd) = take_password_fd(args)?;
    let mut src = LoginSource::default();
    let mut authority_file: Option<String> = None;
    let mut audience_flag: Option<String> = None;
    let mut valid_for_text: Option<String> = None;
    let mut scope: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let flag = &rest[i];
        if flag == "--yes" {
            // A flag that does nothing is a flag someone will come to rely on — and this one
            // would suggest a confirmation exists to skip.
            return Err(format!(
                "no confirmation is asked in this form — what you typed is what you sign; drop --yes\n{USAGE}"
            ));
        }
        let value = rest
            .get(i + 1)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("flag {flag:?} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--audience" => audience_flag = Some(value.clone()),
            "--scope" => scope.push(value.clone()),
            "--valid-for" => valid_for_text = Some(value.clone()),
            "--key" => src.store_key = Some(value.clone()),
            "--seed" => src.seed_hex = Some(value.clone()),
            "--key-file" => src.key_file = Some(value.clone()),
            "--seed-file" => src.seed_file = Some(value.clone()),
            "--authority-file" => authority_file = Some(value.clone()),
            other => return Err(format!("unknown flag {other:?}\n{USAGE}")),
        }
        i += 2;
    }
    src.decide()?;
    if fd.is_some() && src.store_key.is_none() {
        return Err(format!(
            "--password-fd applies only to a store key (--key, or the default)\n{USAGE}"
        ));
    }
    let authority = read_authority(authority_file.as_deref())?;
    // WHAT YOU TYPED IS WHAT YOU SIGN — so what was typed is checked the way the service will
    // check it, here, before an offer nobody could begin on is registered.
    for (i, entry) in scope.iter().enumerate() {
        if entry.is_empty() {
            return Err(format!("login: --scope entry {i} is empty"));
        }
        refuse_undisplayable(&format!("--scope entry {i}"), entry)?;
    }
    let valid_for = parse_valid_for(valid_for_text.as_deref())?;
    // RULE 1: the audience is the CLI's own configuration, a fixed point of §2.1's grammar,
    // refused before anything is fetched.
    let audience = configured_audience(audience_flag.as_deref())?;

    // The code is the CLI's own entropy, registered under it. The service echoes the offer
    // back; an echo that differs is a service that altered what was offered, and nothing of it
    // is trusted from here on.
    let code = mint_code()?;
    let offered = post_offer(
        &audience,
        &OfferBody {
            code: code.clone(),
            scope: scope.clone(),
            valid_for,
        },
    )?;
    check_offer_echo(&offered, &code, &scope, valid_for)?;
    // STDERR, deliberately: the interactive channel, where the password prompt already lives.
    // `archon login … > file` must never write the code into a log (§4.1 rule 1).
    let say = |io: &mut LoginIo, line: String| {
        io.err
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("login: could not write to stderr: {e}"))
    };
    say(io, format!("offer registered at {audience}"))?;
    say(io, format!("code: {code}"))?;
    if let Some(page) = &offered.page {
        say(io, describe_page(&audience, page))?;
    }
    say(
        io,
        format!(
            "waiting for the page to take the offer, up to {}s",
            offered.expires_in
        ),
    )?;

    // The prover paces ITSELF (ADR 0007 §C.7, #39): the route is unpaced because two parties
    // poll it, so the discipline is here — one interval before the first poll, so the page
    // always has the first window, and one between polls.
    let id = poll_offer(&audience, &code, &offered, io)?;

    // RULE 2: answer only the request the offer names, and only after re-checking it against
    // what was offered — never trusting that the service's refusal happened. K is RECORDED
    // from the request; it was never offered, so it is not checked, and it is what the ledger
    // names.
    let request = fetch_login_request(&audience, &id)?;
    validate_login_request(&request, &id)?;
    check_against_offer(&request, &scope, valid_for)?;

    // RULE 3: no confirmation. The key is unlocked now — for a store key this is where the
    // password is asked for, and a person who never finishes never types it — and the proof
    // made and posted.
    let seed = resolve_login_seed(&src, fd)?;
    let (possession, principal) = prove_login(&seed, &audience, &request)?;
    let (status, body) = post_answer(
        &audience,
        &id,
        &LoginAnswer {
            principal,
            possession: to_hex(&possession),
            authority: to_hex(&authority),
        },
    )?;

    // RULE 4: the ledger, accepted or refused, on stdout — field by field, never the code.
    let verdict = error_code_of(status, &body);
    let ledger = render_ledger(
        &audience,
        &request,
        (io.now)(),
        &describe_key_source(&src),
        verdict.as_deref(),
    );
    io.out
        .write_all(ledger.as_bytes())
        .map_err(|e| format!("login: could not write to stdout: {e}"))?;
    match verdict {
        None => Ok(()),
        Some(code) => Err(format!("login: the service refused the login ({code})")),
    }
}

/// Reads --valid-for. Required: a delegation's lifetime is typed, never assumed — a default
/// here would be a number nobody chose, signed anyway.
fn parse_valid_for(text: Option<&str>) -> Result<u32, String> {
    let Some(text) = text else {
        return Err(format!(
            "--valid-for <seconds> is required — a delegation's lifetime is typed, never assumed\n{USAGE}"
        ));
    };
    match text.parse::<u32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!(
            "--valid-for must be a whole number of seconds, 1 or more; got {text:?}"
        )),
    }
}

/// §4.1 rule 1. The audience is --audience, or ARCHON_AUDIENCE as the configured default,
/// checked exactly the same way: it must be a fixed point of §2.1's grammar — the very check the
/// server applies to its own configuration — and the CLI refuses to start otherwise. The
/// `/login/00` is the shortest invocation URL the grammar admits, there only to make the
/// audience parseable as one; feeding the audience through the scheme's derivation asks the one
/// question that matters: is this the string the service binds?
pub fn configured_audience(flag: Option<&str>) -> Result<String, String> {
    let audience = match flag {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => std::env::var("ARCHON_AUDIENCE").unwrap_or_default(),
    };
    if audience.is_empty() {
        return Err(
            "login: no audience — pass --audience <base> or set ARCHON_AUDIENCE; \
in this form the audience is your configuration, never a page's word (docs/login.md §4.1)"
                .to_string(),
        );
    }
    let (derived, _) = login::derive_audience(&format!("{audience}/login/00")).map_err(|e| {
        format!("login: audience {audience:?} is not valid: {e} (docs/login.md §2.1)")
    })?;
    if derived != audience {
        return Err(format!(
            "login: audience {audience:?} is not canonical — the service binds {derived:?}; pass that (docs/login.md §2.1)"
        ));
    }
    Ok(audience)
}

/// The code, from the OS CSPRNG. The randomness lives HERE, in the command, as every other
/// randomness of the pinned tiers does (ADR 0006).
fn mint_code() -> Result<String, String> {
    let mut raw = [0u8; CODE_BYTES];
    getrandom::fill(&mut raw).map_err(|e| format!("login: could not draw a code: {e}"))?;
    Ok(to_hex(&raw))
}

/// Registers the offer. Unknown fields in the response are refused, as everywhere in this
/// command: a service adding fields is speaking a protocol this lane does not.
fn post_offer(audience: &str, offer: &OfferBody) -> Result<OfferResponse, String> {
    let endpoint = format!("{audience}/login/offers");
    let payload = serde_json::to_string(offer)
        .map_err(|e| format!("login: could not encode the offer: {e}"))?;
    let response = minreq::post(&endpoint)
        .with_header("content-type", "application/json")
        .with_body(payload)
        .with_timeout(HTTP_TIMEOUT_SECS)
        .send()
        .map_err(|e| format!("login: could not reach {endpoint}: {e}"))?;
    let body = read_body(&response, &endpoint)?;
    if response.status_code != 201 {
        return Err(login_http_error(response.status_code, &body));
    }
    serde_json::from_str(&body)
        .map_err(|e| format!("login: the service's offer is not the expected JSON: {e}"))
}

/// Requires the service to have registered EXACTLY what was offered. The offer is what the
/// person typed; a service that echoes something else has altered it, and a prover that went on
/// would be waiting to sign a delegation nobody typed.
fn check_offer_echo(
    offered: &OfferResponse,
    code: &str,
    scope: &[String],
    valid_for: u32,
) -> Result<(), String> {
    if offered.code != code {
        return Err(
            "login: the service altered the offer: the code it registered is not the one sent"
                .to_string(),
        );
    }
    same_scope_and_validity(&offered.scope, offered.valid_for, scope, valid_for)
        .map_err(|e| format!("login: the service altered the offer: {e}"))?;
    if offered.expires_in == 0 {
        return Err("login: the service's offer has no lifetime (expires_in)".to_string());
    }
    Ok(())
}

/// The one line about the page address, printed and MARKED, never opened (§4.1 rule 1; ADR
/// 0007 §C.7 (6)). "On the service's own origin" is a byte-exact comparison of scheme and host
/// with the audience's — a differently spelled origin fails closed, the right direction for an
/// address a person is about to click — and launching a browser is the person's action, never
/// this command's: spawning a platform opener by name is the PATH surface §C.5 refuses.
pub fn describe_page(audience: &str, page: &str) -> String {
    let origin = origin_of(audience);
    let on_origin = page == origin
        || page.starts_with(&format!("{origin}/"))
        || page.starts_with(&format!("{origin}#"))
        || page.starts_with(&format!("{origin}?"));
    if on_origin {
        format!("page: {page} (on the service's own origin)")
    } else {
        format!("page: {page} (NOT on the service's origin — do not open it)")
    }
}

/// The audience up to its path: scheme, host and port, as the audience spells them (canonical
/// by construction — `configured_audience` made sure).
fn origin_of(audience: &str) -> &str {
    let after_scheme = audience.find("://").map(|i| i + 3).unwrap_or(0);
    match audience[after_scheme..].find('/') {
        Some(i) => &audience[..after_scheme + i],
        None => audience,
    }
}

/// Waits for the page to take the offer and returns the id of the request that did.
///
/// The pacing is the prover's own (ADR 0007 §C.7, #39): one advertised interval BEFORE the
/// first poll — the page always gets the first window — and one between polls; a 429 from a
/// server that paces anyway is sleep-and-retry, never an error. The wait is bounded by the
/// offer's own lifetime, and a 404 before then is the offer gone — expired, or taken and already
/// finished — which for a prover still waiting means the page never took it.
fn poll_offer(
    audience: &str,
    code: &str,
    offered: &OfferResponse,
    io: &mut LoginIo,
) -> Result<String, String> {
    let interval = offered.interval.max(1);
    let deadline = (io.now)() + offered.expires_in as i64;
    let endpoint = format!("{audience}/login/offers/{code}");
    loop {
        (io.sleep)(interval);
        if (io.now)() > deadline {
            return Err("login: the offer expired before the page took it".to_string());
        }
        let response = minreq::get(&endpoint)
            .with_timeout(HTTP_TIMEOUT_SECS)
            .send()
            .map_err(|e| format!("login: could not reach {endpoint}: {e}"))?;
        let body = read_body(&response, &endpoint)?;
        match response.status_code {
            429 => continue,
            404 => return Err("login: the offer expired before the page took it".to_string()),
            200 => {}
            other => return Err(login_http_error(other, &body)),
        }
        let read: OfferRead = serde_json::from_str(&body)
            .map_err(|e| format!("login: the service's offer is not the expected JSON: {e}"))?;
        if let Some(id) = read.request.filter(|id| !id.is_empty()) {
            return Ok(id);
        }
    }
}

/// §4.1 rule 2, done by the prover for itself: the request's scope must be what was offered,
/// entry for entry, in order, and its validity equal. The service refuses a mismatched begin
/// before storing anything — but a prover that relied on that would be trusting the service
/// about the one thing it is about to sign.
pub fn check_against_offer(
    r: &LoginRequest,
    scope: &[String],
    valid_for: u32,
) -> Result<(), String> {
    same_scope_and_validity(&r.scope, r.valid_for, scope, valid_for).map_err(|e| {
        format!("login: the service's request differs from the offer — {e} — refusing to sign")
    })
}

/// "Differs in any way", stated once for the echo and for the request: the same number of
/// entries, each equal to its counterpart IN ORDER, the same validity.
fn same_scope_and_validity(
    got_scope: &[String],
    got_valid_for: u32,
    scope: &[String],
    valid_for: u32,
) -> Result<(), String> {
    if got_valid_for != valid_for {
        return Err(format!("valid_for is {got_valid_for}, offered {valid_for}"));
    }
    if got_scope.len() != scope.len() {
        return Err(format!(
            "{} scope entries, offered {}",
            got_scope.len(),
            scope.len()
        ));
    }
    for (i, (got, want)) in got_scope.iter().zip(scope).enumerate() {
        if got != want {
            return Err(format!("scope entry {i} is {got:?}, offered {want:?}"));
        }
    }
    Ok(())
}

/// The service's verdict for the ledger: `None` for an accepted answer; otherwise the RFC 8628
/// code from the error body, or the bare status when the body carries none.
fn error_code_of(status: u16, body: &str) -> Option<String> {
    if status == 204 || status == 200 {
        return None;
    }
    #[derive(serde::Deserialize)]
    struct Payload {
        #[serde(default)]
        error: String,
    }
    match serde_json::from_str::<Payload>(body) {
        Ok(p) if !p.error.is_empty() => Some(p.error),
        _ => Some(format!("HTTP {status}")),
    }
}

// ---------------------------------------------------------------------------
// THE SCHEME SEAM
// ---------------------------------------------------------------------------
//
// The one place this lane reaches the login scheme, and the only part of this file that
// changes when `sdk/rs/login` lands. The scheme — binding layout, role tags, proof — is
// seat:cca's (archon#16). Pinned by their authorship comment, for whoever wires this up:
//
//   binding = role ‖ u16 len ‖ audience ‖ K[32] ‖ u16 len ‖ id ‖ scope ‖ u32 valid_for
//   scope   = u16 count ‖ (u16 len ‖ bytes)*
//   role    = 0x01 person's login proof (signed by P), 0x02 browser's collect proof (by K)
//   proof   = possession over the server's nonce and that binding, domain archon-login/1

/// The person's login proof over this request, plus their principal as canonical key text.
///
/// What stays on THIS side of the seam is the wire-to-scheme conversion — hex and key text
/// in, bytes out — plus the principal, which is a property of the seed rather than of the
/// scheme. The binding, the role tag, the domain and the proof are all the scheme's.
///
/// The decodes below were validated already by [`validate_login_request`], which runs
/// BEFORE the person is shown anything. They are re-checked rather than assumed, because
/// this function is reachable from any future caller and a silent mis-decode would produce
/// a proof bound to bytes nobody displayed.
pub fn prove_login(
    seed: &[u8; SEED_SIZE],
    audience: &str,
    request: &LoginRequest,
) -> Result<(Vec<u8>, String), String> {
    let principal = encode_key(&public_key_from_seed(seed));
    let nonce = from_hex(&request.nonce).map_err(|e| format!("login: nonce is not hex: {e}"))?;
    let browser = decode_key(&request.browser)
        .map_err(|e| format!("login: browser key is not canonical key text: {e}"))?;

    // THE ID IS HEX-DECODED, NOT HANDED OVER AS TEXT. docs/login.md §3.1 makes the id BYTES
    // carried as "hex in URLs and JSON"; the scheme binds the bytes. Passing the string's
    // own bytes would bind the ASCII of the hex — 0x38 0x66 0x33 0x63 for "8f3c" instead of
    // 0x8f 0x3c — and the resulting proof verifies NOWHERE. A stub test that builds its
    // expected Request the same wrong way still passes, which is how it survived; the test
    // below decodes independently and asserts the ASCII form does NOT verify.
    let id_bytes = from_hex(&request.id).map_err(|e| format!("login: id is not hex: {e}"))?;
    let proof = login::prove(
        seed,
        audience,
        &login::Request {
            id: id_bytes,
            nonce,
            browser,
            scope: request.scope.clone(),
            valid_for: request.valid_for,
        },
    )?;
    Ok((proof.to_vec(), principal))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Held for the whole of every test that sets ARCHON_HOME, ARCHON_KEY_PASSWORD or
    /// ARCHON_AUDIENCE. Those are process-global and cargo runs tests in parallel: with two
    /// such tests in this module, one's `remove_var` at its end pulled the store out from under
    /// the other mid-scenario — a flake found the first time the offers e2e ran beside the
    /// store-key e2e. `set_var` is plain under edition 2021; it becomes `unsafe fn` in 2024 and
    /// this crate forbids unsafe, so both tests need a different shape then — not a lifted forbid.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const BROWSER: &str =
        "ed25519:7a91b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f";

    fn valid_request() -> LoginRequest {
        LoginRequest {
            id: "8f3c".to_string(),
            nonce: "ab".repeat(16),
            browser: BROWSER.to_string(),
            scope: vec!["read:projects".to_string(), "read:campaigns".to_string()],
            valid_for: 28_800,
            expires: "2026-09-10T18:04:00Z".to_string(),
        }
    }

    // The audience rule is the security boundary of this command: the only thing standing
    // between a phished invocation URL and a proof made out to the wrong service. Tested
    // exhaustively rather than representatively.
    #[test]
    fn derives_the_audience() {
        for (url, audience, id) in [
            (
                "https://prover.core.example.dev/login/8f3c",
                "https://prover.core.example.dev",
                "8f3c",
            ),
            (
                "https://prover.core.example.dev/api/login/8f3c",
                "https://prover.core.example.dev/api",
                "8f3c",
            ),
            (
                "https://h.example/a/b/c/login/ab12",
                "https://h.example/a/b/c",
                "ab12",
            ),
            ("ws://h.example/login/1a", "http://h.example", "1a"),
            (
                "wss://h.example/api/login/1a",
                "https://h.example/api",
                "1a",
            ),
            ("HTTPS://h.example/login/1a", "https://h.example", "1a"),
            (
                "https://Prover.Core.Example.DEV/login/1a",
                "https://prover.core.example.dev",
                "1a",
            ),
            (
                "http://localhost:8080/api/login/1a",
                "http://localhost:8080/api",
                "1a",
            ),
            (
                "https://h.example/API/login/1a",
                "https://h.example/API",
                "1a",
            ),
        ] {
            let (got_audience, got_id_bytes) = login::derive_audience(url).expect(url);
            let got_id = to_hex(&got_id_bytes);
            assert_eq!(got_audience, audience, "audience for {url}");
            assert_eq!(got_id, id, "id for {url}");
        }
    }

    // Each of these must NOT yield an audience. A guess would be worse than a refusal: it
    // would silently sign for something the person did not read.
    #[test]
    fn refuses_urls_that_are_not_invocations() {
        for url in [
            "https://h.example/api/8f3c",
            "https://h.example/signin/8f3c",
            "https://h.example/login",
            "https://h.example/",
            "https:///login/1a",
            "ftp://h.example/login/1a",
            "file:///login/1a",
            "https://h.example/login/1?next=evil",
            "https://h.example/login/1#x",
            "not-a-url",
            // A TRAILING SLASH IS NOW A REFUSAL, and this lane used to ACCEPT it and trim it.
            // docs/login.md §2.1 makes it an empty segment (oracle: trailing-slash-rejected).
            // The test was encoding a normalisation — exactly what moving this into the
            // scheme was meant to stop — so it flipped rather than the scheme bending to it.
            "https://prover.core.example.dev/api/login/8f3c/",
            // Userinfo is refused, not normalised: the three parsers disagree about it, and
            // the disagreement is the phished-invocation shape the rule exists to stop.
            "https://user:pass@h.example/api/login/8f3c",
            "https://user@h.example/login/8f3c",
            // The id is BYTES carried as lowercase hex (docs/login.md §3.1, §4).
            "https://h.example/login/a%20b",
            "https://h.example/login/a%2Fb",
            "https://h.example/login/a b",
            "https://h.example/login/8F3C",
            "https://h.example/login/8f3",
            "https://h.example/login/zzzz",
            "https://h.example/login/a",
        ] {
            assert!(login::derive_audience(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn accepts_a_valid_request() {
        validate_login_request(&valid_request(), "8f3c").expect("valid request rejected");
    }

    #[test]
    fn refuses_malformed_requests() {
        type Break = Box<dyn Fn(&mut LoginRequest)>;
        let cases: Vec<(&str, Break)> = vec![
            (
                "id mismatch",
                Box::new(|r: &mut LoginRequest| r.id = "other".into()),
            ),
            (
                "nonce not hex",
                Box::new(|r: &mut LoginRequest| r.nonce = "zzzz".into()),
            ),
            (
                "nonce too short",
                Box::new(|r: &mut LoginRequest| r.nonce = "ab".repeat(15)),
            ),
            (
                "browser not key text",
                Box::new(|r: &mut LoginRequest| r.browser = "7a91".into()),
            ),
            (
                "empty scope entry",
                Box::new(|r: &mut LoginRequest| r.scope = vec![String::new()]),
            ),
            (
                "valid_for zero",
                Box::new(|r: &mut LoginRequest| r.valid_for = 0),
            ),
        ];
        for (name, break_it) in cases {
            let mut r = valid_request();
            break_it(&mut r);
            assert!(
                validate_login_request(&r, "8f3c").is_err(),
                "accepted {name}"
            );
        }
    }

    // A scope entry is printed verbatim to a terminal. An escape sequence there can erase
    // or repaint the statement the person is about to approve.
    #[test]
    fn refuses_control_characters_in_scope() {
        for bad in [
            "read:\u{1b}[2Jprojects",
            "read:\nprojects",
            "read:\rprojects",
            "read:\u{0}p",
            "read:\u{7f}p",
        ] {
            let mut r = valid_request();
            r.scope = vec![bad.to_string()];
            assert!(
                validate_login_request(&r, "8f3c").is_err(),
                "accepted {bad:?}"
            );
        }
    }

    // The statement is the contract with the person AND the cross-lane pin.
    #[test]
    fn renders_the_statement() {
        // 2026-09-10T10:04:00Z
        let now = 1_789_034_640;
        let got = render_statement(
            "https://prover.core.example.dev/api",
            &valid_request(),
            now,
            "the seed file /keys/julia",
        );
        let want = format!(
            "https://prover.core.example.dev/api asks you to let browser key {BROWSER} act as you:\n  \
read:projects\n  read:campaigns\nfor 8h0m0s, until 2026-09-10T18:04:00Z\n\
signing with the seed file /keys/julia\n"
        );
        assert_eq!(got, want);
    }

    // An empty scope is VALID (docs/login.md §3.1) and must still say so on screen.
    #[test]
    fn renders_an_empty_scope() {
        let mut r = valid_request();
        r.scope.clear();
        let got = render_statement(
            "https://h.example",
            &r,
            0,
            "the seed given on the command line",
        );
        assert!(
            got.contains(NO_SCOPE_LINE),
            "an empty scope must be stated, not shown as a blank: {got:?}"
        );
    }

    // Default ports are omitted (docs/login.md §2): the server binds its configured
    // audience, which has no :443 in it, so keeping the port binds a different string.
    #[test]
    fn omits_default_ports_and_keeps_others() {
        for (url, audience) in [
            (
                "https://h.example:443/api/login/8f3c",
                "https://h.example/api",
            ),
            ("http://h.example:80/api/login/8f3c", "http://h.example/api"),
            (
                "https://h.example:8443/login/8f3c",
                "https://h.example:8443",
            ),
            (
                "http://localhost:8080/api/login/8f3c",
                "http://localhost:8080/api",
            ),
            ("http://[::1]:8080/login/8f3c", "http://[::1]:8080"),
            ("https://[::1]:443/login/8f3c", "https://[::1]"),
            ("wss://h.example:443/login/8f3c", "https://h.example"),
        ] {
            let (got, _) = login::derive_audience(url).expect(url);
            assert_eq!(got, audience, "audience for {url}");
        }
    }

    #[test]
    fn formats_durations() {
        for (seconds, want) in [
            (28_800u32, "8h0m0s"),
            (3_600, "1h0m0s"),
            (3_661, "1h1m1s"),
            (300, "5m0s"),
            (90, "1m30s"),
            (45, "45s"),
            (1, "1s"),
        ] {
            assert_eq!(format_duration(seconds), want, "{seconds}s");
        }
    }

    // Pinned against known instants: this is hand-rolled date arithmetic, so it is checked
    // at a leap day and a year boundary rather than only in the happy middle.
    #[test]
    fn formats_timestamps() {
        for (unix, want) in [
            (0i64, "1970-01-01T00:00:00Z"),
            (1_789_063_440, "2026-09-10T18:04:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
        ] {
            assert_eq!(format_rfc3339_utc(unix), want, "unix {unix}");
        }
    }

    // Default-no is the whole point of a confirmation prompt: a login must never complete
    // because stdin happened to be closed or held something unexpected.
    #[test]
    fn confirm_defaults_to_no() {
        for (input, want) in [
            ("y\n", true),
            ("Y\n", true),
            ("yes\n", true),
            ("YES\n", true),
            (" y \n", true),
            ("n\n", false),
            ("\n", false),
            ("", false),
            ("maybe\n", false),
            ("yolo\n", false),
        ] {
            let mut cursor = std::io::Cursor::new(input.as_bytes().to_vec());
            assert_eq!(confirm(&mut cursor).unwrap(), want, "input {input:?}");
        }
    }

    #[test]
    fn reads_both_seed_file_shapes() {
        let seed = "11".repeat(32);
        assert!(seed_from_hex_file(&format!("{seed}\n")).is_ok());
        let private = format!("{seed}{}", "22".repeat(32));
        let got = seed_from_hex_file(&private).expect("64-byte private key");
        assert_eq!(got[0], 0x11, "took the wrong half of the private key");
        for bad in ["", "zz", &"11".repeat(31)] {
            assert!(seed_from_hex_file(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn surfaces_rfc8628_errors() {
        assert!(login_http_error(400, r#"{"error":"expired_token"}"#).contains("expired"));
        assert!(login_http_error(403, r#"{"error":"access_denied"}"#).contains("refused"));
        assert!(login_http_error(500, "not json").contains("500"));
    }

    // The seam is wired (sdk/rs/login, archon#19). The proof must VERIFY under the
    // scheme's own verifier: this lane converts wire values to scheme values, and a
    // conversion bug is exactly what would otherwise pass as a plausible signature.
    #[test]
    fn the_proof_verifies_under_the_scheme() {
        let mut seed = [0u8; SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let audience = "https://prover.core.example.dev/api";
        let r = valid_request();

        let (proof, principal) = prove_login(&seed, audience, &r).expect("prove_login");
        assert!(principal.starts_with("ed25519:"), "principal {principal}");

        let req = login::Request {
            id: from_hex(&r.id).unwrap(),
            nonce: from_hex(&r.nonce).unwrap(),
            browser: decode_key(&r.browser).unwrap(),
            scope: r.scope.clone(),
            valid_for: r.valid_for,
        };
        let pubkey = public_key_from_seed(&seed);
        assert!(
            login::verify(&pubkey, audience, &req, &proof),
            "the scheme does not verify the proof this lane produced"
        );
        // And it must be bound to THIS audience: a proof that verifies elsewhere is the
        // whole hazard the derived-audience rule exists to prevent.
        assert!(
            !login::verify(&pubkey, "https://evil.example", &req, &proof),
            "the proof verified against a different audience"
        );

        // THE ID IS BOUND AS DECODED BYTES, NOT AS THE ASCII OF ITS HEX TEXT. This assertion
        // exists because the lane got it wrong and the earlier stub test did not notice: it
        // built its expected Request the same wrong way, so both sides agreed with each
        // other and neither agreed with the server.
        let ascii = login::Request {
            id: r.id.as_bytes().to_vec(),
            ..login::Request {
                id: Vec::new(),
                nonce: from_hex(&r.nonce).unwrap(),
                browser: decode_key(&r.browser).unwrap(),
                scope: r.scope.clone(),
                valid_for: r.valid_for,
            }
        };
        assert!(
            !login::verify(&pubkey, audience, &ascii, &proof),
            "the proof verified against an id bound as ASCII hex text; it must be DECODED bytes"
        );
    }
    // The whole flow against a stub service, which is the case seat:cca asked each lane to
    // carry in its unit tests. (The smoke run was pre-network until the store's consumer
    // needed a server; it now hosts one itself — see cli/smoke.mjs — and verifies against
    // the oracle's key, never a lane's.) It exercises the join the tests above each cover
    // only half of: what the service sends, through validation and conversion, into a proof
    // the SCHEME accepts.
    //
    // The stub is a bare TcpListener rather than a test-server crate: this lane is
    // deliberately dependency-light, and adding a dev-dependency to test two HTTP calls
    // would cost more than the twenty lines it saves.
    #[test]
    fn end_to_end_against_a_stub_service() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let body = format!(
            r#"{{"id":"8f3c","nonce":"{}","browser":"{BROWSER}","scope":["read:projects","read:campaigns"],"valid_for":28800,"expires":""}}"#,
            "ab".repeat(16)
        );

        // Two requests: the GET that hands us the request, then the POST that delivers the
        // answer. Served on a thread so the main thread can drive the flow.
        let server = std::thread::spawn(move || {
            let mut paths = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                paths.push(head.lines().next().unwrap_or_default().to_string());
                let response = if head.starts_with("GET") {
                    format!(
                        "HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: {}
Connection: close

{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 204 No Content
Connection: close

"
                    .to_string()
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            paths
        });

        let (audience, id_bytes) =
            login::derive_audience(&format!("http://127.0.0.1:{port}/api/login/8f3c"))
                .expect("derive");
        let id = to_hex(&id_bytes);
        assert_eq!(
            audience,
            format!("http://127.0.0.1:{port}/api"),
            "the audience must come from the URL, not the wire"
        );

        let request = fetch_login_request(&audience, &id).expect("fetch");
        validate_login_request(&request, &id).expect("validate");

        let mut seed = [0u8; SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 7) as u8;
        }
        let (proof, principal) = prove_login(&seed, &audience, &request).expect("prove");
        post_login_answer(
            &audience,
            &id,
            &LoginAnswer {
                principal,
                possession: to_hex(&proof),
                authority: String::new(),
            },
        )
        .expect("post");

        let paths = server.join().expect("server thread");
        assert!(
            paths[0].starts_with("GET /api/login/8f3c"),
            "GET was {:?}",
            paths[0]
        );
        assert!(
            paths[1].starts_with("POST /api/login/8f3c/answer"),
            "POST was {:?}",
            paths[1]
        );

        // The proof must verify for THIS audience and no other.
        let req = login::Request {
            id: from_hex(&request.id).unwrap(),
            nonce: from_hex(&request.nonce).unwrap(),
            browser: decode_key(&request.browser).unwrap(),
            scope: request.scope.clone(),
            valid_for: request.valid_for,
        };
        let pubkey = public_key_from_seed(&seed);
        assert!(
            login::verify(&pubkey, &audience, &req, &proof),
            "scheme rejected the full-flow proof"
        );
        assert!(
            !login::verify(&pubkey, "https://evil.example", &req, &proof),
            "proof not bound to its audience"
        );
    }
    // THE CROSS-LANE STATEMENT FIXTURE. This is where the three lanes are held together:
    // all three suites read the SAME file and assert their renderer reproduces it byte for
    // byte. (cli/smoke.mjs pins one rendered statement too, from the store-key login it runs
    // against the server it hosts; this fixture is what pins every OTHER source line, with
    // no network.)
    #[test]
    fn statement_matches_the_shared_fixture() {
        let raw = std::fs::read_to_string("../testdata/login-statement.json")
            .expect("could not read the shared fixture");
        let doc: serde_json::Value =
            serde_json::from_str(&raw).expect("the shared fixture is not the expected JSON");
        let cases = doc["cases"].as_array().expect("cases");
        assert!(
            !cases.is_empty(),
            "the shared fixture holds no cases — a fixture nobody can fail is not a pin"
        );
        for case in cases {
            let req = &case["request"];
            let r = LoginRequest {
                id: req["id"].as_str().unwrap().to_string(),
                nonce: req["nonce"].as_str().unwrap().to_string(),
                browser: req["browser"].as_str().unwrap().to_string(),
                scope: req["scope"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect(),
                valid_for: req["valid_for"].as_u64().unwrap() as u32,
                expires: String::new(),
            };
            let got = render_statement(
                case["audience"].as_str().unwrap(),
                &r,
                case["nowUnix"].as_i64().unwrap(),
                case["keySource"].as_str().unwrap(),
            );
            assert_eq!(
                got,
                case["statement"].as_str().unwrap(),
                "statement differs from the shared fixture for case {:?}",
                case["name"].as_str().unwrap()
            );
        }
    }

    // The fixture pins describe_key_source's OUTPUT for whichever source a case names; this
    // pins the branch selection itself — and that a store key is named by its NAME, never a
    // principal, whether --key chose it or the default pointer did.
    #[test]
    fn describes_the_key_source() {
        let store = LoginSource {
            store_key: Some("julia".into()),
            ..Default::default()
        };
        assert_eq!(describe_key_source(&store), "the store key julia");
        let seed_file = LoginSource {
            seed_file: Some("/keys/julia".into()),
            ..Default::default()
        };
        assert_eq!(describe_key_source(&seed_file), "the seed file /keys/julia");
        let key_file = LoginSource {
            key_file: Some("k.pem".into()),
            ..Default::default()
        };
        assert_eq!(describe_key_source(&key_file), "the key file k.pem");
        let seed_hex = LoginSource {
            seed_hex: Some("ab".into()),
            ..Default::default()
        };
        assert_eq!(
            describe_key_source(&seed_hex),
            "the seed given on the command line"
        );
        assert_eq!(
            describe_key_source(&LoginSource::default()),
            "an unspecified key"
        );
    }

    // Reads one HTTP/1.1 request off a stream: the head to the blank line, then as many body
    // bytes as Content-Length declares. The e2e stub below serves a POST whose body is the
    // answer, and a single read is not guaranteed to hold all of it.
    fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                let want = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if buf.len() >= end + 4 + want {
                    break;
                }
            }
        }
        buf
    }

    // THE STORE'S CONSUMER, end to end: a key SEALED into a temp store, the real `run`
    // driven with --key and --yes against a stub service that verifies the proof with the
    // scheme against the sealed seed's own public key. This is the row of ADR 0007 §A's
    // table that was "not yet true" until this test could pass.
    //
    // ONE test with its scenarios in sequence: they share ARCHON_HOME and
    // ARCHON_KEY_PASSWORD, which are process-global, and cargo runs separate tests in
    // parallel. The offers e2e below owns the same variables, so both hold ENV_LOCK for their
    // whole duration and run one after the other; nothing else in this crate reads them.
    //
    // The stub records every request BEFORE it answers, and each scenario says how many it
    // expects, because WHERE a refusal lands is the point: a bad name and a missing default
    // are refused before any request; a wrong password after the GET but before any POST —
    // the unlock comes after show-and-confirm, and a failed unlock never posts. libtest
    // captures stdout with no read-back, so the statement is not asserted here (the fixture
    // and describes_the_key_source pin it); the posted principal and the verified proof are.
    #[test]
    fn logs_in_from_a_sealed_store_key() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::sync::{Arc, Mutex};

        let home = std::env::temp_dir().join(format!("archon-login-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        const PASSWORD: &str = "a password with a space";
        std::env::set_var("ARCHON_HOME", &home);
        std::env::set_var("ARCHON_KEY_PASSWORD", PASSWORD);

        let mut seed = [0u8; SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 9) as u8;
        }
        let pubkey = public_key_from_seed(&seed);
        let principal = encode_key(&pubkey);
        crate::cmd::key_store::seal_and_write(
            &home.join("keys").join("julia"),
            &seed,
            PASSWORD.as_bytes(),
        )
        .expect("seal");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let audience = format!("http://127.0.0.1:{}/api", addr.port());
        let url = format!("{audience}/login/8f3c");
        let body = format!(
            r#"{{"id":"8f3c","nonce":"{}","browser":"{BROWSER}","scope":["read:projects","read:campaigns"],"valid_for":28800,"expires":""}}"#,
            "ab".repeat(16)
        );
        // (method, proof verified) per request, pushed BEFORE the response is written so a
        // count taken after `run` returns is complete.
        let seen: Arc<Mutex<Vec<(String, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let server = {
            let seen = seen.clone();
            let listener = listener.try_clone().expect("clone");
            let (audience, body, principal) = (audience.clone(), body.clone(), principal.clone());
            std::thread::spawn(move || loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let raw = read_http_request(&mut stream);
                let text = String::from_utf8_lossy(&raw).to_string();
                // The test's own stop signal, sent once the scenarios are done. A request
                // rather than a switch to non-blocking mode: the listener here is a
                // duplicated handle, and whether non-blocking mode is shared across a
                // duplicate is exactly the kind of thing that differs by platform — it did
                // not reach a blocked accept on Windows, and the test hung on join.
                if text.starts_with("STOP") {
                    return;
                }
                let (method, verified, response) = if text.starts_with("GET") {
                    (
                        "GET",
                        false,
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        ),
                    )
                } else {
                    let json = text.split("\r\n\r\n").nth(1).unwrap_or("");
                    let answer: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
                    let proof =
                        from_hex(answer["possession"].as_str().unwrap_or("")).unwrap_or_default();
                    let req = login::Request {
                        id: vec![0x8f, 0x3c],
                        nonce: from_hex(&"ab".repeat(16)).unwrap(),
                        browser: decode_key(BROWSER).unwrap(),
                        scope: vec!["read:projects".into(), "read:campaigns".into()],
                        valid_for: 28_800,
                    };
                    let ok = answer["principal"].as_str() == Some(principal.as_str())
                        && login::verify(&pubkey, &audience, &req, &proof);
                    (
                        "POST",
                        ok,
                        "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string(),
                    )
                };
                seen.lock().unwrap().push((method.to_string(), verified));
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            })
        };
        let args = |a: &[&str]| -> Vec<String> { a.iter().map(|s| s.to_string()).collect() };
        let requests = || seen.lock().unwrap().clone();

        // --key unlocks the sealed key and the proof verifies.
        run(&args(&[&url, "--key", "julia", "--yes"])).expect("login --key");
        assert_eq!(
            requests(),
            vec![("GET".to_string(), false), ("POST".to_string(), true)],
            "the service must have verified a proof for the sealed key's principal"
        );

        // No source flag falls back to the store's default.
        let pointer = home.join("default");
        std::fs::write(&pointer, "julia\n").unwrap();
        run(&args(&[&url, "--yes"])).expect("login with the default key");
        std::fs::remove_file(&pointer).unwrap();
        assert_eq!(requests().len(), 4);
        assert!(
            requests()[3].1,
            "the default key did not produce a verified proof"
        );

        // No source flag and no default: refused before any request, in the store's wording.
        let err = run(&args(&[&url, "--yes"])).expect_err("no default");
        assert!(err.contains("no default key is set"), "{err}");
        assert_eq!(requests().len(), 4);

        // A name not in the store: refused before any request, in the store's wording.
        let err = run(&args(&[&url, "--key", "nobody", "--yes"])).expect_err("unknown key");
        assert!(
            err.contains("no key named \"nobody\" in archon's store"),
            "{err}"
        );
        assert_eq!(requests().len(), 4);

        // A wrong password: refused after the statement and before any answer.
        std::env::set_var("ARCHON_KEY_PASSWORD", "not the password");
        let err = run(&args(&[&url, "--key", "julia", "--yes"])).expect_err("wrong password");
        std::env::set_var("ARCHON_KEY_PASSWORD", PASSWORD);
        assert!(err.contains("wrong password"), "{err}");
        assert_eq!(requests().len(), 5, "the GET happened, nothing was posted");
        assert_eq!(requests()[4].0, "GET");

        // Two sources: refused before any request.
        let err = run(&args(&[
            &url,
            "--key",
            "julia",
            "--seed",
            &"11".repeat(32),
            "--yes",
        ]))
        .expect_err("two sources");
        assert!(err.contains("mutually exclusive"), "{err}");
        assert_eq!(requests().len(), 5);

        // --password-fd beside a seed file is refused.
        let err = run(&args(&[
            &url,
            "--seed",
            &"11".repeat(32),
            "--password-fd",
            "3",
            "--yes",
        ]))
        .expect_err("fd beside a seed");
        assert!(err.contains("applies only to a store key"), "{err}");
        assert_eq!(requests().len(), 5);

        // --password-fd 0 without --yes is refused.
        let err = run(&args(&[&url, "--key", "julia", "--password-fd", "0"])).expect_err("fd 0");
        assert!(err.contains("pass --yes"), "{err}");
        assert_eq!(requests().len(), 5);

        // A missing authority file: refused before any request. It used to be refused AFTER
        // the person had read the statement and said yes — a refusal belongs before the
        // question.
        let missing = home.join("no-such-file");
        let err = run(&args(&[
            &url,
            "--key",
            "julia",
            "--authority-file",
            missing.to_str().unwrap(),
            "--yes",
        ]))
        .expect_err("missing authority file");
        assert!(err.contains("could not read"), "{err}");
        assert_eq!(requests().len(), 5);

        // Stop the stub with its own signal, then join it.
        {
            let mut stop = TcpStream::connect(addr).expect("connect to stop the stub");
            let _ = stop.write_all(b"STOP\r\n\r\n");
            let _ = stop.flush();
        }
        server.join().expect("stub thread");
        std::env::remove_var("ARCHON_KEY_PASSWORD");
        std::env::remove_var("ARCHON_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    // ---- THE OFFERS FORM (docs/login.md §4.1) --------------------------------------------

    // THE LEDGER FIXTURE (§4.1 rule 4): the offers form prints, AFTER answering, the same
    // fields the confirmed form shows before signing, and all three lanes must print the
    // ledger byte-identically too. Same shared file, second section.
    #[test]
    fn renders_the_ledger_from_the_shared_fixture() {
        let raw = std::fs::read_to_string("../testdata/login-statement.json")
            .expect("could not read the shared fixture");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture is not JSON");
        let cases = doc["offer_cases"].as_array().expect("offer_cases");
        assert!(
            !cases.is_empty(),
            "the shared fixture holds no offer_cases — a fixture nobody can fail is not a pin"
        );
        for case in cases {
            let req = &case["request"];
            let r = LoginRequest {
                id: req["id"].as_str().unwrap().to_string(),
                nonce: req["nonce"].as_str().unwrap().to_string(),
                browser: req["browser"].as_str().unwrap().to_string(),
                scope: req["scope"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect(),
                valid_for: req["valid_for"].as_u64().unwrap() as u32,
                expires: String::new(),
            };
            let verdict = case["verdict"].as_str().unwrap();
            let refused = verdict.strip_prefix("refused:");
            assert!(
                verdict == "accepted" || refused.is_some(),
                "verdict {verdict:?}"
            );
            let got = render_ledger(
                case["audience"].as_str().unwrap(),
                &r,
                case["nowUnix"].as_i64().unwrap(),
                case["keySource"].as_str().unwrap(),
                refused,
            );
            assert_eq!(
                got,
                case["ledger"].as_str().unwrap(),
                "ledger differs from the shared fixture for case {:?}",
                case["name"].as_str().unwrap()
            );
        }
    }

    // The page address is PRINTED AND MARKED, never opened (§4.1 rule 1; ADR 0007 §C.7 (6)):
    // "on the service's own origin" is a byte-exact comparison of scheme and host with the
    // audience's, so a differently spelled origin fails closed.
    #[test]
    fn describes_the_page_by_origin() {
        const AUD: &str = "https://dawn.example/api";
        const ON: &str = " (on the service's own origin)";
        const OFF: &str = " (NOT on the service's origin — do not open it)";
        for (page, mark) in [
            ("https://dawn.example/login", ON),
            ("https://dawn.example/login#abc", ON),
            ("https://dawn.example", ON),
            ("https://dawn.example.evil/login", OFF),
            ("https://evil.example/login", OFF),
            ("HTTPS://dawn.example/login", OFF),
            ("http://dawn.example/login", OFF),
            ("/login", OFF),
        ] {
            assert_eq!(
                describe_page(AUD, page),
                format!("page: {page}{mark}"),
                "{page}"
            );
        }
        // The port is part of the origin.
        assert!(
            describe_page("http://127.0.0.1:8080/api", "http://127.0.0.1:8080/login").ends_with(ON)
        );
        assert!(
            describe_page("http://127.0.0.1:8080/api", "http://127.0.0.1:8081/login")
                .ends_with(OFF)
        );
    }

    // §4.1 rule 1, the flag half: a fixed point of §2.1's grammar, refused otherwise naming
    // the spelling the service would bind. (The ARCHON_AUDIENCE half lives in the sequential
    // e2e test below, which owns the environment.)
    #[test]
    fn configures_the_audience() {
        assert_eq!(
            configured_audience(Some("http://localhost:8080")).unwrap(),
            "http://localhost:8080"
        );
        for bad in [
            "https://Dawn.example/api",     // host case
            "https://dawn.example/api/",    // a trailing slash — an empty segment
            "https://dawn.example:443/api", // a default port
            "wss://dawn.example/api",       // a scheme the grammar folds
            "not an audience",
        ] {
            assert!(configured_audience(Some(bad)).is_err(), "accepted {bad:?}");
        }
        let err = configured_audience(Some("https://Dawn.example/api")).unwrap_err();
        assert!(
            err.contains("\"https://dawn.example/api\""),
            "the refusal must name the derived spelling: {err}"
        );
    }

    /// How the stub alters the request the CLI reads, to prove rule 2 — the prover's own
    /// re-check — fires on every shape of "differs".
    #[derive(Clone, Copy)]
    enum Alter {
        ChangedEntry,
        Reordered,
        Extra,
        Dropped,
        Validity,
    }

    /// The offers stub's script and log, shared with the serving thread.
    #[derive(Default)]
    struct OfferStub {
        offers: std::collections::HashMap<String, (Vec<String>, u32)>,
        requests: Vec<String>,
        polls: usize,
        poll_plan: Vec<u16>,
        taken_at: usize,
        interval: u64,
        expires_in: u64,
        page: Option<String>,
        echo_valid_for_delta: u32,
        alter: Option<Alter>,
        refuse: Option<String>,
        posted: Option<serde_json::Value>,
        verified: bool,
    }

    impl OfferStub {
        fn reset(&mut self) {
            *self = OfferStub {
                taken_at: 2,
                interval: 2,
                expires_in: 300,
                ..OfferStub::default()
            };
        }
        fn the_code(&self) -> String {
            assert_eq!(self.offers.len(), 1, "exactly one offer must be registered");
            self.offers.keys().next().unwrap().clone()
        }
    }

    // THE OFFERS FORM, end to end, from a sealed store key: the real `run_offer` with no URL
    // against a stub playing the SERVICE's four routes, scripted per scenario, the answer
    // verified with the scheme against the sealed key's own public key. The clock is pinned
    // so the ledger is byte-exact, and the sleeps are RECORDED rather than slept, because the
    // pacing is the prover's own (ADR 0007 §C.7, #39) and therefore this lane's to pin: one
    // interval before the first poll, one between polls.
    //
    // ONE test with its scenarios in sequence: they share ARCHON_HOME, ARCHON_KEY_PASSWORD and
    // ARCHON_AUDIENCE, which are process-global (see `logs_in_from_a_sealed_store_key`). The
    // injected `LoginIo` is what lets this lane pin stdout and stderr at all — libtest cannot
    // read its own captured output.
    #[test]
    fn offers_from_a_sealed_store_key() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use std::cell::RefCell;
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::sync::{Arc, Mutex};

        const ID: &str = "8f3c";
        let home = std::env::temp_dir().join(format!("archon-login-offer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        const PASSWORD: &str = "a password with a space";
        std::env::set_var("ARCHON_HOME", &home);
        std::env::set_var("ARCHON_KEY_PASSWORD", PASSWORD);
        std::env::remove_var("ARCHON_AUDIENCE");

        let mut seed = [0u8; SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 9) as u8;
        }
        let pubkey = public_key_from_seed(&seed);
        let principal = encode_key(&pubkey);
        crate::cmd::key_store::seal_and_write(
            &home.join("keys").join("julia"),
            &seed,
            PASSWORD.as_bytes(),
        )
        .expect("seal");
        let mut browser_seed = [0u8; SEED_SIZE];
        for (i, b) in browser_seed.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        let k_text = encode_key(&public_key_from_seed(&browser_seed));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let audience = format!("http://127.0.0.1:{}/api", addr.port());
        let origin = format!("http://127.0.0.1:{}", addr.port());
        let stub: Arc<Mutex<OfferStub>> = Arc::new(Mutex::new(OfferStub::default()));
        let server = {
            let stub = stub.clone();
            let listener = listener.try_clone().expect("clone");
            let (audience, k_text, principal) =
                (audience.clone(), k_text.clone(), principal.clone());
            std::thread::spawn(move || loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let raw = read_http_request(&mut stream);
                let text = String::from_utf8_lossy(&raw).to_string();
                if text.starts_with("STOP") {
                    return;
                }
                let mut words = text.split_whitespace();
                let method = words.next().unwrap_or("").to_string();
                let path = words.next().unwrap_or("").to_string();
                let json = text.split("\r\n\r\n").nth(1).unwrap_or("");
                let (status, body) = {
                    let mut s = stub.lock().unwrap();
                    s.requests.push(format!("{method} {path}"));
                    if method == "POST" && path == "/api/login/offers" {
                        let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
                        let code = v["code"].as_str().unwrap_or("").to_string();
                        let scope: Vec<String> = v["scope"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .map(|x| x.as_str().unwrap_or("").to_string())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let valid_for = v["valid_for"].as_u64().unwrap_or(0) as u32;
                        s.offers.insert(code.clone(), (scope.clone(), valid_for));
                        let mut resp = serde_json::json!({
                            "code": code, "scope": scope, "valid_for": valid_for + s.echo_valid_for_delta,
                            "expires_in": s.expires_in, "interval": s.interval,
                        });
                        if let Some(page) = &s.page {
                            resp["page"] = serde_json::json!(format!("{page}#{code}"));
                        }
                        (201u16, resp.to_string())
                    } else if method == "GET" && path.starts_with("/api/login/offers/") {
                        let code = path.trim_start_matches("/api/login/offers/").to_string();
                        s.polls += 1;
                        let scripted = s.poll_plan.get(s.polls - 1).copied().unwrap_or(0);
                        if scripted != 0 {
                            let err = if scripted == 429 {
                                "slow_down"
                            } else {
                                "expired_token"
                            };
                            (scripted, serde_json::json!({"error": err}).to_string())
                        } else {
                            match s.offers.get(&code).cloned() {
                                None => (
                                    404,
                                    serde_json::json!({"error": "expired_token"}).to_string(),
                                ),
                                Some((scope, valid_for)) => {
                                    let request = if s.taken_at > 0 && s.polls >= s.taken_at {
                                        serde_json::json!(ID)
                                    } else {
                                        serde_json::Value::Null
                                    };
                                    (
                                        200,
                                        serde_json::json!({
                                            "code": code, "scope": scope, "valid_for": valid_for,
                                            "request": request, "expires": "2026-09-10T10:09:00Z",
                                        })
                                        .to_string(),
                                    )
                                }
                            }
                        }
                    } else if method == "GET" && path == format!("/api/login/{ID}") {
                        let (mut scope, mut valid_for) =
                            s.offers.values().next().cloned().unwrap_or_default();
                        match s.alter {
                            Some(Alter::ChangedEntry) => scope[1] = "read:campaign".to_string(),
                            Some(Alter::Reordered) => scope.reverse(),
                            Some(Alter::Extra) => scope.push("write:projects".to_string()),
                            Some(Alter::Dropped) => {
                                scope.pop();
                            }
                            Some(Alter::Validity) => valid_for += 1,
                            None => {}
                        }
                        (200, serde_json::json!({
                            "id": ID, "nonce": "ab".repeat(16), "browser": k_text, "scope": scope,
                            "valid_for": valid_for, "expires": "",
                        }).to_string())
                    } else if method == "POST" && path == format!("/api/login/{ID}/answer") {
                        let answer: serde_json::Value =
                            serde_json::from_str(json).unwrap_or_default();
                        s.posted = Some(answer.clone());
                        let (scope, valid_for) =
                            s.offers.values().next().cloned().unwrap_or_default();
                        let req = login::Request {
                            id: from_hex(ID).unwrap(),
                            nonce: from_hex(&"ab".repeat(16)).unwrap(),
                            browser: decode_key(&k_text).unwrap(),
                            scope,
                            valid_for,
                        };
                        let proof = from_hex(answer["possession"].as_str().unwrap_or(""))
                            .unwrap_or_default();
                        s.verified = answer["principal"].as_str() == Some(principal.as_str())
                            && login::verify(&pubkey, &audience, &req, &proof);
                        match &s.refuse {
                            Some(code) => (403, serde_json::json!({"error": code}).to_string()),
                            None => (204, String::new()),
                        }
                    } else {
                        (
                            404,
                            serde_json::json!({"error": "expired_token"}).to_string(),
                        )
                    }
                };
                let response = if status == 204 {
                    "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            })
        };

        // One run of the form against a freshly scripted stub, with everything it wrote and
        // every sleep it asked for handed back.
        let go = |args: &[&str], script: &dyn Fn(&mut OfferStub)| {
            {
                let mut s = stub.lock().unwrap();
                s.reset();
                script(&mut s);
            }
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            let mut out: Vec<u8> = Vec::new();
            let mut err_out: Vec<u8> = Vec::new();
            let sleeps: RefCell<Vec<u64>> = RefCell::new(Vec::new());
            let sleep = |secs: u64| sleeps.borrow_mut().push(secs);
            let now = || 1_789_034_640i64; // 2026-09-10T10:04:00Z, so the ledger is byte-exact
            let result = {
                let mut io = LoginIo {
                    out: &mut out,
                    err: &mut err_out,
                    sleep: &sleep,
                    now: &now,
                };
                run_offer(&args, &mut io)
            };
            (
                result,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err_out).unwrap(),
                sleeps.into_inner(),
            )
        };
        let snapshot = || {
            let s = stub.lock().unwrap();
            (
                s.requests.clone(),
                s.polls,
                s.posted.clone(),
                s.verified,
                s.the_code_if_any(),
            )
        };
        let base: Vec<&str> = vec![
            "--audience",
            &audience,
            "--scope",
            "read:projects",
            "--scope",
            "read:campaigns",
            "--valid-for",
            "28800",
            "--key",
            "julia",
        ];
        let ledger = |verdict: &str| {
            format!(
                "you offered {audience} to let browser key {k_text} act as you:\n  read:projects\n  read:campaigns\nfor 8h0m0s, until 2026-09-10T18:04:00Z\nsigned with the store key julia\n{verdict}"
            )
        };

        // Offers, waits for the page, answers only the request that took the offer.
        let (r, out, err, sleeps) = go(&base, &|s| s.page = Some(format!("{origin}/login")));
        r.expect("the happy path");
        let (requests, _, posted, verified, code) = snapshot();
        let code = code.expect("one offer");
        assert_eq!(code.len(), 2 * CODE_BYTES, "the code has 32 hex characters");
        assert_eq!(
            out,
            ledger("the service accepted the login. the browser is in.\n")
        );
        assert!(
            !out.contains(&code),
            "the code was printed on stdout — stdout may be a log"
        );
        for want in [
            format!("offer registered at {audience}\n"),
            format!("code: {code}\n"),
            format!("page: {origin}/login#{code} (on the service's own origin)\n"),
            "waiting for the page to take the offer, up to 300s\n".to_string(),
        ] {
            assert!(err.contains(&want), "stderr lacks {want:?}:\n{err}");
        }
        assert_eq!(
            sleeps,
            vec![2, 2],
            "one interval before each of the two polls"
        );
        assert_eq!(
            requests,
            vec![
                "POST /api/login/offers".to_string(),
                format!("GET /api/login/offers/{code}"),
                format!("GET /api/login/offers/{code}"),
                format!("GET /api/login/{ID}"),
                format!("POST /api/login/{ID}/answer"),
            ]
        );
        assert!(
            verified,
            "the service did not verify a proof for the sealed key's principal"
        );
        assert_eq!(
            posted.unwrap()["principal"].as_str(),
            Some(principal.as_str())
        );

        // A request that differs from the offer is refused, and nothing is signed (rule 2).
        for (name, alter) in [
            ("a changed entry", Alter::ChangedEntry),
            ("a reordered entry", Alter::Reordered),
            ("an extra entry", Alter::Extra),
            ("a dropped entry", Alter::Dropped),
            ("a changed validity", Alter::Validity),
        ] {
            let (r, out, _, _) = go(&base, &|s| s.alter = Some(alter));
            let err = r.expect_err(name);
            assert!(err.contains("differs from the offer"), "{name}: {err}");
            assert!(out.is_empty(), "{name}: a refused login printed a ledger");
            assert!(snapshot().2.is_none(), "{name}: an answer was posted");
        }

        // --yes is refused before any request.
        let mut with_yes = base.clone();
        with_yes.push("--yes");
        let (r, _, _, _) = go(&with_yes, &|_| {});
        assert!(r.unwrap_err().contains("drop --yes"));
        assert!(snapshot().0.is_empty(), "requests were made");

        // No audience anywhere: refused before any request, naming both sources.
        let (r, _, _, _) = go(&base[2..], &|_| {});
        assert!(r.unwrap_err().contains("ARCHON_AUDIENCE"));
        assert!(snapshot().0.is_empty());

        // A non-canonical --audience is refused naming the derived spelling.
        let shouted = audience.to_uppercase();
        let mut args = vec!["--audience", shouted.as_str()];
        args.extend_from_slice(&base[2..]);
        let (r, _, _, _) = go(&args, &|_| {});
        assert!(r.unwrap_err().contains("not canonical"));
        let slashed = format!("{audience}/");
        let mut args = vec!["--audience", slashed.as_str()];
        args.extend_from_slice(&base[2..]);
        let (r, _, _, _) = go(&args, &|_| {});
        assert!(r.unwrap_err().contains("not valid"));
        assert!(snapshot().0.is_empty());

        // ARCHON_AUDIENCE is the configured default.
        std::env::set_var("ARCHON_AUDIENCE", &audience);
        let (r, out, _, _) = go(&base[2..], &|_| {});
        std::env::remove_var("ARCHON_AUDIENCE");
        r.expect("the environment's audience");
        assert!(out.starts_with(&format!("you offered {audience} ")) && snapshot().3);

        // A page not on the service's origin is marked, and nothing is opened.
        let (r, _, err, _) = go(&base, &|s| {
            s.page = Some("https://evil.example/login".to_string())
        });
        r.expect("off-origin page");
        let code = snapshot().4.unwrap();
        assert!(
            err.contains(&format!("page: https://evil.example/login#{code} (NOT on the service's origin — do not open it)\n")),
            "{err}"
        );

        // A refusal by the service is recorded in the ledger, and the command still fails.
        let (r, out, _, _) = go(&base, &|s| s.refuse = Some("invalid_grant".to_string()));
        assert!(r.unwrap_err().contains("refused the login (invalid_grant)"));
        assert_eq!(
            out,
            ledger("the service refused the login (invalid_grant). the browser is not in.\n")
        );

        // An offer the page never took.
        let (r, out, _, _) = go(&base, &|s| s.poll_plan = vec![404]);
        assert!(r.unwrap_err().contains("expired before the page took it"));
        assert!(out.is_empty() && snapshot().2.is_none());

        // A 429 is sleep-and-retry, never an error.
        let (r, _, _, sleeps) = go(&base, &|s| {
            s.poll_plan = vec![429];
            s.taken_at = 3;
        });
        r.expect("429 then taken");
        assert_eq!(
            (sleeps.len(), snapshot().1),
            (3, 3),
            "one sleep before each of three polls"
        );

        // An echo that differs from the offer is refused before any poll.
        let (r, _, _, _) = go(&base, &|s| s.echo_valid_for_delta = 1);
        assert!(r.unwrap_err().contains("altered the offer"));
        assert_eq!(snapshot().1, 0, "polls after an altered echo");

        // --valid-for is required, and is a whole positive number of seconds.
        let (r, _, _, _) = go(
            &[
                "--audience",
                &audience,
                "--scope",
                "read:projects",
                "--key",
                "julia",
            ],
            &|_| {},
        );
        assert!(r.unwrap_err().contains("required"));
        for bad in ["0", "-5", "8h", "1.5"] {
            let (r, _, _, _) = go(
                &[
                    "--audience",
                    &audience,
                    "--scope",
                    "read:projects",
                    "--valid-for",
                    bad,
                    "--key",
                    "julia",
                ],
                &|_| {},
            );
            assert!(r.is_err(), "accepted --valid-for {bad:?}");
        }
        assert!(snapshot().0.is_empty());

        // A scope entry that could lie on screen is refused before any request.
        let (r, _, _, _) = go(
            &[
                "--audience",
                &audience,
                "--scope",
                "read:\u{1b}[2Jx",
                "--valid-for",
                "60",
                "--key",
                "julia",
            ],
            &|_| {},
        );
        assert!(r.unwrap_err().contains("control character"));
        let (r, _, _, _) = go(
            &[
                "--audience",
                &audience,
                "--scope",
                "",
                "--valid-for",
                "60",
                "--key",
                "julia",
            ],
            &|_| {},
        );
        assert!(r.is_err(), "an empty --scope value was accepted");
        assert!(snapshot().0.is_empty());

        // Stop the stub with its own signal, then join it.
        {
            let mut stop = TcpStream::connect(addr).expect("connect to stop the stub");
            let _ = stop.write_all(b"STOP\r\n\r\n");
            let _ = stop.flush();
        }
        server.join().expect("stub thread");
        std::env::remove_var("ARCHON_KEY_PASSWORD");
        std::env::remove_var("ARCHON_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    impl OfferStub {
        fn the_code_if_any(&self) -> Option<String> {
            (self.offers.len() == 1).then(|| self.the_code())
        }
    }
}
