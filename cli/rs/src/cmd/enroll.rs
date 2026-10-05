//! `archon enroll` (`docs/enroll.md` §4, ADR 0013): make the enrollment proof for a key in the
//! store, but only after showing the person which account the key joins, decoded from the very
//! intent bytes whose digest the proof binds. The challenge arrives as a token the person
//! carries from the signed-in page; the proof leaves as a token they carry back. The command
//! contacts no server, so its success means a proof was produced, never that the key is
//! enrolled.

use std::fs;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};

use archon_core::crypto::public_key_from_seed;
use archon_core::keytext::encode_key;
use archon_sdk::enroll;

use crate::cmd::key_store::{read_default_key_name, read_password, take_password_fd, usable_key};
use crate::cmd::login::{format_rfc3339_utc, selected_audience};
use crate::io::{json_string, wants_help};
use crate::keystore::{self, Policy, MAX_CONTEXTS};

const USAGE: &str = "usage: archon enroll [--challenge-file <file>] [--audience <base>] [--key <name>] [--password-fd <n>]
  makes the enrollment proof for a key in the store, after showing which account it joins
  (docs/enroll.md). The challenge token is read from --challenge-file, or one line of stdin;
  the audience is --audience or ARCHON_AUDIENCE; the key is --key or the default key. The
  question is asked on the terminal, always, and the proof token is printed on stdout.";

/// Asks for the token when stdin is a terminal.
const PASTE_PROMPT: &str = "paste the challenge token, then press Enter: ";

/// The one purpose version 1 renders (`docs/enroll.md` §2).
const PURPOSE: &str = "add-key";

/// What is read before decoding: a token and its surrounding whitespace.
const MAX_INPUT: u64 = 1 << 20;

const NO_TERMINAL: &str = "enroll: there is no terminal to ask on; archon enroll asks every time, \
and a password from ARCHON_KEY_PASSWORD or --password-fd does not answer it";

pub fn run(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        println!("{USAGE}");
        return Ok(());
    }
    let (rest, pw_fd) = take_password_fd(args)?;
    let (mut challenge_file, mut audience_flag, mut key_name) = (None, None, None);
    let mut i = 0;
    while i < rest.len() {
        let flag = rest[i].as_str();
        let value = match rest.get(i + 1) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return Err(format!("flag {flag:?} needs a value\n{USAGE}")),
        };
        match flag {
            "--challenge-file" => challenge_file = Some(value),
            "--audience" => audience_flag = Some(value),
            "--key" => key_name = Some(value),
            _ => return Err(format!("unknown flag {flag:?}\n{USAGE}")),
        }
        i += 2;
    }
    if challenge_file.is_none() && pw_fd == Some(0) {
        return Err(
            "enroll: --password-fd 0 and a challenge token on stdin would read the same \
stream; pass the token with --challenge-file"
                .to_string(),
        );
    }

    // 1. The entry: one read, whose header the seal authenticates at unlock (ADR 0012 §4).
    let name = match key_name {
        Some(name) => name,
        None => read_default_key_name()?.ok_or_else(|| {
            "enroll: no default key is set; pass --key <name>, or choose one with: archon key default <name>"
                .to_string()
        })?,
    };
    let (file, header) = usable_key(&name)?;
    let permits = |p: &Option<Policy>| p.as_ref().is_some_and(|p| p.permits(enroll::DOMAIN));
    if !permits(&header.policy) {
        return Err(policy_refusal(&name, header.policy.as_ref()));
    }

    // 2. The audience the person selected, and a terminal to ask on.
    let audience = selected_audience(
        "enroll",
        "the audience is your configuration, never a token's word (docs/enroll.md §4)",
        audience_flag.as_deref(),
    )?;
    let (mut tty_in, mut tty_out) = open_terminal().map_err(|_| NO_TERMINAL.to_string())?;

    // 3. The token, read and decoded once. From here on only these values are used.
    let (text, from_terminal) = read_challenge(challenge_file.as_deref(), &mut tty_out)?;
    let ch = enroll::decode_challenge(&text).map_err(|e| {
        if from_terminal {
            format!("{e} (a terminal cuts a long pasted line; save the token to a file and pass --challenge-file)")
        } else {
            e
        }
    })?;

    // 4.–7. Everything decidable before the person is asked.
    check_challenge(&ch, &audience, &header.public_key, now_unix())?;
    let (req, intent) = ch.request()?;
    if intent.purpose != PURPOSE {
        return Err(format!(
            "enroll: the intent's purpose is {}; this archon renders only {PURPOSE:?}, so it signs nothing else",
            json_string(&intent.purpose)
        ));
    }

    // 8. Show, and ask on the terminal.
    let source = format!("the store key {name}");
    write!(
        tty_out,
        "{}{}",
        render_statement(&audience, &intent, &header.public_key, ch.deadline, &source),
        prompt(&intent)
    )
    .map_err(|e| format!("could not write to the terminal: {e}"))?;
    if !answered_yes(&mut tty_in) {
        // Non-zero, so a script never mistakes a refusal for a proof: stdout stays empty.
        let _ = writeln!(tty_out, "refused. nothing was signed.");
        return Err("enroll: refused. nothing was signed.".to_string());
    }

    // 9. Only now is the key unlocked: the same snapshot, its header now authenticated.
    let password = read_password(pw_fd, false, "")?;
    let seed = keystore::open(&file, &password)?;
    if !permits(&header.policy) {
        return Err(policy_refusal(&name, header.policy.as_ref()));
    }
    if public_key_from_seed(&seed) != header.public_key || ch.new_key != header.public_key {
        return Err(format!(
            "enroll: key {name} did not open to the key that was shown; nothing was signed"
        ));
    }

    // 10. The proof, over what was shown, checked before it is printed.
    let proof = enroll::prove(&seed, &audience, &req)?;
    if !enroll::verify(&audience, &req, &proof) {
        return Err("enroll: the proof did not verify; nothing was printed".to_string());
    }
    let token = enroll::encode_proof(&enroll::Proof {
        transaction: req.transaction.clone(),
        new_key: req.new_key.clone(),
        proof: proof.to_vec(),
    })?;

    // 11. The proof token on stdout, alone; the person is told what it is not.
    println!("{token}");
    let _ = writeln!(
        tty_out,
        "proof produced. paste it into the service's page: the key is enrolled only when the page completes."
    );
    Ok(())
}

/// Steps 4 to 6 of `docs/enroll.md` §4: the token's audience is the selected one, its key is the
/// entry's, and its deadline is still ahead. The token's audience is display-safe already (the
/// codec refuses otherwise), and is JSON-quoted to show where it ends.
pub fn check_challenge(
    ch: &enroll::Challenge,
    audience: &str,
    key: &[u8],
    now: i64,
) -> Result<(), String> {
    if ch.audience != audience {
        return Err(format!(
            "enroll: the token is for {}, not the audience you selected, {}; nothing was shown or signed",
            json_string(&ch.audience),
            json_string(audience)
        ));
    }
    if ch.new_key != key {
        return Err(format!(
            "enroll: the token enrolls {}, not this key, {}; nothing was shown or signed",
            encode_key(&ch.new_key),
            encode_key(key)
        ));
    }
    if now >= ch.deadline as i64 {
        return Err(format!(
            "enroll: the request's deadline, about {}, has passed; begin again on the service's page",
            format_rfc3339_utc(ch.deadline as i64)
        ));
    }
    Ok(())
}

/// The statement of `docs/enroll.md` §4, byte-identical in every lane
/// (`cli/testdata/enroll-statement.json`).
pub fn render_statement(
    audience: &str,
    intent: &enroll::Intent,
    key: &[u8],
    deadline: u64,
    key_source: &str,
) -> String {
    let mut out = format!("{audience} asks you to add a key to an account:\n");
    out += &format!("  account:      {}\n", intent.account_name);
    out += &format!("  account id:   {}\n", intent.account_id);
    out += &format!("  key:          {}\n", encode_key(key));
    if intent.restrictions.is_empty() {
        out += "  restrictions: none\n";
    } else {
        out += "  restrictions:\n";
        for r in &intent.restrictions {
            out += &format!("    {r}\n");
        }
    }
    out += "the service may give this key the account's authority.\n";
    out += &format!(
        "the request's deadline is about {}, the service's word; it is not the key's expiry.\n",
        format_rfc3339_utc(deadline as i64)
    );
    out += &format!("signing with {key_source}\n");
    out
}

/// The question, naming the account the person is agreeing to, in plain quotes.
pub fn prompt(intent: &enroll::Intent) -> String {
    format!(
        "add this key to the account \"{}\"? [y/N] ",
        intent.account_name
    )
}

/// One line from the terminal: `y` or `yes`, and nothing else, is consent.
fn answered_yes(input: &mut impl BufRead) -> bool {
    let mut line = String::new();
    if input.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

/// The controlling terminal: `/dev/tty`, or the Windows console.
fn open_terminal() -> std::io::Result<(BufReader<fs::File>, fs::File)> {
    let (input, output) = if cfg!(windows) {
        ("CONIN$", "CONOUT$")
    } else {
        ("/dev/tty", "/dev/tty")
    };
    let out = fs::OpenOptions::new().write(true).open(output)?;
    let inp = fs::File::open(input)?;
    Ok((BufReader::new(inp), out))
}

/// The token: the whole file, or one line of stdin, asked for on the terminal when stdin is one;
/// and whether stdin was a terminal, whose line limit can cut a pasted token.
fn read_challenge(path: Option<&str>, tty_out: &mut fs::File) -> Result<(String, bool), String> {
    if let Some(path) = path {
        let f =
            fs::File::open(path).map_err(|e| format!("enroll: could not read {path:?}: {e}"))?;
        let mut raw = Vec::new();
        f.take(MAX_INPUT + 1)
            .read_to_end(&mut raw)
            .map_err(|e| format!("enroll: could not read {path:?}: {e}"))?;
        if raw.len() as u64 > MAX_INPUT {
            return Err(format!(
                "enroll: {path:?} is over {MAX_INPUT} bytes; a challenge token is at most {}",
                enroll::MAX_TOKEN_SIZE
            ));
        }
        let text = String::from_utf8(raw)
            .map_err(|_| format!("enroll: {path:?} is not text; a challenge token is ASCII"))?;
        return Ok((text, false));
    }
    let stdin = std::io::stdin();
    let from_terminal = stdin.is_terminal();
    if from_terminal {
        let _ = write!(tty_out, "{PASTE_PROMPT}");
    }
    let mut line = String::new();
    stdin
        .lock()
        .take(MAX_INPUT)
        .read_line(&mut line)
        .map_err(|e| format!("enroll: could not read the token from stdin: {e}"))?;
    Ok((line, from_terminal))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A context every shell receives as itself, unquoted: sh, cmd.exe and PowerShell alike. A
/// leading `@` or `-` is left out, since PowerShell and flag parsers read those as something
/// else (`docs/enroll.md` §4 step 1).
fn bare_context(c: &str) -> bool {
    let mut chars = c.chars();
    chars.next().is_some_and(|f| f.is_ascii_alphanumeric())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || "._/:+=-".contains(ch))
}

/// Why the entry may not enroll, and how to change that. `key policy` replaces a list rather
/// than adding to it, so the command printed names every context the entry keeps, then
/// archon-enroll/1; it is printed only when every context needs no quoting in any shell, and
/// otherwise the contexts are listed JSON-quoted.
pub fn policy_refusal(name: &str, policy: Option<&Policy>) -> String {
    let Some(p) = policy else {
        return format!(
            "enroll: key {name} may not sign in {}: it has no policy",
            enroll::DOMAIN
        );
    };
    let head = format!(
        "enroll: key {name} may not sign in {}: its policy is {p}",
        enroll::DOMAIN
    );
    if p.contexts.len() >= MAX_CONTEXTS {
        return format!(
            "{head}.\n  it already lists {MAX_CONTEXTS} contexts, the most a policy holds: drop one with archon key policy, or keep a separate key for enrollment"
        );
    }
    if !p.contexts.iter().all(|c| bare_context(c)) {
        let listed: Vec<String> = p.contexts.iter().map(|c| json_string(c)).collect();
        return format!(
            "{head}.\n  key policy replaces the list: run archon key policy {name} with --allow for each of {}, and for {}",
            listed.join(", "),
            enroll::DOMAIN
        );
    }
    let mut command = format!("archon key policy {name}");
    for c in &p.contexts {
        command += &format!(" --allow {c}");
    }
    command += &format!(" --allow {}", enroll::DOMAIN);
    format!("{head}.\n  to let it enroll, keeping what it has (key policy replaces the list):\n    {command}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use archon_core::keytext::decode_key;

    fn fixture() -> serde_json::Value {
        let raw = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/enroll-statement.json"
        ))
        .expect("the fixture");
        serde_json::from_str(&raw).expect("the fixture is JSON")
    }

    #[test]
    fn the_statement_and_the_prompt_are_the_fixtures() {
        let f = fixture();
        let cases = f["cases"].as_array().expect("cases");
        assert!(!cases.is_empty());
        for c in cases {
            let s = |k: &str| c[k].as_str().expect(k).to_string();
            let i = &c["intent"];
            let intent = enroll::Intent {
                blind: vec![0; 16],
                account_id: i["account_id"].as_str().unwrap().to_string(),
                account_name: i["account_name"].as_str().unwrap().to_string(),
                purpose: PURPOSE.to_string(),
                restrictions: i["restrictions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r.as_str().unwrap().to_string())
                    .collect(),
            };
            let key = decode_key(&s("key")).expect("key text");
            let got = render_statement(
                &s("audience"),
                &intent,
                &key,
                c["deadline"].as_u64().unwrap(),
                &s("keySource"),
            );
            assert_eq!(got, s("statement"), "{}", s("name"));
            assert_eq!(prompt(&intent), s("prompt"), "{}", s("name"));
        }
    }

    #[test]
    fn the_policy_refusal_is_the_fixtures() {
        let f = fixture();
        let cases = f["policy_cases"].as_array().expect("policy_cases");
        assert!(!cases.is_empty());
        for c in cases {
            let p = Policy {
                unrestricted: false,
                contexts: c["policy"]["contexts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect(),
            };
            let got = policy_refusal(c["key"].as_str().unwrap(), Some(&p));
            assert_eq!(
                got,
                c["refusal"].as_str().unwrap(),
                "{}",
                c["name"].as_str().unwrap()
            );
        }
    }

    fn challenge(audience: &str, key: &[u8], deadline: u64) -> enroll::Challenge {
        enroll::Challenge {
            audience: audience.to_string(),
            transaction: vec![0x8f, 0x3c],
            nonce: vec![0; 16],
            new_key: key.to_vec(),
            intent: vec![1],
            deadline,
        }
    }

    #[test]
    fn check_challenge_refuses_another_audience_another_key_and_a_passed_deadline() {
        let key = [7u8; 32];
        let aud = "https://bitshelf.dev/api";
        assert!(check_challenge(&challenge(aud, &key, 1000), aud, &key, 999).is_ok());
        let e = check_challenge(
            &challenge("https://other.example", &key, 1000),
            aud,
            &key,
            999,
        )
        .unwrap_err();
        assert!(e.contains("\"https://other.example\""), "{e}");
        let e = check_challenge(&challenge(aud, &[8u8; 32], 1000), aud, &key, 999).unwrap_err();
        assert!(e.contains("not this key"), "{e}");
        let e = check_challenge(&challenge(aud, &key, 1000), aud, &key, 1000).unwrap_err();
        assert!(e.contains("has passed"), "{e}");
    }
}
