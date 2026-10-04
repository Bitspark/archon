//! Request authentication — THIS KEY MADE THIS HTTP REQUEST (ADR 0010 §2–§6; `docs/request.md`
//! §3–§5 and §7, version 1, fixed by ADR 0010's status note of 4 October 2026).
//!
//! archon's RFC 9421 application profile: the client signs the RFC 9421 signature base
//! directly, in [`DOMAIN`], with archon's construction (Ed25519ph with the domain as the RFC 8032
//! context), and `alg` is never sent — the registered `ed25519` is pure Ed25519. The coverage is
//! fixed: the method, the full target URI, the configured audience as a CHECKED ECHO, a SHA-256
//! Content-Digest, Content-Type if present, and every product-declared header the request
//! carries.
//!
//! This module is the sdk's part (ADR 0010 §1): the transcript, the strict parsing, the coverage
//! rule and pure verification. Time is an argument. What it does NOT do is remember: one-use
//! enforcement (the replay store) and the HTTP extraction belong to the server adapters, so a
//! [`Verified`] is a proof that checked out, not yet a request that may reach an application.

use archon_core::crypto::{
    public_key_from_seed, sign_in_domain, verify_in_domain, PUBLIC_KEY_SIZE, SEED_SIZE,
    SIGNATURE_SIZE,
};
use archon_core::keytext::{decode_key, encode_key};
use sha2::{Digest, Sha256};

use crate::signer::{check_signature, sign_with, Scheme, Signer, SigningRequest};

/// The RFC 8032 context every request signature is made in.
pub const DOMAIN: &str = "archon-request/1";
/// The `tag` signature parameter; a verifier accepts only this.
pub const TAG: &str = "archon-request/1";
/// The one dictionary member in Signature-Input and Signature.
pub const LABEL: &str = "archon";
/// The nonce's least size, in bytes.
pub const MIN_NONCE_SIZE: usize = 16;
/// The nonce's greatest size, in bytes.
pub const MAX_NONCE_SIZE: usize = 64;
/// The longest request-target, in bytes.
pub const MAX_TARGET_SIZE: usize = 8192;
/// The longest covered value, in bytes.
pub const MAX_VALUE_SIZE: usize = 8192;
/// The largest integer the profile spells: 15 digits.
pub const MAX_INT: u64 = 999_999_999_999_999;

/// What a client signs. `declared` holds the product-declared headers the request carries, in
/// the product's declared order, names in lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToSign {
    /// The method token, case kept.
    pub method: String,
    /// The configured audience of the service being called.
    pub audience: String,
    /// The origin-form request-target that will be sent.
    pub request_target: String,
    /// The content, as sent.
    pub body: Vec<u8>,
    /// The Content-Type the request carries, if any.
    pub content_type: Option<String>,
    /// The product-declared headers the request carries.
    pub declared: Vec<(String, String)>,
    /// Signed creation time, seconds since the epoch.
    pub created: u64,
    /// Signed expiry, seconds since the epoch.
    pub expires: u64,
    /// 16..=64 fresh random bytes.
    pub nonce: Vec<u8>,
}

/// The four headers archon adds to a request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    /// `Archon-Audience`.
    pub archon_audience: String,
    /// `Content-Digest`.
    pub content_digest: String,
    /// `Signature-Input`.
    pub signature_input: String,
    /// `Signature` (empty in a [`Prepared`]).
    pub signature: String,
}

/// A request prepared for a signer: the base it will sign, the signing request, and every
/// header but `Signature`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    /// The RFC 9421 signature base.
    pub base: String,
    /// What the signer is asked to sign.
    pub signing: SigningRequest,
    /// The headers, `signature` empty.
    pub headers: Headers,
}

/// What a verifier is configured with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The configured audience.
    pub audience: String,
    /// The product-declared headers, in the product's order.
    pub declared: Vec<String>,
    /// W: the longest acceptable `expires − created`, in seconds.
    pub max_lifetime: u64,
    /// δ: the clock tolerance, in seconds.
    pub skew: u64,
}

/// A request as the server received it: the method, the raw request-target, every header field
/// in the order received (names in any case), and the body after transfer framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// The method, as received.
    pub method: String,
    /// The raw request-target, as received.
    pub request_target: String,
    /// Every header field, in order.
    pub headers: Vec<(String, String)>,
    /// The content.
    pub body: Vec<u8>,
}

/// A proof that checked out under the policy at `now`. Not yet replay-checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The principal's public key.
    pub principal: [u8; PUBLIC_KEY_SIZE],
    /// Its canonical key text.
    pub key_text: String,
    /// Signed creation time.
    pub created: u64,
    /// Signed expiry.
    pub expires: u64,
    /// The client identifier.
    pub nonce: Vec<u8>,
    /// The method.
    pub method: String,
    /// The target URI, built from the configured origin.
    pub target_uri: String,
    /// Every covered field, in coverage order, with the verified value.
    pub covered: Vec<(String, String)>,
    /// The verified content digest.
    pub content_digest: [u8; 32],
}

const RESERVED: [&str; 5] = [
    "archon-audience",
    "content-digest",
    "content-type",
    "signature-input",
    "signature",
];

fn is_visible(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The origin of an audience — the audience up to its authority's end — or an error for an
/// audience outside `docs/request.md` §3.1.
pub fn origin(audience: &str) -> Result<String, String> {
    if !is_visible(audience) {
        return Err("request: the audience is not visible ASCII".to_string());
    }
    let rest = audience
        .strip_prefix("https://")
        .map(|r| ("https://", r))
        .or_else(|| audience.strip_prefix("http://").map(|r| ("http://", r)));
    let Some((scheme, rest)) = rest else {
        return Err("request: the audience is not an http or https URL".to_string());
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("request: the audience's authority is empty or carries userinfo".to_string());
    }
    if audience.contains('?') || audience.contains('#') {
        return Err("request: the audience carries a query or a fragment".to_string());
    }
    if audience.ends_with('/') {
        return Err("request: the audience ends in /".to_string());
    }
    Ok(format!("{scheme}{authority}"))
}

fn check_method(method: &str) -> Result<(), String> {
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err("request: the method is not a token".to_string());
    }
    Ok(())
}

fn check_target(target: &str) -> Result<(), String> {
    if target.is_empty() || target.len() > MAX_TARGET_SIZE {
        return Err("request: the request-target's length".to_string());
    }
    if !target.starts_with('/') || !is_visible(target) || target.contains('#') {
        return Err("request: the request-target is not origin form".to_string());
    }
    Ok(())
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches(|c| c == ' ' || c == '\t')
}

/// A covered value, trimmed of leading and trailing SP and HTAB, or an error.
fn covered_value(value: &str) -> Result<String, String> {
    let v = trim_ows(value);
    if v.is_empty()
        || v.len() > MAX_VALUE_SIZE
        || !v.bytes().all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
    {
        return Err(
            "request: a covered value is empty, too long, or not visible ASCII, SP and HTAB"
                .to_string(),
        );
    }
    Ok(v.to_string())
}

fn check_declared_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || RESERVED.contains(&name)
    {
        return Err(format!("request: {name:?} cannot be a declared header"));
    }
    Ok(())
}

fn check_int(n: u64, what: &str) -> Result<(), String> {
    if n > MAX_INT {
        return Err(format!(
            "request: {what} is not an integer in 0..={MAX_INT}"
        ));
    }
    Ok(())
}

fn check_nonce(nonce: &[u8]) -> Result<(), String> {
    if nonce.len() < MIN_NONCE_SIZE || nonce.len() > MAX_NONCE_SIZE {
        return Err(format!(
            "request: the nonce is {} bytes, want {MIN_NONCE_SIZE}..={MAX_NONCE_SIZE}",
            nonce.len()
        ));
    }
    Ok(())
}

/// The RFC 9421 signature base: one `"<name>": <value>` line per covered component, then
/// `"@signature-params": <inner list>` with no trailing line feed.
pub fn signature_base(components: &[(String, String)], inner_list: &str) -> String {
    let mut out = String::new();
    for (name, value) in components {
        out.push_str(&format!("\"{name}\": {value}\n"));
    }
    out.push_str("\"@signature-params\": ");
    out.push_str(inner_list);
    out
}

fn digest_header(body: &[u8]) -> String {
    format!("sha-256=:{}:", b64_encode(&Sha256::digest(body), B64, true))
}

/// The base and headers for `input`, for a signer whose key is `public_key`. Pure; errors on
/// any value outside `docs/request.md` §3.1.
pub fn prepare(public_key: &[u8; PUBLIC_KEY_SIZE], input: &ToSign) -> Result<Prepared, String> {
    check_method(&input.method)?;
    let origin = origin(&input.audience)?;
    check_target(&input.request_target)?;
    check_int(input.created, "created")?;
    check_int(input.expires, "expires")?;
    if input.created >= input.expires {
        return Err("request: created must be before expires".to_string());
    }
    check_nonce(&input.nonce)?;
    let digest = digest_header(&input.body);
    let mut components = vec![
        ("@method".to_string(), input.method.clone()),
        (
            "@target-uri".to_string(),
            format!("{origin}{}", input.request_target),
        ),
        ("archon-audience".to_string(), input.audience.clone()),
        ("content-digest".to_string(), digest.clone()),
    ];
    if let Some(ct) = &input.content_type {
        components.push(("content-type".to_string(), covered_value(ct)?));
    }
    let mut seen: Vec<&str> = Vec::new();
    for (name, value) in &input.declared {
        check_declared_name(name)?;
        if seen.contains(&name.as_str()) {
            return Err(format!("request: {name} is declared twice"));
        }
        seen.push(name);
        components.push((name.clone(), covered_value(value)?));
    }
    let key_text = encode_key(public_key);
    let names: Vec<String> = components.iter().map(|(n, _)| format!("\"{n}\"")).collect();
    let inner = format!(
        "({});created={};expires={};nonce=\"{}\";keyid=\"{key_text}\";tag=\"{TAG}\"",
        names.join(" "),
        input.created,
        input.expires,
        b64_encode(&input.nonce, B64URL, false)
    );
    let base = signature_base(&components, &inner);
    Ok(Prepared {
        signing: SigningRequest {
            expected_public_key: *public_key,
            scheme: Scheme::PhContext {
                domain: DOMAIN.to_string(),
            },
            message: base.as_bytes().to_vec(),
        },
        base,
        headers: Headers {
            archon_audience: input.audience.clone(),
            content_digest: digest,
            signature_input: format!("{LABEL}={inner}"),
            signature: String::new(),
        },
    })
}

/// The headers, from a signature over a prepared request: checked against it first. Pure.
pub fn complete(prepared: &Prepared, signature: &[u8]) -> Result<Headers, String> {
    let checked = check_signature(&prepared.signing, signature)?;
    let mut headers = prepared.headers.clone();
    headers.signature = format!("{LABEL}=:{}:", b64_encode(&checked, B64, true));
    Ok(headers)
}

/// Sign `input` with the key behind `seed`: the base, and the four headers to send.
pub fn sign(seed: &[u8; SEED_SIZE], input: &ToSign) -> Result<(String, Headers), String> {
    let prepared = prepare(&public_key_from_seed(seed), input)?;
    let signature = sign_in_domain(seed, DOMAIN, &prepared.signing.message)?;
    let headers = complete(&prepared, &signature)?;
    Ok((prepared.base, headers))
}

/// [`sign`] through a signer instead of a seed.
pub async fn sign_with_signer<S: Signer>(signer: &S, input: &ToSign) -> Result<Headers, String> {
    let prepared = prepare(&signer.public_key(), input)?;
    let signature = sign_with(signer, &prepared.signing).await?;
    complete(&prepared, &signature)
}

/// The parts of a Signature-Input value, parsed by the profile's one grammar
/// (`docs/request.md` §5).
struct SignatureInput {
    inner: String,
    names: Vec<String>,
    created: u64,
    expires: u64,
    nonce: String,
    keyid: String,
}

fn parse_int(s: &str) -> Option<(u64, &str)> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    let (num, rest) = s.split_at(digits);
    if digits == 0 || digits > 15 || (digits > 1 && num.starts_with('0')) {
        return None;
    }
    Some((num.parse().ok()?, rest))
}

fn parse_signature_input(value: &str) -> Option<SignatureInput> {
    let inner = value.strip_prefix("archon=")?;
    let mut rest = inner.strip_prefix('(')?;
    let mut names = Vec::new();
    loop {
        let after_quote = rest.strip_prefix('"')?;
        let end = after_quote.find('"')?;
        names.push(after_quote[..end].to_string());
        rest = &after_quote[end + 1..];
        if let Some(r) = rest.strip_prefix(')') {
            rest = r;
            break;
        }
        rest = rest.strip_prefix(' ')?;
    }
    let rest = rest.strip_prefix(";created=")?;
    let (created, rest) = parse_int(rest)?;
    let rest = rest.strip_prefix(";expires=")?;
    let (expires, rest) = parse_int(rest)?;
    let rest = rest.strip_prefix(";nonce=\"")?;
    let n = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        .count();
    if n == 0 {
        return None;
    }
    let (nonce, rest) = rest.split_at(n);
    let rest = rest.strip_prefix("\";keyid=\"")?;
    let k = rest
        .bytes()
        .take_while(|b| *b != b'"' && *b != b'\\')
        .count();
    let (keyid, rest) = rest.split_at(k);
    if rest != "\";tag=\"archon-request/1\"" {
        return None;
    }
    Some(SignatureInput {
        inner: inner.to_string(),
        names,
        created,
        expires,
        nonce: nonce.to_string(),
        keyid: keyid.to_string(),
    })
}

/// `<prefix>=:<standard base64>:` → bytes, in the one canonical spelling.
fn parse_byte_sequence(value: &str, prefix: &str) -> Option<Vec<u8>> {
    let body = value
        .strip_prefix(prefix)?
        .strip_prefix("=:")?
        .strip_suffix(':')?;
    if body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    b64_decode(body, B64, true).ok()
}

/// Verify `received` under `policy` at `now` (seconds since the epoch): `docs/request.md` §7
/// steps 1–7. It does not check replay: a server adapter must insert (TAG, audience, principal,
/// nonce) into its replay store before the request reaches an application.
pub fn verify(policy: &Policy, now: u64, received: &Received) -> Result<Verified, String> {
    let origin = origin(&policy.audience)?;
    let mut declared: Vec<&str> = Vec::new();
    for d in &policy.declared {
        check_declared_name(d)?;
        if declared.contains(&d.as_str()) {
            return Err(format!("request: {d} is declared twice"));
        }
        declared.push(d);
    }
    check_int(policy.max_lifetime, "max_lifetime")?;
    if policy.max_lifetime < 1 {
        return Err("request: max_lifetime must be at least 1".to_string());
    }
    check_int(policy.skew, "skew")?;
    check_int(now, "now")?;

    // ASCII case folding only: HTTP field names are tokens, and Unicode folding would turn
    // U+212A KELVIN SIGN into `k` — a different header in a lane that folds ASCII only.
    let mut fields: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in &received.headers {
        let key = name.to_ascii_lowercase();
        let value = trim_ows(value).to_string();
        match fields.iter_mut().find(|(k, _)| *k == key) {
            Some((_, list)) => list.push(value),
            None => fields.push((key, vec![value])),
        }
    }
    let has = |name: &str| fields.iter().any(|(k, _)| k == name);
    let once = |name: &str| -> Result<String, String> {
        match fields.iter().find(|(k, _)| k == name) {
            Some((_, list)) if list.len() == 1 => Ok(list[0].clone()),
            _ => Err(format!("request: {name} must appear exactly once")),
        }
    };

    // 1. The two proof fields parse, in their one spelling.
    let si = parse_signature_input(&once("signature-input")?)
        .ok_or_else(|| "request: Signature-Input is not the profile's spelling".to_string())?;
    let signature = parse_byte_sequence(&once("signature")?, LABEL)
        .ok_or_else(|| "request: Signature is not the profile's spelling".to_string())?;
    if signature.len() != SIGNATURE_SIZE {
        return Err("request: the signature is not 64 bytes".to_string());
    }
    let nonce = b64_decode(&si.nonce, B64URL, false)?;
    check_nonce(&nonce)?;

    // 2. keyid is a canonical principal (the tag was matched by the grammar).
    let principal: [u8; PUBLIC_KEY_SIZE] = decode_key(&si.keyid)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| "request: keyid is not a principal".to_string())?;
    if encode_key(&principal) != si.keyid {
        return Err("request: keyid is not the canonical key text".to_string());
    }

    // 3. The coverage is exactly §3.1's, for what this request carries.
    let mut expected = vec![
        "@method",
        "@target-uri",
        "archon-audience",
        "content-digest",
    ];
    if has("content-type") {
        expected.push("content-type");
    }
    for d in &policy.declared {
        if has(d) {
            expected.push(d);
        }
    }
    if si.names != expected {
        return Err("request: the coverage is not the profile's for this request".to_string());
    }
    check_method(&received.method)?;
    check_target(&received.request_target)?;
    let mut components = Vec::with_capacity(si.names.len());
    for n in &si.names {
        let value = match n.as_str() {
            "@method" => received.method.clone(),
            "@target-uri" => format!("{origin}{}", received.request_target),
            _ => covered_value(&once(n)?)?,
        };
        components.push((n.clone(), value));
    }

    // 4. The audience echo is the configured audience, byte for byte.
    if once("archon-audience")? != policy.audience {
        return Err("request: Archon-Audience is not the configured audience".to_string());
    }

    // 5. The digest is the received content's.
    let digest = parse_byte_sequence(&once("content-digest")?, "sha-256")
        .ok_or_else(|| "request: Content-Digest is not the profile's spelling".to_string())?;
    let actual = Sha256::digest(&received.body);
    if digest[..] != actual[..] {
        return Err("request: Content-Digest does not match the content".to_string());
    }

    // 6. Freshness: 0 < e − c ≤ W and c − δ ≤ now < e + δ. Every term is at most 15 digits,
    // so i64 cannot overflow.
    let (c, e, w, d, t) = (
        si.created as i64,
        si.expires as i64,
        policy.max_lifetime as i64,
        policy.skew as i64,
        now as i64,
    );
    if !(c < e && e - c <= w) {
        return Err("request: the lifetime is out of bounds".to_string());
    }
    if !(c - d <= t && t < e + d) {
        return Err("request: not fresh at now".to_string());
    }

    // 7. The signature, over the base built from what was received and configured.
    let base = signature_base(&components, &si.inner);
    if !verify_in_domain(&principal, DOMAIN, base.as_bytes(), &signature) {
        return Err("request: the signature does not verify".to_string());
    }

    let mut content_digest = [0u8; 32];
    content_digest.copy_from_slice(&digest);
    Ok(Verified {
        principal,
        key_text: si.keyid,
        created: si.created,
        expires: si.expires,
        nonce,
        method: received.method.clone(),
        target_uri: format!("{origin}{}", received.request_target),
        covered: components
            .into_iter()
            .filter(|(n, _)| !n.starts_with('@'))
            .collect(),
        content_digest,
    })
}

// ---------------------------------------------------------------------------------------------
// base64, both alphabets, accepted only in their one canonical spelling (docs/request.md §3.1):
// decoding and re-encoding must give back the same text.
// ---------------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = (chunk.len() * 8).div_ceil(6);
        for j in 0..chars {
            out.push(alphabet[((n >> (18 - 6 * j)) & 63) as usize] as char);
        }
        if pad {
            out.push_str(&"=".repeat(4 - chars));
        }
    }
    out
}

fn b64_decode(text: &str, alphabet: &[u8; 64], pad: bool) -> Result<Vec<u8>, String> {
    let body = if pad {
        text.trim_end_matches('=')
    } else {
        text
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in body.bytes() {
        let v = alphabet
            .iter()
            .position(|a| *a == b)
            .ok_or_else(|| "request: not base64".to_string())?;
        acc = ((acc << 6) | v as u32) & 0xff_ffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if b64_encode(&out, alphabet, pad) != text {
        return Err("request: not the canonical base64 spelling".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ToSign {
        ToSign {
            method: "POST".to_string(),
            audience: "https://dawn.example/api".to_string(),
            request_target: "/api/v1/things?x=1".to_string(),
            body: br#"{"a":1}"#.to_vec(),
            content_type: Some("application/json".to_string()),
            declared: vec![("idempotency-key".to_string(), "k-1".to_string())],
            created: 1_789_034_640,
            expires: 1_789_034_700,
            nonce: vec![7; 16],
        }
    }

    // What the vectors leave to the lanes: a signed request verifying end to end, and the
    // verifier reporting what it verified.
    #[test]
    fn a_signed_request_verifies() {
        let seed = [0x44; 32];
        let (_, h) = sign(&seed, &input()).unwrap();
        let header = |n: &str, v: &str| (n.to_string(), v.to_string());
        let received = Received {
            method: "POST".to_string(),
            request_target: "/api/v1/things?x=1".to_string(),
            headers: vec![
                header("Content-Type", "application/json"),
                header("Idempotency-Key", "k-1"),
                header("Archon-Audience", &h.archon_audience),
                header("Content-Digest", &h.content_digest),
                header("Signature-Input", &h.signature_input),
                header("Signature", &h.signature),
            ],
            body: input().body,
        };
        let policy = Policy {
            audience: "https://dawn.example/api".to_string(),
            declared: vec!["idempotency-key".to_string()],
            max_lifetime: 300,
            skew: 30,
        };
        let v = verify(&policy, 1_789_034_645, &received).unwrap();
        assert_eq!(v.principal, public_key_from_seed(&seed));
        assert_eq!(v.target_uri, "https://dawn.example/api/v1/things?x=1");
        assert_eq!(v.covered.len(), 4);
    }

    #[test]
    fn base64_round_trips_and_refuses_other_spellings() {
        for n in 0..10 {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            for (alphabet, pad) in [(B64, true), (B64URL, false)] {
                let text = b64_encode(&bytes, alphabet, pad);
                assert_eq!(b64_decode(&text, alphabet, pad).unwrap(), bytes);
            }
        }
        assert!(b64_decode("AA", B64, true).is_err(), "padding missing");
        assert!(b64_decode("AB==", B64, true).is_err(), "unused bits set");
        assert!(
            b64_decode("AA==", B64URL, false).is_err(),
            "padded url form"
        );
    }

    #[test]
    fn the_signature_input_grammar_admits_one_spelling() {
        let k = format!("ed25519:{}", "00".repeat(32));
        let ok = format!("archon=(\"@method\" \"x\");created=0;expires=1;nonce=\"AAAA\";keyid=\"{k}\";tag=\"archon-request/1\"");
        assert!(parse_signature_input(&ok).is_some());
        for bad in [
            ok.replace("created=0", "created=00"),
            ok.replace("(\"@method\" \"x\")", "(\"@method\"  \"x\")"),
            ok.replace("tag=\"archon-request/1\"", "tag=\"archon-request/2\""),
            format!("{ok};alg=\"ed25519\""),
            ok.replace("archon=", "sig1="),
        ] {
            assert!(parse_signature_input(&bad).is_none(), "{bad}");
        }
    }
}
