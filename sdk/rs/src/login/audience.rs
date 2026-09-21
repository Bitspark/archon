//! `derive_audience` — the invocation URL → (audience, id bytes), `docs/login.md` §2.1.
//!
//! Part of the scheme, not of any CLI: three URL parsers normalise three ways and the audience
//! is the first field of the binding, so one URL must yield one audience in every lane. This
//! function accepts exactly the grammar of §2.1 and **refuses everything else rather than
//! normalising it** — no URL library, on purpose (a library is a normaliser, and the `url`
//! crate alone would break the sdk's one-dependency rule).
//!
//! ```text
//! invocation = scheme "://" host [ ":" port ] *( "/" segment ) "/login/" id
//! ```

/// The audience the login proof binds and the request id's bytes, from the URL the person
/// was told to run. Scheme is `http`/`https`/`ws`/`wss` (case-insensitive; `ws` → `http`,
/// `wss` → `https`); the host is an ASCII reg-name or a bracketed IPv6 literal, lowercased; a
/// port is `1..=65535` without a leading zero and is omitted from the audience when it is the
/// folded scheme's default (80, 443); segments are kept as written (case preserved,
/// percent-escapes never decoded); the id is lowercase hex of even length and is returned
/// decoded. Any non-ASCII, whitespace or control byte, userinfo, query, fragment, empty
/// segment, `.`/`..` segment, malformed escape, or a penultimate segment other than `login` is
/// an error.
pub fn derive_audience(url: &str) -> Result<(String, Vec<u8>), String> {
    if let Some((i, c)) = url
        .bytes()
        .enumerate()
        .find(|(_, c)| *c <= 0x20 || *c >= 0x7f)
    {
        return Err(format!(
            "login: URL byte {i} is 0x{c:02x} — only printable ASCII is accepted"
        ));
    }
    let (raw_scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "login: URL has no scheme".to_string())?;
    let (scheme, default_port) = fold_scheme(raw_scheme)?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => return Err("login: URL has no path — expected <audience>/login/<id>".to_string()),
    };
    let (host, port) = parse_authority(authority)?;
    if path.contains('?') || path.contains('#') {
        return Err(
            "login: URL carries a query or fragment — expected <audience>/login/<id>".to_string(),
        );
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        check_segment(seg).map_err(|e| format!("login: path segment {i}: {e}"))?;
    }
    if segments.len() < 2 {
        return Err("login: URL is not <audience>/login/<id>".to_string());
    }
    let penultimate = segments[segments.len() - 2];
    if penultimate != "login" {
        return Err(format!(
            "login: expected <audience>/login/<id>, got {penultimate:?} as the penultimate segment"
        ));
    }
    let id = decode_id(segments[segments.len() - 1])?;
    let mut audience = format!("{scheme}://{host}");
    if !port.is_empty() && port != default_port {
        audience.push(':');
        audience.push_str(port);
    }
    for seg in &segments[..segments.len() - 2] {
        audience.push('/');
        audience.push_str(seg);
    }
    Ok((audience, id))
}

fn fold_scheme(s: &str) -> Result<(&'static str, &'static str), String> {
    match s.to_ascii_lowercase().as_str() {
        "http" | "ws" => Ok(("http", "80")),
        "https" | "wss" => Ok(("https", "443")),
        _ => Err(format!(
            "login: unsupported URL scheme {s:?} — want http(s) or ws(s)"
        )),
    }
}

fn parse_authority(auth: &str) -> Result<(String, &str), String> {
    if auth.contains('@') {
        return Err("login: URL carries userinfo — refused".to_string());
    }
    if auth.is_empty() {
        return Err("login: URL has no host".to_string());
    }
    if let Some(stripped) = auth.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| "login: unterminated IPv6 literal".to_string())?;
        let lit = stripped[..end].to_ascii_lowercase();
        if lit.len() < 2
            || !lit.contains(':')
            || !lit
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase() || c == b':' || c == b'.')
        {
            return Err("login: malformed IPv6 literal".to_string());
        }
        let tail = &stripped[end + 1..];
        let port = if tail.is_empty() {
            ""
        } else {
            let p = tail
                .strip_prefix(':')
                .ok_or_else(|| "login: bytes after the IPv6 literal — refused".to_string())?;
            check_port(p)?
        };
        return Ok((format!("[{lit}]"), port));
    }
    let (name, port) = match auth.split_once(':') {
        Some((n, p)) => (n, check_port(p)?),
        None => (auth, ""),
    };
    let host = name.to_ascii_lowercase();
    for label in host.split('.') {
        if label.is_empty() {
            return Err("login: host has an empty label — refused".to_string());
        }
        if let Some(c) = label
            .bytes()
            .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-'))
        {
            return Err(format!(
                "login: host has byte 0x{c:02x} — refused (IDNs must be given as punycode)"
            ));
        }
    }
    Ok((host, port))
}

fn check_port(p: &str) -> Result<&str, String> {
    if p.is_empty() || (p.len() > 1 && p.starts_with('0')) || !p.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(format!("login: port {p:?} — refused"));
    }
    match p.parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => Ok(p),
        _ => Err(format!("login: port {p:?} is out of range")),
    }
}

fn check_segment(seg: &str) -> Result<(), String> {
    if seg.is_empty() {
        return Err("empty segment (a trailing slash or `//`) — refused".to_string());
    }
    if seg == "." || seg == ".." {
        return Err("dot segment — refused".to_string());
    }
    let b = seg.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&c) {
            i += 1;
        } else if c == b'%' {
            if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return Err("malformed percent-escape — refused".to_string());
            }
            i += 3;
        } else {
            return Err(format!(
                "byte 0x{c:02x} is not allowed in a path segment — refused"
            ));
        }
    }
    Ok(())
}

fn decode_id(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() < 2
        || !b.len().is_multiple_of(2)
        || !b
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return Err(format!(
            "login: id {s:?} is not lowercase hex of even length"
        ));
    }
    Ok(b.chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::derive_audience;

    const ID: &str = "8f3c1d2e4b5a69780f1e2d3c4b5a6978";

    #[test]
    fn accepts() {
        let cases = [
            (
                format!("https://dawn.example/api/login/{ID}"),
                "https://dawn.example/api",
            ),
            (
                format!("https://dawn.example:443/api/login/{ID}"),
                "https://dawn.example/api",
            ),
            (
                format!("http://localhost:8080/login/{ID}"),
                "http://localhost:8080",
            ),
            (
                format!("HTTPS://Dawn.Example/API/login/{ID}"),
                "https://dawn.example/API",
            ),
            (
                format!("wss://dawn.example:80/login/{ID}"),
                "https://dawn.example:80",
            ),
            (
                format!("https://[2001:DB8::1]:443/login/{ID}"),
                "https://[2001:db8::1]",
            ),
            (
                format!("https://dawn.example/a/b%2Fc/login/{ID}"),
                "https://dawn.example/a/b%2Fc",
            ),
        ];
        for (url, want) in cases {
            let (aud, id) = derive_audience(&url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(aud, want, "{url}");
            assert_eq!(id.len(), 16);
        }
    }

    #[test]
    fn refuses() {
        for url in [
            format!("dawn.example/login/{ID}"),
            format!("ftp://dawn.example/login/{ID}"),
            format!("https://dawn.example/api/login/{ID}/"),
            format!("https://user@dawn.example/login/{ID}"),
            format!("https://dawn.example/login/{ID}?x=1"),
            format!("https://dawn.example:0443/login/{ID}"),
            "https://dawn.example/api/login/8F3C".to_string(),
            "https://dawn.example/api/login/8f3".to_string(),
            format!("https://dawn.example/a b/login/{ID}"),
            format!("https://dawn.example/a%2/login/{ID}"),
            format!("https://[fe80::1%25eth0]/login/{ID}"),
            String::new(),
        ] {
            assert!(derive_audience(&url).is_err(), "{url}: not refused");
        }
    }
}
