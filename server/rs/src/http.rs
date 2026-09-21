//! The thin adapter between HTTP on a wire and [`Request`]/[`Response`].
//!
//! Still not a server (ADR 0007 §B): nothing here opens a socket or spawns a task. These are
//! pure functions over bytes — the caller owns the listener, whether that is a `std::net`
//! loop, axum, or a serverless entry point. `examples/serve.rs` is the whole thing wired to a
//! `TcpListener` in about forty lines, and is the shortest complete answer to "how do I mount
//! this".
//!
//! The adapter exists because two small things are easy to get wrong in every framework, and
//! getting either wrong is silent: HEADER NAMES MUST BE MATCHED CASE-INSENSITIVELY (a browser
//! is free to send `Archon-Collect`, and a handler that only looked for `archon-collect`
//! would read every collect as unproven), and THE MOUNT PREFIX MUST BE STRIPPED EXACTLY, so
//! that `/api/loginX/ab` is not served by a handler mounted at `/api/login`.

use crate::{Request, Response, MAX_BODY_BYTES};

/// The request line and headers, without the blank line that ends them.
#[derive(Debug, Clone)]
pub struct Head {
    pub method: String,
    /// The raw request target, query string included.
    pub target: String,
    /// Names lowercased; values trimmed.
    pub headers: Vec<(String, String)>,
}

/// Parses a request head. `bytes` is everything up to (not including) the blank line.
///
/// Deliberately strict: an HTTP/1.1 request line has exactly three space-separated parts and a
/// header line has a colon. A parser that guesses at a malformed request is a parser two
/// implementations will disagree about.
pub fn parse_head(bytes: &[u8]) -> Result<Head, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "request head is not UTF-8".to_string())?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next().unwrap_or("").trim_end();
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3 {
        return Err(format!("malformed request line {request_line:?}"));
    }
    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("malformed header line {line:?}"));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok(Head {
        method: parts[0].to_string(),
        target: parts[1].to_string(),
        headers,
    })
}

impl Head {
    /// A header by name, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// How many body bytes to read, refusing anything past the handler's cap before a single
    /// one is read. A cap enforced only after reading is not a cap.
    pub fn content_length(&self) -> Result<usize, String> {
        let Some(raw) = self.header("content-length") else {
            return Ok(0);
        };
        let n: usize = raw
            .parse()
            .map_err(|_| format!("content-length {raw:?} is not a number"))?;
        if n > MAX_BODY_BYTES {
            return Err(format!(
                "content-length {n} is over the {MAX_BODY_BYTES} cap"
            ));
        }
        Ok(n)
    }

    /// Turns the head and its body into what [`crate::Handler::handle`] takes, with `mount`
    /// stripped from the front of the path.
    ///
    /// The remainder after `mount` must be empty or begin with `/`, so a handler mounted at
    /// `/api/login` does not also answer for `/api/loginX`. The query string is dropped: no
    /// route here reads one, and a path carrying one would not match a stored id anyway.
    ///
    /// Nothing is percent-decoded. Ids are hex and never need it, and decoding is how a `%2f`
    /// turns into a path separator that routing has already finished looking at.
    pub fn into_request(self, body: Vec<u8>, mount: &str) -> Result<Request, String> {
        let path = self.target.split(['?', '#']).next().unwrap_or("");
        let mount = mount.trim_end_matches('/');
        let rest = if mount.is_empty() {
            path
        } else if let Some(r) = path.strip_prefix(mount) {
            if !r.is_empty() && !r.starts_with('/') {
                return Err(format!("path {path:?} is not under the mount {mount:?}"));
            }
            r
        } else {
            return Err(format!("path {path:?} is not under the mount {mount:?}"));
        };
        Ok(Request {
            method: self.method,
            path: rest.to_string(),
            body,
            headers: self.headers,
        })
    }
}

/// Serialises a response as HTTP/1.1 bytes, adding `content-length` and closing the
/// connection. `Connection: close` is what keeps the example a loop rather than a state
/// machine; a real server writes the response through its own framework and never calls this.
pub fn write_response(resp: &Response) -> Vec<u8> {
    let reason = reason_phrase(resp.status);
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", resp.status).into_bytes();
    for (k, v) in &resp.headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\n", resp.body.len()).as_bytes());
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(&resp.body);
    out
}

/// Only the statuses §4 uses. A phrase is decoration — the status is the thing — so an
/// unknown one gets a blank rather than a guess.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &str) -> Head {
        parse_head(raw.as_bytes()).expect("parse_head")
    }

    #[test]
    fn a_header_is_found_whatever_its_case() {
        // The one that matters: a browser may send any casing, and a collect proof that is
        // not found reads as a collect that was never proven.
        let h = head("GET /x HTTP/1.1\r\nArchon-Collect: ab12\r\nHost: dawn.example\r\n");
        assert_eq!(h.header("archon-collect"), Some("ab12"));
        assert_eq!(h.header("ARCHON-COLLECT"), Some("ab12"));
        let req = h.into_request(Vec::new(), "").expect("into_request");
        assert_eq!(req.header(crate::COLLECT_HEADER), Some("ab12"));
    }

    #[test]
    fn the_mount_is_stripped_exactly() {
        let under = |target: &str| {
            head(&format!("GET {target} HTTP/1.1\r\n"))
                .into_request(Vec::new(), "/api/login")
                .map(|r| r.path)
        };
        assert_eq!(under("/api/login").unwrap(), "");
        assert_eq!(under("/api/login/ab12").unwrap(), "/ab12");
        assert_eq!(under("/api/login/ab12/answer").unwrap(), "/ab12/answer");
        // A neighbouring path that merely starts with the same letters is NOT ours.
        assert!(under("/api/loginX/ab12").is_err());
        assert!(under("/elsewhere").is_err());
        // A trailing slash on the mount is the same mount.
        assert_eq!(
            head("GET /api/login/ab12 HTTP/1.1\r\n")
                .into_request(Vec::new(), "/api/login/")
                .unwrap()
                .path,
            "/ab12"
        );
    }

    #[test]
    fn a_query_string_is_not_part_of_the_path() {
        let r = head("GET /ab12?next=%2Fhome HTTP/1.1\r\n")
            .into_request(Vec::new(), "")
            .unwrap();
        assert_eq!(r.path, "/ab12");
    }

    #[test]
    fn the_body_cap_is_enforced_before_the_body_is_read() {
        let over = MAX_BODY_BYTES + 1;
        let h = head(&format!("POST / HTTP/1.1\r\nContent-Length: {over}\r\n"));
        assert!(
            h.content_length().is_err(),
            "a cap enforced only after reading is not a cap"
        );
        assert_eq!(head("POST / HTTP/1.1\r\n").content_length().unwrap(), 0);
        assert!(head("POST / HTTP/1.1\r\nContent-Length: x\r\n")
            .content_length()
            .is_err());
    }

    #[test]
    fn a_malformed_head_is_refused_rather_than_guessed_at() {
        assert!(parse_head(b"GET /x").is_err());
        assert!(parse_head(b"GET /x HTTP/1.1 extra").is_err());
        assert!(parse_head(b"GET /x HTTP/1.1\r\nnot a header\r\n").is_err());
        assert!(parse_head(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn a_response_carries_its_own_length() {
        let resp = Response {
            status: 201,
            body: b"{\"id\":\"ab\"}".to_vec(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
        };
        let bytes = String::from_utf8(write_response(&resp)).unwrap();
        assert!(bytes.starts_with("HTTP/1.1 201 Created\r\n"), "{bytes}");
        assert!(
            bytes.contains("content-type: application/json\r\n"),
            "{bytes}"
        );
        assert!(bytes.contains("content-length: 11\r\n"), "{bytes}");
        assert!(bytes.ends_with("\r\n\r\n{\"id\":\"ab\"}"), "{bytes}");
    }
}
