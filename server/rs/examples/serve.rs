//! A complete mount of the login handler on a bare `TcpListener`, with no dependencies at all
//! beyond this crate. It is here to be the shortest true answer to "how do I run this", and to
//! be COMPILED BY CI so it cannot quietly rot into an example that no longer builds.
//!
//! ```text
//! cargo run --example serve -- https://dawn.example/api 127.0.0.1:8080
//! curl -si -XPOST localhost:8080/api/login \
//!   -d '{"browser":"<key text>","scope":["read:projects"],"valid_for":3600}'
//! ```
//!
//! A production service would mount [`archon_server::Handler`] in the framework it already
//! runs — the handler is a plain function, so that adapter is about as long as `serve` below.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use archon_server::http;
use archon_server::{Config, Handler, Response};

/// Where the four routes live under. Everything before this is the service's own business,
/// which is why the handler never sees it.
const MOUNT: &str = "/api/login";

/// A head longer than this is not a request anyone here means to serve.
const MAX_HEAD: usize = 16 * 1024;

fn main() -> std::io::Result<()> {
    // THE AUDIENCE IS THE SERVICE'S PUBLIC IDENTITY, NOT ITS BIND ADDRESS. A service behind a
    // proxy listens on 127.0.0.1 and is still `https://dawn.example/api` to every CLI that
    // signs for it — the audience must be the URL people actually type, because that is what
    // the CLI derives and binds.
    let audience = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://dawn.example/api".to_string());

    // No admitter: this example's law is "the proof suffices", which is the right default for
    // a service that only needs to know a key holder was here and approved a scope.
    let handler = match Handler::new(Config::new(&audience)) {
        Ok(h) => Arc::new(h),
        Err(e) => {
            // A misconfigured audience is a startup error naming the fix, not a service that
            // runs and refuses every proof for reasons nobody can see.
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    // The bind address is a second argument because the audience is NOT an address: a
    // service's public identity and the socket it happens to listen on are different facts,
    // and an example that conflated them would teach the wrong thing.
    let bind = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&bind)?;
    eprintln!("archon login: {audience} mounted at {MOUNT} on http://{bind}");
    for stream in listener.incoming() {
        let stream = stream?;
        let handler = Arc::clone(&handler);
        // A thread per connection: the handler is `Sync`, and the point here is legibility.
        std::thread::spawn(move || {
            if let Err(e) = serve(&handler, stream) {
                eprintln!("connection: {e}");
            }
        });
    }
    Ok(())
}

fn serve(handler: &Handler, mut stream: TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    // Read until the blank line that ends the head.
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut stream, &refuse(400));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(()); // the client went away mid-head
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let Ok(head) = http::parse_head(&buf[..head_end]) else {
        return respond(&mut stream, &refuse(400));
    };
    // The cap is checked from the declared length BEFORE reading, so an oversized body costs
    // nothing to refuse.
    let Ok(want) = head.content_length() else {
        return respond(&mut stream, &refuse(400));
    };

    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < want {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(want);

    // A path outside the mount is this service's business, not the handler's.
    let Ok(req) = head.into_request(body, MOUNT) else {
        return respond(&mut stream, &refuse(404));
    };
    respond(&mut stream, &handler.handle(&req))
}

fn respond(stream: &mut TcpStream, resp: &Response) -> std::io::Result<()> {
    stream.write_all(&http::write_response(resp))?;
    stream.flush()
}

/// The same body shape §4 uses, so a client parses one thing whether the refusal came from
/// the handler or from the socket in front of it.
fn refuse(status: u16) -> Response {
    let code = if status == 404 {
        "expired_token"
    } else {
        "invalid_request"
    };
    Response {
        status,
        body: format!("{{\"error\":\"{code}\"}}").into_bytes(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
