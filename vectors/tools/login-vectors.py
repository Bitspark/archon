#!/usr/bin/env python3
"""Derive vectors/login.json OUTSIDE the three cores.

The binding and the possession message are assembled by hand from the layouts pinned in
docs/login.md §3 — this file is a fourth, deliberately naive implementation of those layouts —
and every signature is produced by OpenSSL 3.2.x (`pkeyutl -rawin -pkeyopt instance:Ed25519ph
-pkeyopt context-string:<domain>`), never by a core. A vector copied out of a core pins that
core's bugs; a vector derived from the standard lets all three cores be wrong together and be
caught (vectors/README.md, "Authoring").

Run from the repo root: `python vectors/tools/login-vectors.py > vectors/login.json`.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

DOMAIN = "archon-login/1"
ROLE_LOGIN = 0x01
ROLE_COLLECT = 0x02
POSSESSION_TAG = 0x01
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")  # RFC 8410, Ed25519 seed

SEED_P = bytes([0x11]) * 32
SEED_K = bytes([0x22]) * 32
SEED_X = bytes([0x33]) * 32
AUDIENCE = "https://dawn.example/api"


def u16(n: int) -> bytes:
    assert 0 <= n <= 0xFFFF
    return n.to_bytes(2, "big")


def u32(n: int) -> bytes:
    assert 0 <= n <= 0xFFFFFFFF
    return n.to_bytes(4, "big")


def openssl(args, stdin: bytes = b"") -> bytes:
    r = subprocess.run(["openssl", *args], input=stdin, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"openssl {' '.join(args)} failed: {r.stderr.decode(errors='replace')}")
    return r.stdout


def pem_for(seed: bytes) -> bytes:
    der = PKCS8_PREFIX + seed
    b64 = base64.encodebytes(der).replace(b"\n", b"")
    return b"-----BEGIN PRIVATE KEY-----\n" + b64 + b"\n-----END PRIVATE KEY-----\n"


def pubkey_of(seed: bytes) -> bytes:
    """The public key as OpenSSL derives it (SPKI DER: 12-byte RFC 8410 prefix, then 32 bytes)."""
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "key.pem")
        with open(key, "wb") as f:
            f.write(pem_for(seed))
        spki = openssl(["pkey", "-in", key, "-pubout", "-outform", "DER"])
    assert len(spki) == 44 and spki[:12] == bytes.fromhex("302a300506032b6570032100")
    return spki[12:]


def sign(seed: bytes, message: bytes, domain: str | None, prehash: bool = True) -> bytes:
    """Ed25519ph with `domain` as the RFC 8032 context (the floor's sign_in_domain), or, with
    domain=None and prehash=False, a plain Ed25519 signature (the floor's raw sign)."""
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "key.pem")
        msg = os.path.join(d, "msg.bin")
        with open(key, "wb") as f:
            f.write(pem_for(seed))
        with open(msg, "wb") as f:
            f.write(message)
        args = ["pkeyutl", "-sign", "-rawin", "-in", msg, "-inkey", key]
        if prehash:
            args += ["-pkeyopt", "instance:Ed25519ph"]
            if domain is not None:
                args += ["-pkeyopt", "context-string:" + domain]
        sig = openssl(args)
    assert len(sig) == 64
    return sig


def binding(role: int, audience: bytes, browser: bytes, ident: bytes, scope: list[bytes], valid_for: int) -> bytes:
    out = bytes([role]) + u16(len(audience)) + audience + browser + u16(len(ident)) + ident + u16(len(scope))
    for entry in scope:
        out += u16(len(entry)) + entry
    return out + u32(valid_for)


def possession_message(nonce: bytes, bound: bytes) -> bytes:
    return bytes([POSSESSION_TAG]) + u16(len(nonce)) + nonce + u16(len(bound)) + bound


# ---- §2.1: derive_audience, a deliberately naive fourth implementation of the grammar --------
HEX_LOWER = set("0123456789abcdef")
SEGMENT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@")


def check_port(p: str) -> str:
    if p == "" or (len(p) > 1 and p[0] == "0") or not p.isdigit() or not (1 <= int(p) <= 65535):
        raise ValueError("port")
    return p


def derive_audience(url: str):
    """Returns (audience, id_bytes) or raises ValueError. Refuses rather than normalises."""
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in url):
        raise ValueError("non-printable or non-ASCII")
    if "://" not in url:
        raise ValueError("no scheme")
    scheme, rest = url.split("://", 1)
    scheme = {"http": "http", "ws": "http", "https": "https", "wss": "https"}.get(scheme.lower())
    if scheme is None:
        raise ValueError("scheme")
    default_port = "80" if scheme == "http" else "443"
    if "/" not in rest:
        raise ValueError("no path")
    auth, path = rest.split("/", 1)
    if "@" in auth or auth == "":
        raise ValueError("userinfo or empty host")
    if auth.startswith("["):
        end = auth.find("]")
        if end < 0:
            raise ValueError("ipv6")
        host = auth[: end + 1].lower()
        lit = host[1:-1]
        if len(lit) < 2 or ":" not in lit or any(c not in HEX_LOWER and c not in ":." for c in lit):
            raise ValueError("ipv6")
        tail = auth[end + 1 :]
        port = ""
        if tail:
            if not tail.startswith(":"):
                raise ValueError("ipv6 tail")
            port = check_port(tail[1:])
    else:
        name, _, port = auth.partition(":")
        port = check_port(port) if ":" in auth else ""
        host = name.lower()
        for label in host.split("."):
            if label == "" or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label):
                raise ValueError("host")
    if "?" in path or "#" in path:
        raise ValueError("query or fragment")
    segments = path.split("/")
    for seg in segments:
        if seg in ("", ".", ".."):
            raise ValueError("segment")
        i = 0
        while i < len(seg):
            c = seg[i]
            if c == "%":
                if i + 2 >= len(seg) or any(h not in "0123456789abcdefABCDEF" for h in seg[i + 1 : i + 3]):
                    raise ValueError("escape")
                i += 3
                continue
            if c not in SEGMENT_CHARS:
                raise ValueError("segment char")
            i += 1
    if len(segments) < 2 or segments[-2] != "login":
        raise ValueError("not /login/<id>")
    ident = segments[-1]
    if len(ident) < 2 or len(ident) % 2 or any(c not in HEX_LOWER for c in ident):
        raise ValueError("id")
    audience = scheme + "://" + host + (":" + port if port and port != default_port else "")
    for seg in segments[:-2]:
        audience += "/" + seg
    return audience, bytes.fromhex(ident)


def req_json(ident: bytes, nonce: bytes, browser: bytes, scope: list[bytes], valid_for: int) -> dict:
    return {
        "id": ident.hex(),
        "nonce": nonce.hex(),
        "browser": browser.hex(),
        "scope": [s.hex() for s in scope],
        "valid_for": valid_for,
    }


def main() -> None:
    pub_p, pub_k, pub_x = pubkey_of(SEED_P), pubkey_of(SEED_K), pubkey_of(SEED_X)
    aud = AUDIENCE.encode()
    ident = bytes.fromhex("8f3c1d2e4b5a69780f1e2d3c4b5a6978")
    nonce = bytes([0xAA]) * 16
    scope = [b"read:projects", b"read:campaigns"]
    valid_for = 28800
    base_req = req_json(ident, nonce, pub_k, scope, valid_for)

    def bound(role=ROLE_LOGIN, a=aud, b=pub_k, i=ident, s=scope, v=valid_for):
        return binding(role, a, b, i, s, v)

    def proof(seed, role=ROLE_LOGIN, n=nonce, **kw):
        return sign(seed, possession_message(n, bound(role, **kw)), DOMAIN)

    # ---- login_binding --------------------------------------------------------------------
    unicode_scope = [b"read:projects", "publish:projekte/übersicht".encode()]
    long_scope = [f"read:item/{i}".encode() for i in range(300)]
    login_binding = [
        {"note": "the pinned layout: role ‖ u16 len ‖ audience ‖ browser[32] ‖ u16 len ‖ id ‖ u16 count ‖ (u16 len ‖ entry)* ‖ u32 valid_for (docs/login.md §3.2). Inputs {role, audience (utf-8 string), request{id, nonce, browser, scope[hex entries], valid_for}}; expected {\"ok\": hex} or {\"error\": true}. The nonce is not part of the binding. Oversize refusals (a field over the u16 prefix, a binding over the possession scheme's u16 field) are per-lane unit tests, not 130 KB vectors.",
         "name": "login-role", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": base_req, "result": {"ok": bound().hex()}},
        {"note": "the collect role differs in the first byte only.",
         "name": "collect-role", "role": ROLE_COLLECT, "audience": AUDIENCE, "request": base_req, "result": {"ok": bound(ROLE_COLLECT).hex()}},
        {"note": "an empty scope list is allowed by the scheme (count 0); the law may refuse it.",
         "name": "empty-scope", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, [], valid_for), "result": {"ok": bound(s=[]).hex()}},
        {"note": "scope entries are UTF-8 bytes, bound as given (NFC or not — the scheme does not normalise).",
         "name": "unicode-scope", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, unicode_scope, valid_for), "result": {"ok": bound(s=unicode_scope).hex()}},
        {"note": "300 entries: the count is u16, the order is the list's.",
         "name": "many-entries", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, long_scope, valid_for), "result": {"ok": bound(s=long_scope).hex()}},
        {"note": "valid_for is u32 big-endian; the maximum is representable.",
         "name": "max-validity", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, scope, 0xFFFFFFFF), "result": {"ok": bound(v=0xFFFFFFFF).hex()}},
        {"note": "a one-byte id is the minimum.",
         "name": "min-id", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(b"\x00", nonce, pub_k, scope, valid_for), "result": {"ok": bound(i=b"\x00").hex()}},
        {"note": "an unknown role is refused.", "name": "role-unknown-rejected", "role": 0x03, "audience": AUDIENCE, "request": base_req, "result": {"error": True}},
        {"note": "an empty audience is refused: it is the field that makes the proof unrelayable.", "name": "audience-empty-rejected", "role": ROLE_LOGIN, "audience": "", "request": base_req, "result": {"error": True}},
        {"note": "a control character in the audience is refused (it is displayed before signing).", "name": "audience-control-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE + "\n", "request": base_req, "result": {"error": True}},
        {"note": "the browser key must be exactly 32 bytes.", "name": "browser-short-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k[:31], scope, valid_for), "result": {"error": True}},
        {"note": "the browser key must be exactly 32 bytes.", "name": "browser-long-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k + b"\x00", scope, valid_for), "result": {"error": True}},
        {"note": "an empty id is refused.", "name": "id-empty-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(b"", nonce, pub_k, scope, valid_for), "result": {"error": True}},
        {"note": "an empty scope entry is refused (the list may be empty; an entry may not).", "name": "scope-entry-empty-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, [b"read:projects", b""], valid_for), "result": {"error": True}},
        {"note": "a control character (U+0007) in a scope entry is refused: the CLI prints entries verbatim.", "name": "scope-control-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, [b"read:\x07projects"], valid_for), "result": {"error": True}},
        {"note": "U+007F in a scope entry is refused.", "name": "scope-del-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, [b"read:\x7fprojects"], valid_for), "result": {"error": True}},
        {"note": "a scope entry that is not valid UTF-8 (0xff) is refused.", "name": "scope-not-utf8-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, [b"read:\xffprojects"], valid_for), "result": {"error": True}},
        {"note": "valid_for 0 is refused.", "name": "validity-zero-rejected", "role": ROLE_LOGIN, "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, scope, 0), "result": {"error": True}},
    ]

    # ---- login_prove ----------------------------------------------------------------------
    sig_login = proof(SEED_P)
    sig_login_empty_scope = proof(SEED_P, s=[])
    sig_login_unicode = proof(SEED_P, s=unicode_scope)
    login_prove = [
        {"note": "the login proof: possession by P in domain archon-login/1 over the request's nonce and the login binding — Ed25519ph, context-string archon-login/1, over 0x01 ‖ u16 len ‖ nonce ‖ u16 len ‖ binding. Inputs {seed, audience, request}; expected {\"ok\": 128 hex} or {\"error\": true}. Signatures derived with OpenSSL 3.2.4 — an implementation outside all three cores.",
         "name": "basic", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": base_req, "result": {"ok": sig_login.hex()}},
        {"note": "empty scope list proves.", "name": "empty-scope", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, [], valid_for), "result": {"ok": sig_login_empty_scope.hex()}},
        {"note": "unicode scope entries prove over their UTF-8 bytes.", "name": "unicode-scope", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, unicode_scope, valid_for), "result": {"ok": sig_login_unicode.hex()}},
        {"note": "a 15-byte nonce is refused by the possession scheme.", "name": "nonce-short-rejected", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": req_json(ident, nonce[:15], pub_k, scope, valid_for), "result": {"error": True}},
        {"note": "every binding refusal is a prove refusal: empty audience.", "name": "audience-empty-rejected", "seed": SEED_P.hex(), "audience": "", "request": base_req, "result": {"error": True}},
        {"note": "every binding refusal is a prove refusal: zero validity.", "name": "validity-zero-rejected", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": req_json(ident, nonce, pub_k, scope, 0), "result": {"error": True}},
        {"note": "a 31-byte seed is refused by the floor.", "name": "seed-short-rejected", "seed": SEED_P[:31].hex(), "audience": AUDIENCE, "request": base_req, "result": {"error": True}},
    ]

    # ---- login_verify ---------------------------------------------------------------------
    sig_other_domain = sign(SEED_P, possession_message(nonce, bound()), "archon-login/2")
    sig_raw = sign(SEED_P, possession_message(nonce, bound()), None, prehash=False)
    sig_ph_no_ctx = sign(SEED_P, possession_message(nonce, bound()), None, prehash=True)
    sig_bare_nonce = sign(SEED_P, nonce, DOMAIN)
    sig_collect_by_p_role = sign(SEED_P, possession_message(nonce, bound(ROLE_COLLECT)), DOMAIN)
    sig_binding_only = sign(SEED_P, bound(), DOMAIN)

    def v(name, note, pub=pub_p, a=AUDIENCE, req=None, sig=None, valid=False):
        return {"note": note, "name": name, "pubkey": pub.hex(), "audience": a, "request": req or base_req, "sig": (sig or sig_login).hex(), "valid": valid}

    login_verify = [
        v("basic", "verify the login proof: inputs {pubkey, audience, request, sig}; expected {valid: bool}. Total: every shape failure is false. The substitutions are the content — each bound field must bind, and no signature of another shape is a proof.", valid=True),
        v("wrong-audience", "the same proof at another audience is not a proof there — the relay case.", a="https://evil.example/api"),
        v("audience-trailing-slash", "the audience is bound byte-for-byte: a trailing slash is a different audience (the CLI trims it before binding; the server's configuration must match).", a=AUDIENCE + "/"),
        v("wrong-browser", "another browser key.", req=req_json(ident, nonce, pub_x, scope, valid_for)),
        v("wrong-id", "another request id.", req=req_json(bytes.fromhex("00" * 16), nonce, pub_k, scope, valid_for)),
        v("wrong-nonce", "another nonce.", req=req_json(ident, bytes([0xAB]) * 16, pub_k, scope, valid_for)),
        v("scope-reordered", "the scope list is ordered.", req=req_json(ident, nonce, pub_k, list(reversed(scope)), valid_for)),
        v("scope-entry-changed", "one entry changed.", req=req_json(ident, nonce, pub_k, [b"read:projects", b"write:campaigns"], valid_for)),
        v("scope-entry-added", "one entry added.", req=req_json(ident, nonce, pub_k, scope + [b"admin"], valid_for)),
        v("scope-entry-removed", "one entry removed.", req=req_json(ident, nonce, pub_k, scope[:1], valid_for)),
        v("validity-changed", "valid_for changed by one second.", req=req_json(ident, nonce, pub_k, scope, valid_for + 1)),
        v("wrong-key", "another key's proof does not verify under P.", pub=pub_x),
        v("other-domain", "a possession proof in archon-login/2 is not a login proof.", sig=sig_other_domain),
        v("raw-signature", "a plain Ed25519 signature over the possession message is not a proof (no context).", sig=sig_raw),
        v("ph-without-context", "Ed25519ph without the context is not a proof.", sig=sig_ph_no_ctx),
        v("bare-nonce", "a signature over the nonce alone is not a proof.", sig=sig_bare_nonce),
        v("binding-without-possession-layout", "a signature over the binding without the possession layout is not a proof.", sig=sig_binding_only),
        v("collect-role", "the collect-role proof, even by P, is not a login proof.", sig=sig_collect_by_p_role),
        v("sig-truncated", "63 bytes.", sig=sig_login[:63]),
        v("sig-flipped", "one bit flipped.", sig=bytes([sig_login[0] ^ 0x01]) + sig_login[1:]),
        v("pubkey-short", "31-byte key.", pub=pub_p[:31]),
        v("nonce-short", "a 15-byte nonce is false even with a matching signature shape.", req=req_json(ident, nonce[:15], pub_k, scope, valid_for)),
        v("scope-control", "a control character in the request is false, not an error.", req=req_json(ident, nonce, pub_k, [b"read:\x07projects"], valid_for)),
    ]

    # ---- login_collect_prove --------------------------------------------------------------
    sig_collect = proof(SEED_K, ROLE_COLLECT)
    login_collect_prove = [
        {"note": "the collect proof: possession by K (the key the request names as browser) in archon-login/1 over the nonce and the collect binding (role 0x02). Inputs {seed, audience, request}; expected {\"ok\": 128 hex} or {\"error\": true}. Derived with OpenSSL 3.2.4.",
         "name": "basic", "seed": SEED_K.hex(), "audience": AUDIENCE, "request": base_req, "result": {"ok": sig_collect.hex()}},
        {"note": "a seed whose public key is not the request's browser is refused: only K may collect.", "name": "not-the-browser-key-rejected", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": base_req, "result": {"error": True}},
        {"note": "binding refusals apply: empty audience.", "name": "audience-empty-rejected", "seed": SEED_K.hex(), "audience": "", "request": base_req, "result": {"error": True}},
        {"note": "a short nonce is refused.", "name": "nonce-short-rejected", "seed": SEED_K.hex(), "audience": AUDIENCE, "request": req_json(ident, nonce[:15], pub_k, scope, valid_for), "result": {"error": True}},
    ]

    # ---- login_collect_verify -------------------------------------------------------------
    sig_login_by_k = proof(SEED_K)

    def cv(name, note, a=AUDIENCE, req=None, sig=None, valid=False):
        return {"note": note, "name": name, "audience": a, "request": req or base_req, "sig": (sig or sig_collect).hex(), "valid": valid}

    login_collect_verify = [
        cv("basic", "verify the collect proof under the request's own browser key: inputs {audience, request, sig}; expected {valid: bool}. Total.", valid=True),
        cv("wrong-audience", "another audience.", a="https://evil.example/api"),
        cv("login-role", "K's login-role proof is not a collect proof.", sig=sig_login_by_k),
        cv("wrong-browser", "the request names another browser key, so the proof is checked under that key and fails.", req=req_json(ident, nonce, pub_x, scope, valid_for)),
        cv("validity-changed", "valid_for changed.", req=req_json(ident, nonce, pub_k, scope, valid_for + 1)),
        cv("sig-truncated", "63 bytes.", sig=sig_collect[:63]),
    ]

    # ---- login_audience -------------------------------------------------------------------
    hid = ident.hex()

    def a(name, url, note):
        try:
            aud, i = derive_audience(url)
            return {"note": note, "name": name, "url": url, "result": {"ok": {"audience": aud, "id": i.hex()}}}
        except ValueError:
            return {"note": note, "name": name, "url": url, "result": {"error": True}}

    login_audience = [
        a("basic", f"https://dawn.example/api/login/{hid}", 'derive_audience (docs/login.md §2.1): input {url}; expected {"ok": {audience, id hex}} or {"error": true}. The grammar is accepted exactly and everything else is REFUSED, never normalised — one URL yields one audience in every lane. The id is returned decoded.'),
        a("default-port-https", f"https://dawn.example:443/api/login/{hid}", "an explicit default port is omitted from the audience."),
        a("default-port-http", f"http://localhost:80/login/{hid}", "80 is http's default."),
        a("non-default-port", f"http://localhost:8080/login/{hid}", "a non-default port is kept as written."),
        a("uppercase-scheme-host", f"HTTPS://Dawn.Example/API/login/{hid}", "scheme and host are lowercased; path segments keep their case."),
        a("wss-folds", f"wss://dawn.example/api/login/{hid}", "wss folds to https."),
        a("ws-default-port", f"ws://dawn.example:80/login/{hid}", "ws folds to http, whose default port 80 is then omitted."),
        a("wss-port-80-kept", f"wss://dawn.example:80/login/{hid}", "after the fold to https, 80 is not the default and is kept."),
        a("percent-escape-kept", f"https://dawn.example/a/b%2Fc/v1/login/{hid}", "a well-formed percent-escape is kept as written, never decoded."),
        a("ipv6-non-default", f"https://[::1]:8443/api/login/{hid}", "an IPv6 literal keeps its brackets; the port is kept."),
        a("ipv6-default-port", f"https://[2001:DB8::1]:443/login/{hid}", "an IPv6 literal is lowercased; the default port is omitted."),
        a("ipv4", f"https://10.0.0.7/login/{hid}", "an IPv4 host is a reg-name."),
        a("no-base-path", f"https://dawn.example/login/{hid}", "a service mounted at its origin: the audience has no path."),
        a("sub-delims-in-segment", f"https://dawn.example/a:b@c!$&'()*+,;=/login/{hid}", "RFC 3986 pchar is accepted as written."),
        a("min-id", "https://dawn.example/login/00", "a one-byte id is the minimum."),
        a("no-scheme-rejected", f"dawn.example/api/login/{hid}", "no scheme."),
        a("scheme-rejected", f"ftp://dawn.example/login/{hid}", "only http(s) and ws(s)."),
        a("no-path-rejected", "https://dawn.example", "no path at all."),
        a("no-id-rejected", "https://dawn.example/login", "the penultimate segment must be `login` and an id must follow."),
        a("penultimate-rejected", f"https://dawn.example/api/{hid}", "the penultimate segment is not `login`."),
        a("trailing-slash-rejected", f"https://dawn.example/api/login/{hid}/", "a trailing slash is an empty segment — refused, not trimmed."),
        a("empty-segment-rejected", f"https://dawn.example//login/{hid}", "`//` is an empty segment."),
        a("dot-segment-rejected", f"https://dawn.example/./login/{hid}", "`.` is refused, not resolved."),
        a("dotdot-segment-rejected", f"https://dawn.example/../login/{hid}", "`..` is refused, not resolved."),
        a("userinfo-rejected", f"https://user@dawn.example/login/{hid}", "userinfo is refused — measured: net/url and WHATWG drop it, a hand-written split reads it as the host (lane B, 2026-09-10)."),
        a("userinfo-password-rejected", f"https://user:pass@dawn.example/api/login/{hid}", "userinfo with a password is refused; a lenient parser would also swallow the base path."),
        a("query-rejected", f"https://dawn.example/login/{hid}?x=1", "a query is refused."),
        a("fragment-rejected", f"https://dawn.example/login/{hid}#f", "a fragment is refused."),
        a("id-uppercase-rejected", "https://dawn.example/api/login/8F3C", "the id is lowercase hex — uppercase is refused, not folded."),
        a("id-odd-rejected", "https://dawn.example/api/login/8f3", "odd length."),
        a("id-not-hex-rejected", "https://dawn.example/api/login/zz", "not hex."),
        a("id-empty-rejected", "https://dawn.example/api/login/", "an empty id is an empty segment."),
        a("port-zero-rejected", f"https://dawn.example:0/login/{hid}", "port 0."),
        a("port-too-big-rejected", f"https://dawn.example:65536/login/{hid}", "port 65536."),
        a("port-leading-zero-rejected", f"https://dawn.example:0443/login/{hid}", "a leading zero is refused, not normalised to 443."),
        a("port-not-digits-rejected", f"https://dawn.example:4a3/login/{hid}", "a non-digit port."),
        a("port-empty-rejected", f"https://dawn.example:/login/{hid}", "a colon with no port."),
        a("host-trailing-dot-rejected", f"https://dawn.example./login/{hid}", "an empty label."),
        a("host-underscore-rejected", f"https://dawn_example/login/{hid}", "a byte outside the host alphabet."),
        a("host-non-ascii-rejected", f"https://dawn.exämple/login/{hid}", "non-ASCII anywhere is refused — an IDN must be given as punycode."),
        a("ipv6-unterminated-rejected", f"https://[::1/login/{hid}", "unterminated literal."),
        a("ipv6-zone-rejected", f"https://[fe80::1%25eth0]/login/{hid}", "a zone id is refused."),
        a("space-rejected", f"https://dawn.example/a b/login/{hid}", "whitespace is refused."),
        a("escape-malformed-rejected", f"https://dawn.example/a%2/login/{hid}", "a malformed percent-escape."),
        a("escape-not-hex-rejected", f"https://dawn.example/a%zz/login/{hid}", "a malformed percent-escape."),
        a("empty-host-rejected", f"https:///login/{hid}", "no host."),
        a("empty-rejected", "", "nothing."),
    ]

    doc = {
        "version": 1,
        "note": "archon login-scheme conformance vectors (docs/login.md): the audience derivation (§2.1: one grammar, refused not normalised), the binding both proofs are made over, the person's login proof, the browser's collect proof, and their verification — all in the SDK's possession scheme, domain archon-login/1. Scope entries are given as hex so that a non-UTF-8 entry can be a case; a lane decodes them before calling the scheme (a failed decode is the same refusal). Audience is a UTF-8 string. Entropy (nonce, id, keys) and time (valid_for) are case INPUTS — the scheme never sources them — which is what makes every output deterministic and pinnable. Signatures derived with OpenSSL 3.2.4, outside all three cores (vectors/tools/login-vectors.py).",
        "login_audience": login_audience,
        "login_binding": login_binding,
        "login_prove": login_prove,
        "login_verify": login_verify,
        "login_collect_prove": login_collect_prove,
        "login_collect_verify": login_collect_verify,
    }
    out = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(out.encode("utf-8"))  # never the console codepage


if __name__ == "__main__":
    main()
