#!/usr/bin/env python3
"""Derive vectors/request.json OUTSIDE the three cores.

The enrollment binding and the possession message are assembled by hand from the layouts in
docs/request.md §6 — this file is a fourth, deliberately naive implementation of them — and every
signature is produced by OpenSSL 3.2.x (`pkeyutl -rawin -pkeyopt instance:Ed25519ph -pkeyopt
context-string:<domain>`), never by a core. A vector copied out of a core pins that core's bugs;
a vector derived from the standard lets all three cores be wrong together and be caught
(vectors/README.md, "Authoring").

The profiles are PROVISIONAL (ADR 0010 §8): these vectors pin the provisional bytes so the three
lanes agree on them while the failure tests are built, and they change if the wire does.

Run from the repo root: `python vectors/tools/request-vectors.py > vectors/request.json`.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

ENROLL_DOMAIN = "archon-enroll/1"
REQUEST_DOMAIN = "archon-request/1"
REQUEST_TAG = "archon-request/1"
LABEL = "archon"
ENROLL_VERSION = 0x01
POSSESSION_TAG = 0x01
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")  # RFC 8410, Ed25519 seed

SEED_N = bytes([0x44]) * 32  # the new key, the one being enrolled
SEED_P = bytes([0x11]) * 32  # an existing key that is NOT the new one
SEED_X = bytes([0x55]) * 32  # a third key
AUDIENCE = "https://dawn.example/api"


def u16(n: int) -> bytes:
    assert 0 <= n <= 0xFFFF
    return n.to_bytes(2, "big")


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


def enroll_binding(purpose: bytes, audience: bytes, transaction: bytes, new_key: bytes, digest: bytes) -> bytes:
    """docs/request.md §6, by hand."""
    return (
        bytes([ENROLL_VERSION])
        + u16(len(purpose)) + purpose
        + u16(len(audience)) + audience
        + u16(len(transaction)) + transaction
        + new_key
        + digest
    )


def possession_message(nonce: bytes, bound: bytes) -> bytes:
    return bytes([POSSESSION_TAG]) + u16(len(nonce)) + nonce + u16(len(bound)) + bound



# ---- the request profile (docs/request.md §3–§5), by hand ------------------------------------

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def origin_of(audience: str) -> str:
    scheme, rest = audience.split("://", 1)
    return scheme + "://" + rest.split("/", 1)[0]


def content_digest(body: bytes) -> str:
    return "sha-256=:" + b64(hashlib.sha256(body).digest()) + ":"


def inner_list(names, created, expires, nonce: bytes, keyid: str, tag=REQUEST_TAG, params=None) -> str:
    """The Signature-Input inner list in its one spelling, or `params` verbatim when a case
    needs a deliberately wrong parameter string."""
    comps = "(" + " ".join('"' + n + '"' for n in names) + ")"
    if params is None:
        params = f';created={created};expires={expires};nonce="{b64url(nonce)}";keyid="{keyid}";tag="{tag}"'
    return comps + params


def signature_base(components, inner: str) -> str:
    return "".join(f'"{n}": {v}\n' for n, v in components) + '"@signature-params": ' + inner


def client(seed, method, audience, target, body, content_type, declared, created, expires, nonce,
           names=None, params=None, sign_seed=None, sig_domain=REQUEST_DOMAIN, prehash=True, keyid=None):
    """A naive client: returns (base, the four headers archon adds). `names` reorders or
    changes the coverage, `params` replaces the parameter string, `sign_seed` signs with another
    key than the keyid names — each still signs exactly the base it builds, so a refusal can
    only come from the rule the case breaks."""
    keyid = keyid or "ed25519:" + pubkey_of(seed).hex()
    digest = content_digest(body)
    values = {"@method": method, "@target-uri": origin_of(audience) + target,
              "archon-audience": audience, "content-digest": digest}
    order = ["@method", "@target-uri", "archon-audience", "content-digest"]
    if content_type is not None:
        values["content-type"] = content_type.strip(" \t")
        order.append("content-type")
    for n, v in declared:
        values[n] = v.strip(" \t")
        order.append(n)
    names = names or order
    components = [(n, values.get(n, "")) for n in names]
    inner = inner_list(names, created, expires, nonce, keyid, params=params)
    base = signature_base(components, inner)
    sig = sign(sign_seed or seed, base.encode(), sig_domain, prehash=prehash)
    return base, {
        "archon-audience": audience,
        "content-digest": digest,
        "signature-input": LABEL + "=" + inner,
        "signature": LABEL + "=:" + b64(sig) + ":",
    }

def req_json(nonce: bytes, transaction: bytes, purpose: bytes, new_key: bytes, digest: bytes) -> dict:
    return {
        "nonce": nonce.hex(),
        "transaction": transaction.hex(),
        "purpose": purpose.hex(),
        "new_key": new_key.hex(),
        "intent_digest": digest.hex(),
    }


def request_families() -> dict:
    """request_sign and request_verify (docs/request.md §3–§5, §7 steps 1–7)."""
    seed, other = SEED_N, SEED_X
    keyid = "ed25519:" + pubkey_of(seed).hex()
    T0, T1 = 1789034640, 1789034700
    nonce = bytes(range(16))
    body = b'{"name":"thing"}'
    target = "/api/v1/things?x=1"
    ctype = "application/json"
    idem = ("idempotency-key", "k-123")

    def sign_case(name, note, method="POST", audience=AUDIENCE, tgt=target, b=body, ct=ctype, declared=(),
                  created=T0, expires=T1, n=nonce, s=seed, error=False):
        case = {"note": note, "name": name, "seed": s.hex(), "method": method, "audience": audience,
                "request_target": tgt, "body": b.hex(), "content_type": ct, "declared": [list(d) for d in declared],
                "created": created, "expires": expires, "nonce": n.hex()}
        if error:
            case["result"] = {"error": True}
        else:
            base, headers = client(s, method, audience, tgt, b, ct, list(declared), created, expires, n)
            case["result"] = {"ok": {"base": base, "headers": headers}}
        return case

    request_sign = [
        sign_case("basic", 'the client (docs/request.md §3–§4): inputs {seed, method, audience, request_target, body (hex), content_type (string or null), declared [[name, value]] in the product\'s order, created, expires, nonce (hex)}; expected {"ok": {base, headers}} — the RFC 9421 signature base as text, and the four headers archon adds, named in lowercase — or {"error": true}. Every signature is Ed25519ph in context archon-request/1 over the base, derived with OpenSSL 3.2.4 outside the cores. PROVISIONAL (ADR 0010 §8).'),
        sign_case("empty-body-get", "a GET with no body and no Content-Type: the digest is the empty string's, and content-type is not covered.", method="GET", tgt="/api/v1/things", b=b"", ct=None),
        sign_case("declared-headers", "product-declared headers are covered in the product's order, after content-type.", declared=[idem, ("x-tenant", "acme")]),
        sign_case("target-kept-verbatim", "the request-target is covered exactly as sent: an escape is not decoded, query order and duplicates are kept.", tgt="/api/a%2Fb?b=2&a=1&a=1"),
        sign_case("values-trimmed", "a covered value loses its leading and trailing SP and HTAB; inner whitespace stays.", ct=" \tapplication/json; charset=utf-8\t ", declared=[("idempotency-key", "  k 1  ")]),
        sign_case("audience-with-port", "an audience with a port: the origin keeps it.", audience="http://localhost:8080"),
        sign_case("audience-at-origin", "an audience with no path: the origin is the audience.", audience="https://dawn.example", tgt="/v1/things"),
        sign_case("nonce-64", "64 bytes is the nonce's maximum.", n=bytes(range(64))),
        sign_case("method-case-kept", "the method is a token whose case is kept.", method="patch"),
        sign_case("method-empty-rejected", "an empty method.", method="", error=True),
        sign_case("method-space-rejected", "a space is not a tchar.", method="GE T", error=True),
        sign_case("audience-trailing-slash-rejected", "an audience ending in `/` is refused, not trimmed.", audience=AUDIENCE + "/", error=True),
        sign_case("audience-scheme-rejected", "only http and https.", audience="ftp://dawn.example/api", error=True),
        sign_case("audience-query-rejected", "an audience with a query.", audience=AUDIENCE + "?x=1", error=True),
        sign_case("audience-userinfo-rejected", "an authority with userinfo.", audience="https://user@dawn.example/api", error=True),
        sign_case("audience-empty-authority-rejected", "no authority.", audience="https:///api", error=True),
        sign_case("target-absolute-rejected", "absolute form is not origin form.", tgt="https://dawn.example/api/v1/things", error=True),
        sign_case("target-asterisk-rejected", "asterisk form.", tgt="*", error=True),
        sign_case("target-space-rejected", "a space in the target.", tgt="/api/v1/a b", error=True),
        sign_case("target-fragment-rejected", "a fragment is never part of a request-target.", tgt="/api/v1/things#x", error=True),
        sign_case("target-non-ascii-rejected", "a byte above 0x7E.", tgt="/api/v1/ä", error=True),
        sign_case("target-too-long-rejected", "8193 bytes.", tgt="/" + "a" * 8192, error=True),
        sign_case("declared-uppercase-rejected", "a declared name is lowercase.", declared=[("Idempotency-Key", "k")], error=True),
        sign_case("declared-reserved-rejected", "`signature` cannot be a declared header.", declared=[("signature", "x")], error=True),
        sign_case("declared-content-type-rejected", "content-type is covered by its own rule, never declared.", declared=[("content-type", "x")], error=True),
        sign_case("declared-duplicate-rejected", "a declared name given twice.", declared=[idem, idem], error=True),
        sign_case("declared-value-lf-rejected", "a line feed in a covered value.", declared=[("idempotency-key", "k\nx")], error=True),
        sign_case("declared-value-empty-rejected", "an empty covered value.", declared=[("idempotency-key", "  ")], error=True),
        sign_case("declared-value-non-ascii-rejected", "a byte above 0x7E in a covered value.", declared=[("idempotency-key", "kä")], error=True),
        sign_case("content-type-control-rejected", "a control character in content-type.", ct="application/json\x01", error=True),
        sign_case("nonce-15-rejected", "15 bytes is under the floor.", n=bytes(15), error=True),
        sign_case("nonce-65-rejected", "65 bytes is over the bound.", n=bytes(65), error=True),
        sign_case("created-equals-expires-rejected", "created must be before expires.", created=T0, expires=T0, error=True),
        sign_case("expires-16-digits-rejected", "an integer over 15 digits.", expires=10**15, error=True),
        sign_case("seed-short-rejected", "a 31-byte seed.", s=seed[:31], error=True),
    ]

    # ---- request_verify -------------------------------------------------------------------
    policy = {"audience": AUDIENCE, "declared": ["idempotency-key", "x-tenant"], "max_lifetime": 300, "skew": 30}
    now = T0 + 10

    def signed(**kw):
        """The base valid request: POST with content-type and a covered idempotency-key."""
        args = dict(method="POST", audience=AUDIENCE, target=target, body=body, content_type=ctype,
                    declared=[idem], created=T0, expires=T1, nonce=nonce)
        args.update(kw)
        _, h = client(seed, args["method"], args["audience"], args["target"], args["body"], args["content_type"],
                      args["declared"], args["created"], args["expires"], args["nonce"],
                      names=kw.get("names"), params=kw.get("params"), sign_seed=kw.get("sign_seed"),
                      sig_domain=kw.get("sig_domain", REQUEST_DOMAIN), prehash=kw.get("prehash", True),
                      keyid=kw.get("keyid"))
        return h

    def received(h, method="POST", tgt=target, b=body, ct=ctype, extra=(), drop=(), names_case=str.title,
                 declared=(idem,)):
        headers = [["Host", "dawn.example"]]
        if ct is not None:
            headers.append(["Content-Type", ct])
        for n, v in declared:
            headers.append([n, v])
        for n, v in h.items():
            if n not in drop:
                headers.append([names_case(n), v])
        headers += [list(e) for e in extra]
        return {"method": method, "request_target": tgt, "headers": headers, "body": b.hex()}

    ok = {"principal": keyid, "created": T0, "expires": T1, "nonce": nonce.hex(), "target_uri": origin_of(AUDIENCE) + target}
    H = signed()

    def v(name, note, req, pol=None, t=now, result=None):
        return {"note": note, "name": name, "policy": pol or policy, "now": t, "request": req,
                "result": result if result is not None else {"error": True}}

    def edit(h, key, value):
        out = dict(h)
        out[key] = value
        return out

    si = H["signature-input"]
    sig_value = H["signature"]
    sig_bytes = base64.b64decode(sig_value[len("archon=:"):-1])
    nonce_text = b64url(nonce)
    request_verify = [
        v("basic", 'the verifier (docs/request.md §3.1, §5, §7 steps 1–7; replay is the server\'s): inputs {policy {audience, declared, max_lifetime, skew}, now, request {method, request_target, headers [[name, value]] as received, body (hex)}}; expected {"ok": {principal, created, expires, nonce (hex), target_uri}} or {"error": true}. Each refusal below breaks exactly one rule; where the case can be signed correctly it is, so the refusal comes from that rule and not from a bad signature. PROVISIONAL (ADR 0010 §8).',
          received(H), result={"ok": ok}),
        v("header-names-any-case", "header names are matched without regard to case.", received(H, names_case=str.upper), result={"ok": ok}),
        v("names-fold-ascii-only", "a header named with U+212A KELVIN SIGN is not idempotency-key: names fold ASCII case only, so this is an unrelated header and not a second covered field.",
          received(H, extra=[["Idempotency-Key", "k-999"]]), result={"ok": ok}),
        v("host-is-not-authoritative", "the Host and X-Forwarded-Host the request carries change nothing: @target-uri comes from the configured audience.",
          received(H, extra=[["X-Forwarded-Host", "evil.example"], ["Forwarded", "host=evil.example"]]), result={"ok": ok}),
        v("empty-body-get", "a GET with no body and no Content-Type.",
          received(signed(method="GET", target="/api/v1/things", body=b"", content_type=None, declared=[]), method="GET", tgt="/api/v1/things", b=b"", ct=None, declared=()),
          result={"ok": dict(ok, target_uri=origin_of(AUDIENCE) + "/api/v1/things")}),
        v("declared-absent-uncovered", "a declared header the request does not carry is not covered.",
          received(signed(declared=[]), declared=()), result={"ok": ok}),
        v("fresh-at-earliest", "now = created − skew is the earliest acceptable time.", received(H), t=T0 - 30, result={"ok": ok}),
        v("fresh-at-latest", "now = expires + skew − 1 is the latest acceptable time.", received(H), t=T1 + 30 - 1, result={"ok": ok}),
        v("lifetime-at-max", "expires − created = max_lifetime is accepted.",
          received(signed(expires=T0 + 300)), result={"ok": dict(ok, expires=T0 + 300)}),
        # parsing (§5)
        v("signature-input-missing", "no Signature-Input.", received(H, drop=("signature-input",))),
        v("signature-missing", "no Signature.", received(H, drop=("signature",))),
        v("signature-input-twice", "Signature-Input twice.", received(H, extra=[["Signature-Input", si]])),
        v("signature-twice", "Signature twice.", received(H, extra=[["Signature", sig_value]])),
        v("label-other", "another label.", received(edit(edit(H, "signature-input", "sig1=" + si[7:]), "signature", "sig1=" + sig_value[7:]))),
        v("second-member", "a second dictionary member.", received(edit(H, "signature-input", si + ", other=" + si[7:]))),
        v("params-reordered", "expires before created.",
          received(signed(params=f';expires={T1};created={T0};nonce="{nonce_text}";keyid="{keyid}";tag="{REQUEST_TAG}"'))),
        v("param-alg", "an alg parameter is refused: the registered ed25519 is pure Ed25519.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text}";keyid="{keyid}";tag="{REQUEST_TAG}";alg="ed25519"'))),
        v("param-unknown", "an unknown parameter.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text}";keyid="{keyid}";tag="{REQUEST_TAG}";foo=1'))),
        v("int-leading-zero", "created with a leading zero.",
          received(signed(params=f';created=0{T0};expires={T1};nonce="{nonce_text}";keyid="{keyid}";tag="{REQUEST_TAG}"'))),
        v("int-16-digits", "expires over 15 digits.",
          received(signed(params=f';created={T0};expires=1000000000000000;nonce="{nonce_text}";keyid="{keyid}";tag="{REQUEST_TAG}"'))),
        v("nonce-padded", "padding is not the one spelling of base64url.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text}==";keyid="{keyid}";tag="{REQUEST_TAG}"'))),
        v("nonce-non-canonical", "unused bits set in the last character.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text[:-1]}x";keyid="{keyid}";tag="{REQUEST_TAG}"'))),
        v("nonce-15-bytes", "15 bytes is under the floor.", received(signed(nonce=bytes(15)))),
        v("keyid-uppercase-hex", "keyid is the canonical principal: the hex is lowercase, so a key decoder that accepts either case is not enough.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text}";keyid="ed25519:{pubkey_of(seed).hex().upper()}";tag="{REQUEST_TAG}"'))),
        v("keyid-uppercase-prefix", "the prefix is `ed25519:` exactly.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text}";keyid="{keyid.upper()}";tag="{REQUEST_TAG}"'))),
        v("tag-other", "another profile tag.",
          received(signed(params=f';created={T0};expires={T1};nonce="{nonce_text}";keyid="{keyid}";tag="archon-request/2"'))),
        v("space-after-semicolon", "whitespace other than the single spaces between components.",
          received(signed(params=f'; created={T0};expires={T1};nonce="{nonce_text}";keyid="{keyid}";tag="{REQUEST_TAG}"'))),
        v("component-unknown", "a derived component the profile does not know.",
          received(signed(names=["@method", "@target-uri", "archon-audience", "content-digest", "content-type", "idempotency-key", "@path"]))),
        v("signature-not-canonical-base64", "padding missing.", received(edit(H, "signature", "archon=:" + b64(sig_bytes).rstrip("=") + ":"))),
        v("signature-63-bytes", "63 bytes.", received(edit(H, "signature", "archon=:" + b64(sig_bytes[:63]) + ":"))),
        v("digest-other-algorithm", "only sha-256.", received(edit(H, "content-digest", "sha-512=:" + b64(hashlib.sha512(body).digest()) + ":"))),
        v("digest-two-members", "one member only.", received(edit(H, "content-digest", H["content-digest"] + ", sha-512=:" + b64(hashlib.sha512(body).digest()) + ":"))),
        # coverage (§3.1)
        v("coverage-reordered", "a correctly signed request whose coverage is not §3's order.",
          received(signed(names=["@method", "archon-audience", "@target-uri", "content-digest", "content-type", "idempotency-key"]))),
        v("content-type-uncovered", "Content-Type present but not covered.",
          received(signed(names=["@method", "@target-uri", "archon-audience", "content-digest", "idempotency-key"]))),
        v("declared-uncovered", "a declared header present but not covered.",
          received(signed(names=["@method", "@target-uri", "archon-audience", "content-digest", "content-type"]))),
        v("covers-absent-header", "a covered declared header the request does not carry.",
          received(signed(declared=[idem, ("x-tenant", "acme")]))),
        v("covers-undeclared-header", "a header the product did not declare is covered.",
          received(signed(declared=[idem, ("user-agent", "agent/1")]), declared=(idem, ("user-agent", "agent/1")))),
        v("covered-header-twice", "a covered field that appears more than once.", received(H, extra=[["Idempotency-Key", "k-123"]])),
        v("content-type-twice", "Content-Type twice.", received(H, extra=[["Content-Type", ctype]])),
        v("audience-header-twice", "Archon-Audience twice.", received(H, extra=[["Archon-Audience", AUDIENCE]])),
        # the checks (§7)
        v("audience-mismatch", "a request signed for another audience is refused by the echo, whatever the signature.",
          received(signed(audience="https://evil.example/api"))),
        v("audience-trailing-slash", "a request properly signed with the audience plus a trailing slash: the echo is compared byte for byte.",
          received(signed(audience=AUDIENCE + "/"))),
        v("audience-same-origin-other-path", "a request properly signed for another service on the same origin: its @target-uri is identical, so only the echo refuses it.",
          received(signed(audience="https://dawn.example/other"))),
        v("body-changed", "the digest is recomputed over the received body.", received(H, b=b'{"name":"other"}')),
        v("body-dropped", "the body removed: the digest no longer matches.", received(H, b=b"")),
        v("method-changed", "the method as received is the one covered.", received(H, method="PUT")),
        v("target-changed", "another query.", received(H, tgt="/api/v1/things?x=2")),
        v("target-decoded", "a request signed over an escape and received decoded.",
          received(signed(target="/api/a%2Fb"), tgt="/api/a/b")),
        v("target-absolute-form", "a received request-target that is not origin form.",
          received(H, tgt="https://dawn.example" + target)),
        v("covered-value-changed", "the idempotency key changed.", received(H, declared=(("idempotency-key", "k-124"),))),
        v("content-type-changed", "Content-Type changed.", received(H, ct="text/plain")),
        v("content-type-non-ascii", "a covered value with a byte above 0x7E.",
          received(signed(content_type="text/plain; x=ä"), ct="text/plain; x=ä")),
        v("signed-by-another-key", "keyid names one key, the signature is another's.", received(signed(sign_seed=other))),
        v("raw-signature", "a plain Ed25519 signature over the base.", received(signed(prehash=False, sig_domain=None))),
        v("ph-without-context", "Ed25519ph without the context.", received(signed(sig_domain=None))),
        v("other-domain", "the base signed in archon-login/1.", received(signed(sig_domain="archon-login/1"))),
        v("signature-flipped", "one bit flipped.",
          received(edit(H, "signature", "archon=:" + b64(bytes([sig_bytes[0] ^ 1]) + sig_bytes[1:]) + ":"))),
        # freshness (§7 step 6)
        v("expired", "now = expires + skew.", received(H), t=T1 + 30),
        v("not-yet-valid", "now = created − skew − 1.", received(H), t=T0 - 31),
        v("lifetime-over-max", "expires − created = max_lifetime + 1.", received(signed(expires=T0 + 301))),
        v("policy-max-lifetime-zero", "a policy with max_lifetime 0 is refused.", received(H), pol=dict(policy, max_lifetime=0)),
    ]
    return {"request_sign": request_sign, "request_verify": request_verify}


def main() -> None:
    pub_n, pub_p, pub_x = pubkey_of(SEED_N), pubkey_of(SEED_P), pubkey_of(SEED_X)
    aud = AUDIENCE.encode()
    nonce = bytes([0xCC]) * 16
    txn = bytes.fromhex("7a1b2c3d4e5f60718293a4b5c6d7e8f9")
    purpose = b"add-key"
    # The service's own SHA-256 of its immutable intent bytes; archon only binds the 32 bytes.
    digest = bytes.fromhex("5f2e1d0c3b4a59687766554433221100ffeeddccbbaa99887766554433221100")
    base_req = req_json(nonce, txn, purpose, pub_n, digest)

    def bound(p=purpose, a=aud, t=txn, k=pub_n, d=digest):
        return enroll_binding(p, a, t, k, d)

    def proof(seed=SEED_N, n=nonce, **kw):
        return sign(seed, possession_message(n, bound(**kw)), ENROLL_DOMAIN)

    def rj(n=nonce, t=txn, p=purpose, k=pub_n, d=digest):
        return req_json(n, t, p, k, d)

    # ---- enroll_binding -------------------------------------------------------------------
    unicode_purpose = "schlüssel-hinzufügen".encode()
    p255 = b"p" * 255
    t255 = bytes(range(255))
    enroll_binding_cases = [
        {"note": "the pinned layout: version 0x01 ‖ u16 len ‖ purpose ‖ u16 len ‖ audience ‖ u16 len ‖ transaction ‖ new_key[32] ‖ intent_digest[32] (docs/request.md §6, PROVISIONAL). Inputs {audience (utf-8 string), request{nonce, transaction, purpose (hex), new_key, intent_digest}}; expected {\"ok\": hex} or {\"error\": true}. The nonce is not part of the binding. Oversize audience refusals (a binding over the possession scheme's u16 field) are per-lane unit tests, not 64 KB vectors.",
         "name": "basic", "audience": AUDIENCE, "request": base_req, "result": {"ok": bound().hex()}},
        {"note": "the purpose is UTF-8 bytes, bound as given (no normalisation).",
         "name": "unicode-purpose", "audience": AUDIENCE, "request": rj(p=unicode_purpose), "result": {"ok": bound(p=unicode_purpose).hex()}},
        {"note": "255 bytes is the purpose's maximum.",
         "name": "purpose-255", "audience": AUDIENCE, "request": rj(p=p255), "result": {"ok": bound(p=p255).hex()}},
        {"note": "a one-byte transaction id is the minimum; it is opaque bytes.",
         "name": "transaction-min", "audience": AUDIENCE, "request": rj(t=b"\x00"), "result": {"ok": bound(t=b"\x00").hex()}},
        {"note": "255 bytes is the transaction id's maximum.",
         "name": "transaction-255", "audience": AUDIENCE, "request": rj(t=t255), "result": {"ok": bound(t=t255).hex()}},
        {"note": "a 256-byte purpose is refused.", "name": "purpose-256-rejected", "audience": AUDIENCE, "request": rj(p=b"p" * 256), "result": {"error": True}},
        {"note": "an empty purpose is refused: the purpose is what separates an addition from a rotation or a recovery.", "name": "purpose-empty-rejected", "audience": AUDIENCE, "request": rj(p=b""), "result": {"error": True}},
        {"note": "a control character (U+0007) in the purpose is refused.", "name": "purpose-control-rejected", "audience": AUDIENCE, "request": rj(p=b"add\x07key"), "result": {"error": True}},
        {"note": "U+007F in the purpose is refused.", "name": "purpose-del-rejected", "audience": AUDIENCE, "request": rj(p=b"add\x7fkey"), "result": {"error": True}},
        {"note": "a purpose that is not valid UTF-8 (0xff) is refused.", "name": "purpose-not-utf8-rejected", "audience": AUDIENCE, "request": rj(p=b"add\xffkey"), "result": {"error": True}},
        {"note": "a 256-byte transaction id is refused.", "name": "transaction-256-rejected", "audience": AUDIENCE, "request": rj(t=bytes(256)), "result": {"error": True}},
        {"note": "an empty transaction id is refused: completion names a pending record.", "name": "transaction-empty-rejected", "audience": AUDIENCE, "request": rj(t=b""), "result": {"error": True}},
        {"note": "an empty audience is refused.", "name": "audience-empty-rejected", "audience": "", "request": base_req, "result": {"error": True}},
        {"note": "a control character in the audience is refused.", "name": "audience-control-rejected", "audience": AUDIENCE + "\n", "request": base_req, "result": {"error": True}},
        {"note": "the new key must be exactly 32 bytes.", "name": "new-key-short-rejected", "audience": AUDIENCE, "request": rj(k=pub_n[:31]), "result": {"error": True}},
        {"note": "the new key must be exactly 32 bytes.", "name": "new-key-long-rejected", "audience": AUDIENCE, "request": rj(k=pub_n + b"\x00"), "result": {"error": True}},
        {"note": "the intent digest must be exactly 32 bytes.", "name": "intent-digest-short-rejected", "audience": AUDIENCE, "request": rj(d=digest[:31]), "result": {"error": True}},
        {"note": "the intent digest must be exactly 32 bytes.", "name": "intent-digest-long-rejected", "audience": AUDIENCE, "request": rj(d=digest + b"\x00"), "result": {"error": True}},
    ]

    # ---- enroll_prove ---------------------------------------------------------------------
    sig = proof()
    enroll_prove = [
        {"note": "the enrollment proof: possession by the NEW key in domain archon-enroll/1 over the server's nonce and the enrollment binding — Ed25519ph, context-string archon-enroll/1, over 0x01 ‖ u16 len ‖ nonce ‖ u16 len ‖ binding. Inputs {seed, audience, request}; expected {\"ok\": 128 hex} or {\"error\": true}. Signatures derived with OpenSSL 3.2.4 — an implementation outside all three cores.",
         "name": "basic", "seed": SEED_N.hex(), "audience": AUDIENCE, "request": base_req, "result": {"ok": sig.hex()}},
        {"note": "another purpose is another statement, and another signature.",
         "name": "rotate-purpose", "seed": SEED_N.hex(), "audience": AUDIENCE, "request": rj(p=b"rotate"), "result": {"ok": proof(p=b"rotate").hex()}},
        {"note": "a seed whose public key is not the request's new key is refused: only the key being enrolled proves.", "name": "not-the-new-key-rejected", "seed": SEED_P.hex(), "audience": AUDIENCE, "request": base_req, "result": {"error": True}},
        {"note": "a 15-byte nonce is refused by the possession scheme.", "name": "nonce-short-rejected", "seed": SEED_N.hex(), "audience": AUDIENCE, "request": rj(n=nonce[:15]), "result": {"error": True}},
        {"note": "every binding refusal is a prove refusal: an empty audience.", "name": "audience-empty-rejected", "seed": SEED_N.hex(), "audience": "", "request": base_req, "result": {"error": True}},
        {"note": "a 31-byte seed is refused.", "name": "seed-short-rejected", "seed": SEED_N[:31].hex(), "audience": AUDIENCE, "request": base_req, "result": {"error": True}},
    ]

    # ---- enroll_verify --------------------------------------------------------------------
    sig_login_domain = sign(SEED_N, possession_message(nonce, bound()), "archon-login/1")
    sig_raw = sign(SEED_N, possession_message(nonce, bound()), None, prehash=False)
    sig_ph_no_ctx = sign(SEED_N, possession_message(nonce, bound()), None, prehash=True)
    sig_bare_nonce = sign(SEED_N, nonce, ENROLL_DOMAIN)
    sig_binding_only = sign(SEED_N, bound(), ENROLL_DOMAIN)

    def v(name, note, a=AUDIENCE, req=None, s=None, valid=False):
        return {"note": note, "name": name, "audience": a, "request": req or base_req, "sig": (s or sig).hex(), "valid": valid}

    enroll_verify = [
        v("basic", "verify the enrollment proof under the request's own new key: inputs {audience, request, sig}; expected {valid: bool}. Total: every shape failure is false. The substitutions are the content — each bound field must bind, and no signature of another shape is a proof.", valid=True),
        v("wrong-audience", "the same proof at another audience is not a proof there.", a="https://evil.example/api"),
        v("audience-trailing-slash", "the audience is bound byte for byte.", a=AUDIENCE + "/"),
        v("wrong-purpose", "an addition's proof is not a rotation's.", req=rj(p=b"rotate")),
        v("wrong-transaction", "another pending transaction.", req=rj(t=bytes(16))),
        v("wrong-nonce", "another server nonce.", req=rj(n=bytes([0xCD]) * 16)),
        v("wrong-intent-digest", "another intent.", req=rj(d=bytes(32))),
        v("other-new-key", "the request names another new key, so the proof is checked under that key and fails.", req=rj(k=pub_x)),
        v("login-domain", "the same bytes proved in archon-login/1 are not an enrollment proof.", s=sig_login_domain),
        v("raw-signature", "a plain Ed25519 signature over the possession message is not a proof.", s=sig_raw),
        v("ph-without-context", "Ed25519ph without the context is not a proof.", s=sig_ph_no_ctx),
        v("bare-nonce", "a signature over the nonce alone is not a proof.", s=sig_bare_nonce),
        v("binding-without-possession-layout", "a signature over the binding without the possession layout is not a proof.", s=sig_binding_only),
        v("sig-truncated", "63 bytes.", s=sig[:63]),
        v("sig-flipped", "one bit flipped.", s=bytes([sig[0] ^ 0x01]) + sig[1:]),
        v("nonce-short", "a 15-byte nonce is false, not an error.", req=rj(n=nonce[:15])),
        v("purpose-control", "a control character in the request is false, not an error.", req=rj(p=b"add\x07key")),
        v("new-key-short", "a 31-byte new key is false, not an error.", req=rj(k=pub_n[:31])),
    ]

    doc = {
        "version": 1,
        "note": "archon request-authentication and key-enrollment conformance vectors (docs/request.md), PROVISIONAL until ADR 0010 §8's gate is met. It carries the request profile (§3–§5, §7 steps 1–7: the client's signature base, headers and signature, and every acceptance and refusal of the verifier short of replay, which is the server's) and key enrollment (§6: the binding, the new key's proof, and its verification in the SDK's possession scheme, domain archon-enroll/1). Purposes are given as hex so that a non-UTF-8 purpose can be a case; a lane decodes them before calling the scheme. Audience is a UTF-8 string. Entropy (nonce, transaction id, keys) is a case INPUT — the scheme never sources it. Signatures derived with OpenSSL 3.2.4, outside all three cores (vectors/tools/request-vectors.py).",
        "enroll_binding": enroll_binding_cases,
        "enroll_prove": enroll_prove,
        "enroll_verify": enroll_verify,
        **request_families(),
    }
    out = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(out.encode("utf-8"))  # never the console codepage


if __name__ == "__main__":
    main()
