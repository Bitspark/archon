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
import json
import os
import subprocess
import sys
import tempfile

ENROLL_DOMAIN = "archon-enroll/1"
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


def req_json(nonce: bytes, transaction: bytes, purpose: bytes, new_key: bytes, digest: bytes) -> dict:
    return {
        "nonce": nonce.hex(),
        "transaction": transaction.hex(),
        "purpose": purpose.hex(),
        "new_key": new_key.hex(),
        "intent_digest": digest.hex(),
    }


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
        "note": "archon request-authentication and key-enrollment conformance vectors (docs/request.md), PROVISIONAL until ADR 0010 §8's gate is met. This first cut carries key enrollment (§6): the binding, the new key's proof, and its verification — in the SDK's possession scheme, domain archon-enroll/1. The request-profile families follow. Purposes are given as hex so that a non-UTF-8 purpose can be a case; a lane decodes them before calling the scheme. Audience is a UTF-8 string. Entropy (nonce, transaction id, keys) is a case INPUT — the scheme never sources it. Signatures derived with OpenSSL 3.2.4, outside all three cores (vectors/tools/request-vectors.py).",
        "enroll_binding": enroll_binding_cases,
        "enroll_prove": enroll_prove,
        "enroll_verify": enroll_verify,
    }
    out = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(out.encode("utf-8"))  # never the console codepage


if __name__ == "__main__":
    main()
