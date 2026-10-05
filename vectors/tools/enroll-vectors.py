#!/usr/bin/env python3
"""Derive vectors/enroll.json OUTSIDE the three cores.

`archon enroll`'s formats (docs/enroll.md §2–§3, ADR 0013): the intent in format 1, the challenge
token, the request a challenge token yields, and the proof token. Every byte is assembled by hand
from the layouts in docs/enroll.md, so this file is a fourth, deliberately naive implementation of
them. A vector copied out of a lane pins that lane's bugs; a vector derived from the
specification lets all three lanes be wrong together and be caught (vectors/README.md,
"Authoring").

The display-unsafe set is read from vectors/display-unsafe.json, the frozen ranges every lane
already sweeps, so this file depends on no Unicode table.

Text fields are given as hex in the cases, so that non-UTF-8 text can be a case. Token texts are
JSON strings, given exactly. The request a token yields is spelled as vectors/request.json spells
an enrollment request, so a lane can feed it straight to enroll_binding.

Run from the repo root: `python vectors/tools/enroll-vectors.py > vectors/enroll.json`.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
UNSAFE = [
    (int(lo, 16), int(hi, 16))
    for lo, hi in json.load(open(os.path.join(HERE, "..", "display-unsafe.json"), encoding="utf-8"))["ranges"]
]

INTENT_FORMAT = 0x01
MIN_BLIND, MAX_BLIND = 16, 64
MAX_TEXT = 255
MAX_RESTRICTIONS = 32
CHALLENGE_PREFIX = "archon-enroll-challenge-1:"
PROOF_PREFIX = "archon-enroll-proof-1:"
MAX_TOKEN = 65536
MAX_DEADLINE = 253402300799  # 9999-12-31T23:59:59Z
MIN_NONCE, MAX_NONCE = 16, 255
MAX_TRANSACTION = 255
MAX_INTENT = 0xFFFF
WHITESPACE = "\t\n\r "

AUDIENCE = "https://bitshelf.dev/api"
NEW_KEY = bytes.fromhex("7a91b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f")
BLIND = bytes(range(0xA0, 0xB0))  # 16 bytes
TRANSACTION = bytes.fromhex("8f3c2a9d1e4b7c60a5f2d8e1b3c4a5d6")
NONCE = bytes.fromhex("abababababababababababababababab")
DEADLINE = 1791190000
PROOF = bytes(range(64))


# The cases' invisible and look-alike code points, by number, so this file holds none of them.
ZWSP = chr(0x200B)
RLO = chr(0x202E)
LSEP = chr(0x2028)
SHY = chr(0x00AD)
NBSP = chr(0x00A0)
CSI = chr(0x009B)
BOM = chr(0xFEFF)
CYR_A = chr(0x0430)
CYR_I = chr(0x0456)


class Refused(Exception):
    pass


def u16(n):
    assert 0 <= n <= 0xFFFF
    return n.to_bytes(2, "big")


def unsafe(cp):
    return any(lo <= cp <= hi for lo, hi in UNSAFE)


def check_text(raw, what):
    """1..=255 bytes of well-formed UTF-8 with no display-unsafe code point."""
    if not 1 <= len(raw) <= MAX_TEXT:
        raise Refused(f"{what} length {len(raw)}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Refused(f"{what} not UTF-8")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in text):
        raise Refused(f"{what} surrogate")
    for c in text:
        if unsafe(ord(c)):
            raise Refused(f"{what} U+{ord(c):04X}")


# ---- the intent, format 1 (docs/enroll.md §2) ------------------------------------------------

def encode_intent(blind, ref, name, purpose, restrictions):
    if not MIN_BLIND <= len(blind) <= MAX_BLIND:
        raise Refused("blind")
    for raw, what in ((ref, "account id"), (name, "account name"), (purpose, "purpose")):
        check_text(raw, what)
    if len(restrictions) > MAX_RESTRICTIONS:
        raise Refused("restrictions")
    for r in restrictions:
        check_text(r, "restriction")
    out = bytes([INTENT_FORMAT]) + u16(len(blind)) + blind
    for raw in (ref, name, purpose):
        out += u16(len(raw)) + raw
    out += bytes([len(restrictions)])
    for r in restrictions:
        out += u16(len(r)) + r
    return out


def raw_intent(blind, ref, name, purpose, restrictions, fmt=INTENT_FORMAT, count=None, tail=b""):
    """The layout with NO checks, for decoder cases the encoder would refuse."""
    out = bytes([fmt]) + u16(len(blind)) + blind
    for raw in (ref, name, purpose):
        out += u16(len(raw)) + raw
    out += bytes([len(restrictions) if count is None else count])
    for r in restrictions:
        out += u16(len(r)) + r
    return out + tail


def decode_intent(b):
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(b):
            raise Refused("truncated")
        chunk = b[pos:pos + n]
        pos += n
        return chunk

    def field():
        return take(int.from_bytes(take(2), "big"))

    if take(1)[0] != INTENT_FORMAT:
        raise Refused("format")
    blind = field()
    if not MIN_BLIND <= len(blind) <= MAX_BLIND:
        raise Refused("blind")
    ref, name, purpose = field(), field(), field()
    for raw, what in ((ref, "account id"), (name, "account name"), (purpose, "purpose")):
        check_text(raw, what)
    count = take(1)[0]
    if count > MAX_RESTRICTIONS:
        raise Refused("restrictions")
    restrictions = []
    for _ in range(count):
        r = field()
        check_text(r, "restriction")
        restrictions.append(r)
    if pos != len(b):
        raise Refused("trailing")
    return {"blind": blind.hex(), "account_id": ref.hex(), "account_name": name.hex(),
            "purpose": purpose.hex(), "restrictions": [r.hex() for r in restrictions]}


# ---- the tokens (docs/enroll.md §3) ----------------------------------------------------------

def check_audience(a):
    """Non-empty UTF-8 with no display-unsafe code point: stricter than the binding's C0-and-DEL
    rule, because a refusal prints a token's audience (docs/enroll.md §3)."""
    raw = a.encode("utf-8")
    if not 1 <= len(raw) <= 0xFFFF or any(unsafe(ord(c)) for c in a):
        raise Refused("audience")
    return raw


def encode_challenge(audience, transaction, nonce, new_key, intent, deadline):
    raw_aud = check_audience(audience)
    if not 1 <= len(transaction) <= MAX_TRANSACTION:
        raise Refused("transaction")
    if not MIN_NONCE <= len(nonce) <= MAX_NONCE:
        raise Refused("nonce")
    if len(new_key) != 32:
        raise Refused("new key")
    if not 1 <= len(intent) <= MAX_INTENT:
        raise Refused("intent")
    if not 0 <= deadline <= MAX_DEADLINE:
        raise Refused("deadline")
    body = (u16(len(raw_aud)) + raw_aud + u16(len(transaction)) + transaction + u16(len(nonce)) + nonce
            + new_key + u16(len(intent)) + intent + deadline.to_bytes(8, "big"))
    text = CHALLENGE_PREFIX + body.hex()
    if len(text) > MAX_TOKEN:
        raise Refused("size")
    return text


def unwrap(text, prefix):
    i, j = 0, len(text)
    while i < j and text[i] in WHITESPACE:
        i += 1
    while j > i and text[j - 1] in WHITESPACE:
        j -= 1
    t = text[i:j]
    if len(t.encode("utf-8")) > MAX_TOKEN:
        raise Refused("size")
    if not t.startswith(prefix):
        raise Refused("prefix")
    h = t[len(prefix):]
    if len(h) % 2 or any(c not in "0123456789abcdef" for c in h):
        raise Refused("hex")
    return bytes.fromhex(h)


def decode_challenge(text):
    b = unwrap(text, CHALLENGE_PREFIX)
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(b):
            raise Refused("truncated")
        chunk = b[pos:pos + n]
        pos += n
        return chunk

    def field():
        return take(int.from_bytes(take(2), "big"))

    raw_aud = field()
    try:
        audience = raw_aud.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Refused("audience")
    check_audience(audience)
    transaction, nonce = field(), field()
    new_key = take(32)
    intent = field()
    deadline = int.from_bytes(take(8), "big")
    if pos != len(b):
        raise Refused("trailing")
    if not 1 <= len(transaction) <= MAX_TRANSACTION or not MIN_NONCE <= len(nonce) <= MAX_NONCE:
        raise Refused("field")
    if not 1 <= len(intent) or deadline > MAX_DEADLINE:
        raise Refused("field")
    return {"audience": audience, "transaction": transaction.hex(), "nonce": nonce.hex(),
            "new_key": new_key.hex(), "intent": intent.hex(), "deadline": deadline}


def challenge_request(text):
    c = decode_challenge(text)
    intent = bytes.fromhex(c["intent"])
    i = decode_intent(intent)
    return {"audience": c["audience"], "request": {
        "nonce": c["nonce"], "transaction": c["transaction"], "purpose": i["purpose"],
        "new_key": c["new_key"], "intent_digest": hashlib.sha256(intent).hexdigest()}}


def encode_proof(transaction, new_key, proof):
    if not 1 <= len(transaction) <= MAX_TRANSACTION or len(new_key) != 32 or len(proof) != 64:
        raise Refused("field")
    return PROOF_PREFIX + (u16(len(transaction)) + transaction + new_key + proof).hex()


def decode_proof(text):
    b = unwrap(text, PROOF_PREFIX)
    if len(b) < 2:
        raise Refused("truncated")
    n = int.from_bytes(b[:2], "big")
    if not 1 <= n <= MAX_TRANSACTION or len(b) != 2 + n + 32 + 64:
        raise Refused("field")
    return {"transaction": b[2:2 + n].hex(), "new_key": b[2 + n:2 + n + 32].hex(),
            "proof": b[2 + n + 32:].hex()}


# ---- cases -----------------------------------------------------------------------------------

def result(fn, *args):
    try:
        return {"ok": fn(*args)}
    except Refused:
        return {"error": True}


def intent_json(blind, ref, name, purpose, restrictions):
    return {"blind": blind.hex(), "account_id": ref.hex(), "account_name": name.hex(),
            "purpose": purpose.hex(), "restrictions": [r.hex() for r in restrictions]}


def main():
    REF, NAME, ADD = b"u_8f3c2a", b"julia (bitspark)", b"add-key"
    RESTR = [b"read:projects", b"expires 2027-01-01"]
    base = (BLIND, REF, NAME, ADD, [])

    def ie(name, note, blind=BLIND, ref=REF, nm=NAME, purpose=ADD, restrictions=()):
        restrictions = list(restrictions)
        r = result(encode_intent, blind, ref, nm, purpose, restrictions)
        return {"name": name, "note": note,
                "intent": intent_json(blind, ref, nm, purpose, restrictions),
                "result": {"ok": r["ok"].hex()} if "ok" in r else r}

    intent_encode = [
        ie("basic", "the intent in format 1: 0x01 ‖ u16 blind ‖ u16 account ref ‖ u16 account name ‖ u16 purpose ‖ u8 count ‖ (u16 restriction)*. Inputs {intent} with every text field as hex; expected {ok: hex} or {error: true}."),
        ie("restrictions", "two restrictions, kept in order.", restrictions=RESTR),
        ie("restrictions-32", "32 restrictions is the most.", restrictions=[b"r%02d" % i for i in range(32)]),
        ie("restrictions-33", "33 restrictions are refused.", restrictions=[b"r%02d" % i for i in range(33)]),
        ie("blind-64", "a 64-byte blind is the longest.", blind=bytes(64)),
        ie("blind-15", "a 15-byte blind is refused: the blind must carry at least 128 bits.", blind=BLIND[:15]),
        ie("blind-65", "a 65-byte blind is refused.", blind=bytes(65)),
        ie("ref-empty", "an empty account id is refused.", ref=b""),
        ie("ref-255", "a 255-byte account id is the longest.", ref=b"r" * 255),
        ie("ref-256", "a 256-byte account id is refused.", ref=b"r" * 256),
        ie("name-non-ascii", "non-ASCII text that is display-safe is allowed.", nm="jülia (büro) 文".encode("utf-8")),
        ie("name-lookalike", "a Cyrillic " + CYR_A + " (U+0430) is display-safe: look-alikes are not in the set, and the command cannot catch them (docs/enroll.md §6).", nm=("jul" + CYR_I + CYR_A + " (bitspark)").encode("utf-8")),
        ie("name-zero-width", "a zero-width space (U+200B, Cf) is refused.", nm=("julia" + ZWSP).encode("utf-8")),
        ie("name-bidi", "a right-to-left override (U+202E) is refused.", nm=("julia" + RLO).encode("utf-8")),
        ie("name-bom", "a byte-order mark (U+FEFF, Cf) at the start of a name is refused, not dropped: a decoder that strips a leading BOM would show a name other than the bytes.", nm=(BOM + "julia").encode("utf-8")),
        ie("name-c1", "a C1 control (U+0085) is refused.", nm="julia\u0085".encode("utf-8")),
        ie("name-not-utf8", "text that is not UTF-8 is refused.", nm=b"julia\xff"),
        ie("name-encoded-surrogate", "a UTF-8-encoded surrogate (ED A0 80) is not well-formed UTF-8 and is refused.", nm=b"julia\xed\xa0\x80"),
        ie("purpose-empty", "an empty purpose is refused.", purpose=b""),
        ie("purpose-control", "a control character in the purpose is refused.", purpose=b"add\x07key"),
        ie("purpose-rotate", "any display-safe purpose encodes; which purposes a command renders is the command's rule.", purpose=b"rotate"),
        ie("restriction-empty", "an empty restriction is refused.", restrictions=[b"read", b""]),
        ie("restriction-separator", "a line separator (U+2028, Zl) in a restriction is refused.", restrictions=[("read" + LSEP + "all").encode("utf-8")]),
        ie("restriction-soft-hyphen", "a soft hyphen (U+00AD, default ignorable) in a restriction is refused.", restrictions=[("read" + SHY + "all").encode("utf-8")]),
    ]

    ok_bytes = encode_intent(*base)

    def idec(name, note, b):
        return {"name": name, "note": note, "bytes": b.hex(), "result": result(decode_intent, b)}

    intent_decode = [
        idec("basic", "decoding format 1: inputs {bytes}; expected {ok: {blind, account_id, account_name, purpose, restrictions}} with text as hex, or {error: true}.", ok_bytes),
        idec("restrictions", "two restrictions, in order.", encode_intent(BLIND, REF, NAME, ADD, RESTR)),
        idec("empty", "no bytes.", b""),
        idec("format-2", "an unknown format byte is refused, never skipped.", raw_intent(*base, fmt=0x02)),
        idec("format-0", "format 0 is refused.", raw_intent(*base, fmt=0x00)),
        idec("trailing", "a byte after the last restriction is refused.", ok_bytes + b"\x00"),
        idec("truncated", "the last byte missing.", ok_bytes[:-1]),
        idec("length-past-end", "a field length that runs past the end.", ok_bytes[:3] + b"\xff\xff"),
        idec("blind-15", "a 15-byte blind is refused at decoding too.", raw_intent(BLIND[:15], REF, NAME, ADD, [])),
        idec("count-33", "a count of 33 is refused, whatever follows.", raw_intent(BLIND, REF, NAME, ADD, [b"r%02d" % i for i in range(33)])),
        idec("count-over-content", "a count of 2 with one restriction present.", raw_intent(BLIND, REF, NAME, ADD, [b"read"], count=2)),
        idec("name-bidi", "an encoder would refuse it; a decoder refuses it too.", raw_intent(BLIND, REF, ("julia" + RLO).encode("utf-8"), ADD, [])),
        idec("name-bom", "a name whose bytes begin EF BB BF is refused: a UTF-8 decoder that silently strips a leading BOM would accept it and show the name without it.", raw_intent(BLIND, REF, (BOM + "julia").encode("utf-8"), ADD, [])),
        idec("ref-bom", "the first text field after the blind, beginning with a BOM, is refused too.", raw_intent(BLIND, (BOM + "u_8f3c2a").encode("utf-8"), NAME, ADD, [])),
        idec("ref-empty", "an empty account id.", raw_intent(BLIND, b"", NAME, ADD, [])),
        idec("not-utf8", "a restriction that is not UTF-8.", raw_intent(BLIND, REF, NAME, ADD, [b"\xc3"])),
    ]

    def cj(audience=AUDIENCE, transaction=TRANSACTION, nonce=NONCE, new_key=NEW_KEY, intent=ok_bytes, deadline=DEADLINE):
        return {"audience": audience, "transaction": transaction.hex(), "nonce": nonce.hex(),
                "new_key": new_key.hex(), "intent": intent.hex(), "deadline": deadline}

    def cenc(name, note, **kw):
        c = cj(**kw)
        args = (c["audience"], bytes.fromhex(c["transaction"]), bytes.fromhex(c["nonce"]),
                bytes.fromhex(c["new_key"]), bytes.fromhex(c["intent"]), c["deadline"])
        return {"name": name, "note": note, "challenge": c, "result": result(encode_challenge, *args)}

    challenge_encode = [
        cenc("basic", "the challenge token: archon-enroll-challenge-1: then lowercase hex of u16 audience ‖ u16 transaction ‖ u16 nonce ‖ new key[32] ‖ u16 intent ‖ u64 deadline. Inputs {challenge}; expected {ok: text} or {error: true}."),
        cenc("intent-opaque", "the token's codec checks its own fields only: an intent that is not format 1 still encodes, and is refused when the command decodes it.", intent=b"\x02opaque"),
        cenc("transaction-255", "a 255-byte transaction id is the longest.", transaction=bytes(255)),
        cenc("transaction-256", "a 256-byte transaction id is refused.", transaction=bytes(256)),
        cenc("transaction-empty", "an empty transaction id is refused.", transaction=b""),
        cenc("nonce-15", "a 15-byte nonce is refused.", nonce=NONCE[:15]),
        cenc("nonce-255", "a 255-byte nonce is the longest.", nonce=bytes(255)),
        cenc("nonce-256", "a 256-byte nonce is refused.", nonce=bytes(256)),
        cenc("new-key-31", "a 31-byte key is refused.", new_key=NEW_KEY[:31]),
        cenc("intent-empty", "an empty intent is refused.", intent=b""),
        cenc("audience-empty", "an empty audience is refused.", audience=""),
        cenc("audience-control", "a control character in the audience is refused.", audience="https://bitshelf.dev/api\n"),
        cenc("audience-c1", "a C1 control (U+009B, the 8-bit CSI) in the audience is refused: the binding's rule admits it, and a refusal would print it.", audience="https://bitshelf.dev/api" + CSI),
        cenc("audience-bidi", "a right-to-left override in the audience is refused.", audience="https://bitshelf.dev/" + RLO + "ipa"),
        cenc("deadline-zero", "deadline 0 encodes; whether it has passed is the command's check.", deadline=0),
        cenc("deadline-max", "9999-12-31T23:59:59Z is the latest deadline.", deadline=MAX_DEADLINE),
        cenc("deadline-over", "one second later is refused.", deadline=MAX_DEADLINE + 1),
        cenc("size-over", "a token over 65536 bytes is refused at writing too.", intent=bytes(40000)),
    ]

    good = encode_challenge(AUDIENCE, TRANSACTION, NONCE, NEW_KEY, ok_bytes, DEADLINE)
    good_body = good[len(CHALLENGE_PREFIX):]

    def body(audience=AUDIENCE.encode(), transaction=TRANSACTION, nonce=NONCE, new_key=NEW_KEY, intent=ok_bytes, deadline=DEADLINE, tail=b""):
        return (u16(len(audience)) + audience + u16(len(transaction)) + transaction + u16(len(nonce)) + nonce
                + new_key + u16(len(intent)) + intent + deadline.to_bytes(8, "big") + tail).hex()

    # A token of exactly 65536 bytes: prefix + hex of a body of (65536 - len(prefix)) / 2 bytes.
    fixed = 2 + len(AUDIENCE) + 2 + len(TRANSACTION) + 2 + len(NONCE) + 32 + 2 + 8
    at_bound = CHALLENGE_PREFIX + body(intent=bytes((MAX_TOKEN - len(CHALLENGE_PREFIX)) // 2 - fixed))
    assert len(at_bound) == MAX_TOKEN, len(at_bound)

    def cdec(name, note, text):
        return {"name": name, "note": note, "text": text, "result": result(decode_challenge, text)}

    challenge_decode = [
        cdec("basic", "reading a challenge token: inputs {text}; expected {ok: {audience, transaction, nonce, new_key, intent, deadline}} or {error: true}.", good),
        cdec("whitespace", "leading and trailing tabs, line feeds, carriage returns and spaces are ignored.", " \t\r\n" + good + "\r\n"),
        cdec("whitespace-inside", "whitespace inside the token is refused.", good[:40] + " " + good[40:]),
        cdec("whitespace-nbsp", "a no-break space (U+00A0) around the token is not whitespace here, and is refused.", NBSP + good),
        cdec("whitespace-formfeed", "a form feed around the token is refused.", good + "\f"),
        cdec("uppercase", "uppercase hex is refused.", CHALLENGE_PREFIX + good_body.upper()),
        cdec("no-prefix", "the hex alone is refused.", good_body),
        cdec("proof-prefix", "a proof token's prefix is refused.", PROOF_PREFIX + good_body),
        cdec("prefix-version-2", "another version's prefix is refused.", "archon-enroll-challenge-2:" + good_body),
        cdec("odd-hex", "an odd number of hex digits is refused.", good + "0"),
        cdec("trailing-byte", "a byte after the deadline is refused.", CHALLENGE_PREFIX + body(tail=b"\x00")),
        cdec("truncated", "the deadline cut short.", good[:-2]),
        cdec("at-bound", "a token of exactly 65536 bytes is read.", at_bound),
        cdec("over-bound", "65538 bytes are refused.", CHALLENGE_PREFIX + body(intent=bytes((MAX_TOKEN - len(CHALLENGE_PREFIX)) // 2 - fixed + 1))),
        cdec("deadline-over", "a deadline after 9999-12-31T23:59:59Z is refused.", CHALLENGE_PREFIX + body(deadline=MAX_DEADLINE + 1)),
        cdec("nonce-15", "a 15-byte nonce is refused.", CHALLENGE_PREFIX + body(nonce=NONCE[:15])),
        cdec("new-key-short", "a key field that eats the intent's length leaves the token malformed.", CHALLENGE_PREFIX + body(new_key=NEW_KEY[:31])),
        cdec("audience-not-utf8", "an audience that is not UTF-8 is refused.", CHALLENGE_PREFIX + body(audience=b"https://\xff")),
        cdec("audience-control", "a control character in the audience is refused.", CHALLENGE_PREFIX + body(audience=b"https://h.example\x7f")),
        cdec("audience-c1", "a C1 control (U+009B) in the audience is refused at decoding, before any refusal could print it.", CHALLENGE_PREFIX + body(audience=("https://bitshelf.dev/api" + CSI).encode("utf-8"))),
        cdec("audience-bidi", "a right-to-left override in the audience is refused at decoding.", CHALLENGE_PREFIX + body(audience=("https://bitshelf.dev/" + RLO + "ipa").encode("utf-8"))),
        cdec("intent-empty", "an empty intent is refused.", CHALLENGE_PREFIX + body(intent=b"")),
        cdec("intent-opaque", "an intent that is not format 1 is read: the token checks its own fields.", CHALLENGE_PREFIX + body(intent=b"\x02opaque")),
    ]

    def creq(name, note, text):
        return {"name": name, "note": note, "text": text, "result": result(challenge_request, text)}

    rotate = encode_intent(BLIND, REF, NAME, b"rotate", [])
    challenge_req = [
        creq("basic", "the request a challenge token yields: the token's nonce, transaction and new key, the INTENT's purpose, and SHA-256 of the token's intent bytes (docs/enroll.md §3). Inputs {text}; expected {ok: {audience, request}} with request spelled as vectors/request.json spells one (purpose as hex), or {error: true}.", good),
        creq("restrictions", "restrictions change the intent's bytes, so they change the digest.", encode_challenge(AUDIENCE, TRANSACTION, NONCE, NEW_KEY, encode_intent(BLIND, REF, NAME, ADD, RESTR), DEADLINE)),
        creq("other-blind", "the same account under another blind is another digest.", encode_challenge(AUDIENCE, TRANSACTION, NONCE, NEW_KEY, encode_intent(bytes(16), REF, NAME, ADD, []), DEADLINE)),
        creq("purpose-rotate", "the purpose comes from the intent; the sdk derives any purpose, and the command decides which it renders.", encode_challenge(AUDIENCE, TRANSACTION, NONCE, NEW_KEY, rotate, DEADLINE)),
        creq("intent-not-format-1", "an intent that is not format 1 yields no request.", CHALLENGE_PREFIX + body(intent=b"\x02opaque")),
        creq("intent-unsafe", "an intent with a display-unsafe name yields no request.", CHALLENGE_PREFIX + body(intent=raw_intent(BLIND, REF, ("julia" + ZWSP).encode("utf-8"), ADD, []))),
        creq("token-malformed", "a malformed token yields no request.", good.upper()),
    ]

    def penc(name, note, transaction=TRANSACTION, new_key=NEW_KEY, proof=PROOF):
        return {"name": name, "note": note,
                "proof_token": {"transaction": transaction.hex(), "new_key": new_key.hex(), "proof": proof.hex()},
                "result": result(encode_proof, transaction, new_key, proof)}

    proof_encode = [
        penc("basic", "the proof token: archon-enroll-proof-1: then lowercase hex of u16 transaction ‖ new key[32] ‖ proof[64]. Inputs {proof_token}; expected {ok: text} or {error: true}."),
        penc("transaction-255", "a 255-byte transaction id is the longest.", transaction=bytes(255)),
        penc("transaction-256", "a 256-byte transaction id is refused.", transaction=bytes(256)),
        penc("transaction-empty", "an empty transaction id is refused.", transaction=b""),
        penc("new-key-33", "a 33-byte key is refused.", new_key=NEW_KEY + b"\x00"),
        penc("proof-63", "a 63-byte proof is refused.", proof=PROOF[:63]),
    ]

    pgood = encode_proof(TRANSACTION, NEW_KEY, PROOF)
    pbody = pgood[len(PROOF_PREFIX):]

    def pdec(name, note, text):
        return {"name": name, "note": note, "text": text, "result": result(decode_proof, text)}

    proof_decode = [
        pdec("basic", "reading a proof token: inputs {text}; expected {ok: {transaction, new_key, proof}} or {error: true}.", pgood),
        pdec("whitespace", "surrounding whitespace is ignored.", "\n" + pgood + "\n"),
        pdec("challenge-prefix", "a challenge token's prefix is refused.", CHALLENGE_PREFIX + pbody),
        pdec("uppercase", "uppercase hex is refused.", PROOF_PREFIX + pbody.upper()),
        pdec("trailing-byte", "a byte after the proof is refused.", pgood + "00"),
        pdec("truncated", "the proof's last byte missing.", pgood[:-2]),
        pdec("transaction-zero", "a transaction length of 0 is refused.", PROOF_PREFIX + (u16(0) + NEW_KEY + PROOF).hex()),
        pdec("empty", "the prefix alone.", PROOF_PREFIX),
    ]

    doc = {
        "version": 1,
        "note": "archon enroll's formats (docs/enroll.md §2–§3, ADR 0013): the intent in format 1, the challenge token, the request a challenge token yields, and the proof token. Text fields are hex in the cases so non-UTF-8 text can be a case; token texts are given exactly, as JSON strings. The display-unsafe set is vectors/display-unsafe.json's. Every byte is assembled by hand from the specification (vectors/tools/enroll-vectors.py), outside the three lanes.",
        "enroll_intent_encode": intent_encode,
        "enroll_intent_decode": intent_decode,
        "enroll_challenge_encode": challenge_encode,
        "enroll_challenge_decode": challenge_decode,
        "enroll_challenge_request": challenge_req,
        "enroll_proof_encode": proof_encode,
        "enroll_proof_decode": proof_decode,
    }
    out = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"  # ASCII: no invisible code point sits raw in the file
    sys.stdout.buffer.write(out.encode("utf-8"))


if __name__ == "__main__":
    main()
