"""Unit tests for the Python sdk.

The oracle in `vectors/sdk.json` is the cross-language authority and is driven by
`conformance/check-py-sdk.mjs`; these tests cover the same ground from inside Python, plus
what the oracle's `ok` / `error` protocol cannot express: which exception is raised, and that
verification never raises. The two verify-side refusals below (a short nonce and an empty
binding) are also pinned by the oracle since 0.8.0; before that its cases for them carried
no genuine signature, and these tests were the only thing that caught their removal.
"""

import pytest

from archon_core import public_key_from_seed, sign, sign_in_domain
from archon_sdk import Opened, envelope, possession

SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))
DOMAIN = "example/pop/v1"
NONCE = bytes(range(16))
BINDING = b"channel"


# --- possession: the layout ----------------------------------------------------------

def test_possession_layout_is_pinned():
    assert possession.message_bytes(NONCE, BINDING) == (
        b"\x01" + b"\x00\x10" + NONCE + b"\x00\x07" + BINDING
    )


def test_possession_layout_bounds():
    possession.message_bytes(bytes(possession.MIN_NONCE_SIZE), b"x")
    possession.message_bytes(bytes(possession.MAX_FIELD_SIZE), bytes(possession.MAX_FIELD_SIZE))
    with pytest.raises(ValueError, match="min 16"):
        possession.message_bytes(bytes(15), b"x")
    with pytest.raises(ValueError, match="max 65535"):
        possession.message_bytes(bytes(possession.MAX_FIELD_SIZE + 1), b"x")
    with pytest.raises(ValueError, match="empty"):
        possession.message_bytes(NONCE, b"")
    with pytest.raises(ValueError, match="max 65535"):
        possession.message_bytes(NONCE, bytes(possession.MAX_FIELD_SIZE + 1))


# --- possession: prove and verify ------------------------------------------------------

def test_possession_round_trip_and_every_field_binds():
    pub = public_key_from_seed(SEED)
    proof = possession.prove(SEED, DOMAIN, NONCE, BINDING)
    assert len(proof) == 64
    assert possession.verify(pub, DOMAIN, NONCE, BINDING, proof)
    assert not possession.verify(pub, DOMAIN, bytes(range(1, 17)), BINDING, proof)
    assert not possession.verify(pub, DOMAIN, NONCE, b"other channel", proof)
    assert not possession.verify(pub, "example/pop/v2", NONCE, BINDING, proof)
    assert not possession.verify(public_key_from_seed(OTHER_SEED), DOMAIN, NONCE, BINDING, proof)


def test_possession_is_deterministic():
    assert possession.prove(SEED, DOMAIN, NONCE, BINDING) == possession.prove(SEED, DOMAIN, NONCE, BINDING)


def test_a_raw_signature_over_the_layout_is_not_a_proof():
    pub = public_key_from_seed(SEED)
    raw = sign(SEED, possession.message_bytes(NONCE, BINDING))
    assert not possession.verify(pub, DOMAIN, NONCE, BINDING, raw)


def test_prove_refuses_what_is_not_a_proof():
    with pytest.raises(ValueError):
        possession.prove(SEED, DOMAIN, bytes(15), BINDING)
    with pytest.raises(ValueError):
        possession.prove(SEED, DOMAIN, NONCE, b"")
    with pytest.raises(ValueError):
        possession.prove(SEED, "", NONCE, BINDING)
    with pytest.raises(ValueError):
        possession.prove(SEED[:31], DOMAIN, NONCE, BINDING)


def test_verify_refuses_a_genuine_signature_over_an_unbound_layout():
    # A GENUINE signature over the exact bytes the scheme would sign if it allowed an empty
    # binding, in the domain — so only the sdk's own check can refuse it. The oracle's
    # `binding-empty-rejected` verify case has pinned the same thing since 0.8.0.
    pub = public_key_from_seed(SEED)
    unbound = b"\x01" + b"\x00\x10" + NONCE + b"\x00\x00"
    assert not possession.verify(pub, DOMAIN, NONCE, b"", sign_in_domain(SEED, DOMAIN, unbound))


def test_verify_refuses_a_genuine_signature_over_a_short_nonce():
    # The same for `nonce-15-rejected`: a genuine signature over the 15-byte layout.
    pub = public_key_from_seed(SEED)
    short = bytes(15)
    layout = b"\x01" + b"\x00\x0f" + short + b"\x00\x07" + BINDING
    assert not possession.verify(pub, DOMAIN, short, BINDING, sign_in_domain(SEED, DOMAIN, layout))


def test_verify_is_total():
    pub = public_key_from_seed(SEED)
    proof = possession.prove(SEED, DOMAIN, NONCE, BINDING)
    assert possession.verify(pub[:31], DOMAIN, NONCE, BINDING, proof) is False
    assert possession.verify(pub, DOMAIN, NONCE, BINDING, proof[:63]) is False
    assert possession.verify(pub, "", NONCE, BINDING, proof) is False
    assert possession.verify(pub, DOMAIN, None, BINDING, proof) is False


# --- envelope --------------------------------------------------------------------------

ENV_DOMAIN = "example/env/v1"


def test_envelope_layout_is_pinned():
    sealed = envelope.seal(SEED, ENV_DOMAIN, b"payload")
    d = ENV_DOMAIN.encode()
    assert sealed[:4] == b"arcn"
    assert sealed[4] == envelope.VERSION
    assert sealed[5] == len(d)
    assert sealed[6 : 6 + len(d)] == d
    at = 6 + len(d)
    assert sealed[at : at + 32] == public_key_from_seed(SEED)
    assert sealed[at + 96 :] == b"payload"
    assert envelope.message_bytes(b"payload") == b"\x02payload"


def test_envelope_round_trip():
    opened = envelope.open(envelope.seal(SEED, ENV_DOMAIN, b"payload"), ENV_DOMAIN)
    assert opened == Opened(pubkey=public_key_from_seed(SEED), payload=b"payload")


def test_empty_payload_is_allowed():
    assert envelope.open(envelope.seal(SEED, ENV_DOMAIN, b""), ENV_DOMAIN).payload == b""


def test_the_verifier_chooses_the_domain():
    # A genuine envelope in another domain: an opener that trusted the envelope's own domain
    # field would accept it.
    sealed = envelope.seal(SEED, "example/env/other", b"payload")
    with pytest.raises(ValueError, match="different domain"):
        envelope.open(sealed, ENV_DOMAIN)


def test_every_tamper_is_refused():
    sealed = bytearray(envelope.seal(SEED, ENV_DOMAIN, b"payload"))
    for index in (0, 4, 5, 6, 6 + len(ENV_DOMAIN), len(sealed) - 1):
        bent = bytearray(sealed)
        bent[index] ^= 0x01
        with pytest.raises(ValueError):
            envelope.open(bytes(bent), ENV_DOMAIN)
    for cut in (0, 3, 5, 6 + len(ENV_DOMAIN) + 31, 6 + len(ENV_DOMAIN) + 95):
        with pytest.raises(ValueError):
            envelope.open(bytes(sealed[:cut]), ENV_DOMAIN)


def test_a_possession_proof_is_never_an_envelope_signature():
    # The scheme tags keep the two layouts apart: sign the payload bytes as a possession
    # message would be signed (no envelope tag) and splice that signature in.
    sealed = bytearray(envelope.seal(SEED, ENV_DOMAIN, b"payload"))
    at = 6 + len(ENV_DOMAIN) + 32
    sealed[at : at + 64] = sign_in_domain(SEED, ENV_DOMAIN, b"payload")
    with pytest.raises(ValueError, match="does not verify"):
        envelope.open(bytes(sealed), ENV_DOMAIN)


def test_seal_refuses_a_bad_domain_or_seed():
    with pytest.raises(ValueError):
        envelope.seal(SEED, "", b"x")
    with pytest.raises(ValueError):
        envelope.seal(SEED, "d" * 256, b"x")
    with pytest.raises(ValueError):
        envelope.seal(SEED[:31], ENV_DOMAIN, b"x")
