"""The signer seam (ADR 0009 §2–4): every helper through a `Signer` produces the SAME bytes the
seed functions produce — checked against `vectors/sdk.json`, whose signatures OpenSSL derived —
and every rule the seam enforces is exercised against a signer that breaks it."""

import json
from pathlib import Path

import pytest

from archon_core import public_key_from_seed, sign, sign_in_domain
from archon_sdk import envelope, possession
from archon_sdk.signer import (
    PH_CONTEXT,
    RAW,
    Capabilities,
    PhContext,
    Raw,
    SeedSigner,
    SigningRequest,
    check_signature,
    sign_with,
)

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "vectors" / "sdk.json").read_text("utf-8"))
SEED = bytes([7]) * 32
DOMAIN = "archon/test/pop"
NONCE = bytes([1]) * 16


def ok_cases(family):
    return [c for c in VECTORS[family] if "ok" in c["result"]]


def test_through_a_seed_signer_every_helper_reproduces_the_vectors():
    checked = 0
    for c in ok_cases("possession_prove"):
        sig = possession.prove_with(
            SeedSigner(bytes.fromhex(c["seed"])), c["domain"], bytes.fromhex(c["nonce"]), bytes.fromhex(c["binding"])
        )
        assert sig.hex() == c["result"]["ok"], c["name"]
        checked += 1
    for c in ok_cases("envelope_seal"):
        env = envelope.seal_with(SeedSigner(bytes.fromhex(c["seed"])), c["domain"], bytes.fromhex(c["payload"]))
        assert env.hex() == c["result"]["ok"], c["name"]
        checked += 1
    # Every ok case, counted independently: a key slip that skipped them all would pass silently.
    assert checked == len(ok_cases("possession_prove")) + len(ok_cases("envelope_seal")) >= 6


class Fake:
    """A signer that counts its calls and signs however `how` says."""

    def __init__(self, public_key, how, capabilities=Capabilities(schemes=(RAW, PH_CONTEXT))):
        self.public_key = public_key
        self.capabilities = capabilities
        self.how = how
        self.calls = 0

    def sign(self, request):
        self.calls += 1
        return self.how(request)


def test_an_out_of_range_request_is_refused_before_the_signer_is_called():
    f = Fake(public_key_from_seed(SEED), lambda r: sign(SEED, r.message))
    with pytest.raises(ValueError):
        possession.prove_with(f, "", NONCE, b"b")
    with pytest.raises(ValueError):
        possession.prove_with(f, DOMAIN, NONCE[:15], b"b")
    with pytest.raises(ValueError):
        envelope.seal_with(f, "d" * 256, b"")
    with pytest.raises(ValueError):
        sign_with(f, SigningRequest(bytes(31), Raw(), b"x"))
    assert f.calls == 0


def test_a_signer_is_asked_only_for_what_it_says_it_can_do():
    pub = public_key_from_seed(SEED)
    request = possession.prepare(pub, DOMAIN, NONCE, b"b")
    raw_only = Fake(pub, lambda r: sign(SEED, r.message), Capabilities(schemes=(RAW,)))
    elsewhere = Fake(pub, lambda r: sign_in_domain(SEED, DOMAIN, r.message), Capabilities((PH_CONTEXT,), ("archon/test/other",)))
    other_key = Fake(public_key_from_seed(bytes([8]) * 32), lambda r: sign(SEED, r.message))
    for signer, want in [(raw_only, "cannot produce"), (elsewhere, "does not sign in domain"), (other_key, "not the expected key")]:
        with pytest.raises(ValueError, match=want):
            sign_with(signer, request)
        assert signer.calls == 0


@pytest.mark.parametrize(
    "label,how",
    [
        ("signs with another key", lambda r: sign_in_domain(bytes([8]) * 32, DOMAIN, r.message)),
        ("drops the context and signs raw", lambda r: sign(SEED, r.message)),
        ("signs in another domain", lambda r: sign_in_domain(SEED, "archon/test/other", r.message)),
        ("signs other bytes", lambda r: sign_in_domain(SEED, DOMAIN, b"\x00")),
        ("returns 63 bytes", lambda r: sign_in_domain(SEED, DOMAIN, r.message)[1:]),
    ],
)
def test_a_signature_is_checked_against_the_request_never_the_signers_word(label, how):
    pub = public_key_from_seed(SEED)
    request = possession.prepare(pub, DOMAIN, NONCE, b"b")
    with pytest.raises(ValueError, match="does not verify"):
        sign_with(Fake(pub, how), request)
    with pytest.raises(ValueError, match="does not verify"):
        possession.complete(request, how(request))


def test_complete_assembles_from_the_request_and_the_seed_signer_is_deterministic():
    s = SeedSigner(SEED)
    request = envelope.prepare_seal(s.public_key, "archon/test/env", b"payload")
    assert request.scheme == PhContext("archon/test/env")
    first = s.sign(request)
    assert s.sign(request) == first, "signing twice gives the same bytes"
    env = envelope.complete_seal(request, first)
    assert envelope.open(env, "archon/test/env").payload == b"payload"
    with pytest.raises(ValueError, match="not a seal request"):
        envelope.complete_seal(possession.prepare(s.public_key, "d", NONCE, b"b"), first)
    assert check_signature(request, first) == first
    assert SEED.hex() not in repr(s), "the repr never carries the seed"
