"""Unit tests for the Python core.

The oracle in `vectors/identity.json` is the cross-language authority and is driven by
`conformance/check.mjs`; these tests cover the same ground from inside Python, plus the
argument-shape failures the oracle has no way to express (a raised exception, a wrong-sized
seed) because its protocol only carries `ok` / `error`.
"""

import pytest

from archon_core import (
    MAX_DOMAIN_SIZE,
    decode_key,
    encode_key,
    pkcs8_pem_to_seed,
    pubkey_from_hex,
    pubkey_to_spki_pem,
    public_key_from_seed,
    seed_from_hex,
    seed_to_pkcs8_pem,
    sign,
    sign_in_domain,
    signature_from_hex,
    spki_pem_to_pubkey,
    to_hex,
    verify,
    verify_in_domain,
)

SEED = bytes(range(32))
MSG = b"hello"
DOMAIN = "example.v1"


# --- crypto ---------------------------------------------------------------------------

def test_public_key_is_32_bytes_and_stable():
    pub = public_key_from_seed(SEED)
    assert len(pub) == 32
    assert pub == public_key_from_seed(SEED)


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError):
        public_key_from_seed(SEED[:31])


def test_sign_verify_roundtrip():
    assert verify(public_key_from_seed(SEED), MSG, sign(SEED, MSG))


def test_verify_is_total_not_raising():
    pub = public_key_from_seed(SEED)
    sig = sign(SEED, MSG)
    assert verify(pub, b"goodbye", sig) is False
    assert verify(pub[:31], MSG, sig) is False          # short key
    assert verify(pub, MSG, sig[:63]) is False          # short signature
    assert verify(pub, MSG, bytes(64)) is False         # all-zero signature


def test_domain_separation_is_cryptographic():
    pub = public_key_from_seed(SEED)
    sig = sign_in_domain(SEED, DOMAIN, MSG)
    assert verify_in_domain(pub, DOMAIN, MSG, sig)
    assert verify_in_domain(pub, "other.v1", MSG, sig) is False   # another domain
    assert verify(pub, MSG, sig) is False                         # never as raw
    assert verify_in_domain(pub, DOMAIN, MSG, sign(SEED, MSG)) is False  # raw never in a domain


def test_domain_bounds():
    with pytest.raises(ValueError):
        sign_in_domain(SEED, "", MSG)                             # "sign in no domain"
    with pytest.raises(ValueError):
        sign_in_domain(SEED, "d" * (MAX_DOMAIN_SIZE + 1), MSG)
    longest = "d" * MAX_DOMAIN_SIZE
    assert verify_in_domain(
        public_key_from_seed(SEED), longest, MSG, sign_in_domain(SEED, longest, MSG)
    )


def test_verify_in_domain_is_false_not_raising_on_bad_domain():
    pub = public_key_from_seed(SEED)
    sig = sign_in_domain(SEED, DOMAIN, MSG)
    assert verify_in_domain(pub, "", MSG, sig) is False
    assert verify_in_domain(pub, "d" * (MAX_DOMAIN_SIZE + 1), MSG, sig) is False


@pytest.mark.parametrize(
    "pubkey_hex",
    [
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    ],
)
def test_small_order_public_keys_are_rejected(pubkey_hex):
    """archon's profile rejects them; PyCryptodome's verifier alone would not.

    These are the two oracle cases that disagreed before the explicit check existed.
    """
    pub = bytes.fromhex(pubkey_hex)
    sig = pub + bytes(32)  # the R=A, S=0 shape the oracle uses
    assert verify(pub, MSG, sig) is False
    assert verify_in_domain(pub, DOMAIN, MSG, sig) is False


# --- hexbytes -------------------------------------------------------------------------

def test_hex_is_lowercase_and_fixed_size():
    assert to_hex(b"\x00\xff") == "00ff"
    assert seed_from_hex("AA" * 32) == bytes([0xAA]) * 32        # either case in
    for bad in ["aa" * 31, "aa" * 33, "", "zz" * 32]:
        with pytest.raises(ValueError):
            seed_from_hex(bad)


def test_hex_rejects_whitespace_that_python_would_otherwise_accept():
    """`bytes.fromhex` tolerates spaces; archon's grammar does not, and the other cores
    reject them. Agreement is the point."""
    with pytest.raises(ValueError):
        seed_from_hex("aa " * 16 + "aa" * 16)


def test_hex_decoders_are_typed_by_length():
    assert len(pubkey_from_hex("11" * 32)) == 32
    assert len(signature_from_hex("11" * 64)) == 64
    with pytest.raises(ValueError):
        pubkey_from_hex("11" * 64)      # a signature is not a public key


# --- keytext --------------------------------------------------------------------------

def test_key_text_roundtrip():
    pub = public_key_from_seed(SEED)
    text = encode_key(pub)
    assert text.startswith("ed25519:")
    assert text == text.lower()
    assert decode_key(text) == pub


@pytest.mark.parametrize(
    "bad",
    [
        "d75a98",                       # no prefix
        "ed25519:abc",                  # odd number of digits
        "ed25519:" + "zz" * 32,         # non-hex
        "ed25519:" + "aa" * 31,         # decodes to the wrong size
        "ED25519:" + "aa" * 32,         # the prefix is exact
    ],
)
def test_key_text_refusals(bad):
    with pytest.raises(ValueError):
        decode_key(bad)


# --- keycodec -------------------------------------------------------------------------

def test_pem_roundtrips():
    pub = public_key_from_seed(SEED)
    assert spki_pem_to_pubkey(pubkey_to_spki_pem(pub)) == pub
    assert pkcs8_pem_to_seed(seed_to_pkcs8_pem(SEED)) == SEED


def test_pem_shape():
    pem = pubkey_to_spki_pem(public_key_from_seed(SEED)).decode("ascii")
    assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert pem.endswith("-----END PUBLIC KEY-----\n")


def test_pem_accepts_crlf():
    pem = seed_to_pkcs8_pem(SEED).decode("ascii")
    assert pkcs8_pem_to_seed(pem.replace("\n", "\r\n").encode("ascii")) == SEED


def test_pem_refuses_the_wrong_block_and_bad_template():
    with pytest.raises(ValueError):
        spki_pem_to_pubkey(seed_to_pkcs8_pem(SEED))       # private PEM to the public decoder
    with pytest.raises(ValueError):
        pubkey_to_spki_pem(b"\x00" * 31)                  # key must be 32 bytes
    with pytest.raises(ValueError):
        spki_pem_to_pubkey(b"-----BEGIN PUBLIC KEY-----\nbm90IERFUg==\n-----END PUBLIC KEY-----\n")
