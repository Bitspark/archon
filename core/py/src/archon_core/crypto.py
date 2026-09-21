"""Ed25519 signing and verification — the floor's only cryptography.

Like the other cores, this binds an existing Ed25519 implementation and writes none of its
own curve arithmetic. The binding here is PyCryptodome, chosen for one reason the mainstream
alternative cannot meet: `sign_in_domain` is Ed25519ph with the domain as the RFC 8032 §5.1
context string, and `cryptography`'s Ed25519 exposes only `sign(data)` — pure Ed25519, no
prehash, no context. PyCryptodome's `eddsa.new(key, 'rfc8032', context=...)` reaches it.

- `sign` / `verify` — raw Ed25519 over the message bytes.
- `sign_in_domain` / `verify_in_domain` — DOMAIN-SEPARATED: Ed25519ph with the domain as the
  context. A signature made in one domain verifies in no other and never as a raw signature.

Verification is fail-closed: every shape failure collapses to False rather than raising, so a
caller cannot mistake "malformed" for "valid".
"""

from Crypto.Hash import SHA512
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
SEED_SIZE = 32
#: The longest domain (RFC 8032 context) a signature can be made in, in bytes.
MAX_DOMAIN_SIZE = 255

__all__ = [
    "PUBLIC_KEY_SIZE",
    "SIGNATURE_SIZE",
    "SEED_SIZE",
    "MAX_DOMAIN_SIZE",
    "public_key_from_seed",
    "sign",
    "verify",
    "sign_in_domain",
    "verify_in_domain",
]


def _private(seed: bytes):
    if len(seed) != SEED_SIZE:
        raise ValueError(f"crypto: seed must be {SEED_SIZE} bytes, got {len(seed)}")
    return ECC.construct(curve="Ed25519", seed=bytes(seed))


def _public(pubkey: bytes):
    # Importing an encoded SPKI is the only route PyCryptodome offers from 32 raw bytes.
    return ECC.import_key(_SPKI_PREFIX + bytes(pubkey))


# The order of the prime-order subgroup, L = 2^252 + 27742317777372353535851937790883648493.
_L = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED


def _is_prime_order_point(encoded: bytes) -> bool:
    """ADR 0008: `encoded` is a canonical encoding of a point of order exactly L.

    False for a point not on the curve, a non-canonical spelling (y >= p, or x = 0 with the
    sign bit set: the point re-encodes to different bytes), the identity, any small-order
    point and any mixed-order point. This is archon's acceptance policy, not the library's:
    RFC 8032 permits more than one verification equation, and implementations genuinely
    differ — PyCryptodome's is cofactored, so on its own it accepts a mixed-order key for
    every message and a small-order R, where Go and ed25519-dalek (uncofactored) accept the
    former for one message in eight and refuse the latter. Restricting both points to the
    prime-order subgroup is where the two equations agree; checking it here, explicitly, is
    what makes the accepted set archon's rather than the library's.

    It is a check, not curve arithmetic we wrote: `[L]A` uses the library's own point
    multiplication, and a point is in the prime-order subgroup exactly when `[L]A` is the
    identity. That is stronger than a small-order check (`[8]A`), which passes a mixed-order
    point, and stronger than a blocklist, which misses non-canonical spellings.
    """
    try:
        key = ECC.import_key(_SPKI_PREFIX + bytes(encoded))
        if key.public_key().export_key(format="raw") != bytes(encoded):
            return False
        point = key.pointQ
        if point.is_point_at_infinity():
            return False
        return (point * _L).is_point_at_infinity()
    except Exception:  # noqa: BLE001 - an unusable point is not a valid key either
        return False


def _in_profile(pubkey: bytes, signature: bytes) -> bool:
    """The profile's shape conditions: sizes, and A and R prime-order points. S's range
    (0 <= S < L) is PyCryptodome's own check, so it is not repeated here."""
    return (
        len(pubkey) == PUBLIC_KEY_SIZE
        and len(signature) == SIGNATURE_SIZE
        and _is_prime_order_point(pubkey)
        and _is_prime_order_point(signature[:PUBLIC_KEY_SIZE])
    )


# The SPKI template keycodec also uses. Importing an encoded public key is the only route
# PyCryptodome offers from 32 raw bytes, so the prefix lives here too rather than crossing a
# module boundary for four constants.
_SPKI_PREFIX = bytes(
    [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]
)


def public_key_from_seed(seed: bytes) -> bytes:
    """The 32-byte public key for `seed`. Raises when the seed is not 32 bytes."""
    return _private(seed).public_key().export_key(format="raw")


def sign(seed: bytes, message: bytes) -> bytes:
    """A raw Ed25519 signature over `message`."""
    return eddsa.new(_private(seed), "rfc8032").sign(bytes(message))


def verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """True when `signature` is `pubkey`'s over `message`, within the verification
    profile (ADR 0008). False on any shape failure, including a key or an R outside the
    profile."""
    if not _in_profile(pubkey, signature):
        return False
    try:
        eddsa.new(_public(pubkey), "rfc8032").verify(bytes(message), bytes(signature))
        return True
    except (ValueError, TypeError):
        return False


def _check_domain(domain: str) -> None:
    # A domain is 1..=255 bytes of UTF-8. `str.encode` raises (a ValueError) on a lone
    # surrogate rather than substituting, which is the behaviour the profile requires.
    n = len(domain.encode("utf-8"))
    if n == 0:
        raise ValueError("crypto: domain is empty")
    if n > MAX_DOMAIN_SIZE:
        raise ValueError(f"crypto: domain is {n} bytes, max {MAX_DOMAIN_SIZE}")


def sign_in_domain(seed: bytes, domain: str, message: bytes) -> bytes:
    """Signs `message` in `domain` — Ed25519ph with the domain as the RFC 8032 context.

    Raises, never silently signs raw, when the domain is empty or longer than 255 bytes.
    """
    _check_domain(domain)
    digest = SHA512.new(bytes(message))
    signer = eddsa.new(_private(seed), "rfc8032", context=domain.encode("utf-8"))
    return signer.sign(digest)


def verify_in_domain(
    pubkey: bytes, domain: str, message: bytes, signature: bytes
) -> bool:
    """True when `signature` is `pubkey`'s over `message` IN `domain`, within the
    verification profile (ADR 0008). False otherwise."""
    try:
        _check_domain(domain)
    except ValueError:
        return False
    if not _in_profile(pubkey, signature):
        return False
    try:
        digest = SHA512.new(bytes(message))
        verifier = eddsa.new(_public(pubkey), "rfc8032", context=domain.encode("utf-8"))
        verifier.verify(digest, bytes(signature))
        return True
    except (ValueError, TypeError):
        return False
