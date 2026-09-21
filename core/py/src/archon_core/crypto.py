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


def _is_small_order(key) -> bool:
    """True when the public key is a small-order point.

    ⚠ This is archon's acceptance policy, not the library's. RFC 8032 permits more than one
    verification equation, and implementations genuinely differ here: Go's `crypto/ed25519`
    and `ed25519-dalek` REJECT small-order public keys, while cofactored (ZIP-215) verifiers
    ACCEPT them. The TypeScript core meets the same divergence and settles it with
    @noble's `{ zip215: false }`; PyCryptodome offers no such flag, so the check is explicit
    here.

    It is a check, not curve arithmetic we wrote: `[8]A` uses the library's own point
    multiplication, and a point is small-order exactly when `[8]A` is the identity. That is
    stronger than a blocklist of known encodings, which would miss any non-canonical
    spelling of the same points.

    Without this, two oracle cases — `small-order-pubkey-order4` and
    `small-order-pubkey-order8` — verify as TRUE in Python and FALSE in the other three
    cores, which is precisely the cross-language disagreement the oracle exists to catch.
    """
    try:
        return (key.pointQ * 8).is_point_at_infinity()
    except Exception:  # noqa: BLE001 - an unusable point is not a valid key either
        return True


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
    """True when `signature` is `pubkey`'s over `message`. False on any shape failure."""
    if len(pubkey) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        key = _public(pubkey)
        if _is_small_order(key):
            return False
        eddsa.new(key, "rfc8032").verify(bytes(message), bytes(signature))
        return True
    except (ValueError, TypeError):
        return False


def _check_domain(domain: str) -> None:
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
    """True when `signature` is `pubkey`'s over `message` IN `domain`. False otherwise."""
    if len(pubkey) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        _check_domain(domain)
    except ValueError:
        return False
    try:
        key = _public(pubkey)
        if _is_small_order(key):
            return False
        digest = SHA512.new(bytes(message))
        verifier = eddsa.new(key, "rfc8032", context=domain.encode("utf-8"))
        verifier.verify(digest, bytes(signature))
        return True
    except (ValueError, TypeError):
        return False
