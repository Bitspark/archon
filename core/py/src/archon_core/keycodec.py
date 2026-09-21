"""The SPKI and PKCS-8 PEM codecs — a BYTE codec, not key custody.

For an Ed25519 key the DER is fixed-length and fixed-shape, so this is a template match, not
an ASN.1 parser: a 12-byte SPKI prefix or a 16-byte PKCS-8 v1 prefix, then exactly 32 key
bytes. Anything else is refused. That is deliberate — a general parser would accept encodings
the other cores would not, and agreement is the claim.

RFC 5280 (SPKI) and RFC 5958 (PKCS-8 v1). PKCS-8 v2, which carries the public key alongside
the private one, is NOT accepted: it is a second spelling of the same key.
"""

import base64

from .crypto import PUBLIC_KEY_SIZE

_KEY_LEN = PUBLIC_KEY_SIZE  # 32; the seed is the same length

_SPKI_PREFIX = bytes(
    [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]
)
_PKCS8_PREFIX = bytes(
    [
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]
)

_PEM_PUBLIC = "PUBLIC KEY"
_PEM_PRIVATE = "PRIVATE KEY"

__all__ = [
    "pubkey_to_spki_pem",
    "seed_to_pkcs8_pem",
    "spki_pem_to_pubkey",
    "pkcs8_pem_to_seed",
]


def _encode(key: bytes, prefix: bytes, pem_type: str) -> bytes:
    if len(key) != _KEY_LEN:
        raise ValueError(f"keycodec: key must be {_KEY_LEN} bytes, got {len(key)}")
    body = base64.b64encode(prefix + bytes(key)).decode("ascii")
    return (
        f"-----BEGIN {pem_type}-----\n{body}\n-----END {pem_type}-----\n"
    ).encode("ascii")


def _decode(pem_bytes: bytes, prefix: bytes, pem_type: str) -> bytes:
    text = bytes(pem_bytes).decode("ascii", errors="strict").replace("\r\n", "\n")
    text = text.rstrip("\n")
    begin = f"-----BEGIN {pem_type}-----"
    end = f"-----END {pem_type}-----"
    lines = text.split("\n")
    if len(lines) < 3 or lines[0] != begin or lines[-1] != end:
        raise ValueError(f"keycodec: not a {pem_type!r} PEM block")
    try:
        # validate=True: base64 that carries stray characters is refused rather than
        # silently skipped, which is what a lax decoder would do.
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except Exception as exc:  # noqa: BLE001 - surfaced as one codec error
        raise ValueError(f"keycodec: invalid base64 in PEM body: {exc}") from exc
    if len(der) != len(prefix) + _KEY_LEN or der[: len(prefix)] != prefix:
        raise ValueError(
            f"keycodec: DER does not match the {pem_type} ed25519-key-codec-v1 template"
        )
    return der[len(prefix) :]


def pubkey_to_spki_pem(pubkey: bytes) -> bytes:
    """A public key as an RFC 5280 SPKI PEM block."""
    return _encode(pubkey, _SPKI_PREFIX, _PEM_PUBLIC)


def seed_to_pkcs8_pem(seed: bytes) -> bytes:
    """A seed as an RFC 5958 PKCS-8 v1 PEM block."""
    return _encode(seed, _PKCS8_PREFIX, _PEM_PRIVATE)


def spki_pem_to_pubkey(pem_bytes: bytes) -> bytes:
    """The 32 public-key bytes from an SPKI PEM block, or raises."""
    return _decode(pem_bytes, _SPKI_PREFIX, _PEM_PUBLIC)


def pkcs8_pem_to_seed(pem_bytes: bytes) -> bytes:
    """The 32 seed bytes from a PKCS-8 v1 PEM block, or raises."""
    return _decode(pem_bytes, _PKCS8_PREFIX, _PEM_PRIVATE)
