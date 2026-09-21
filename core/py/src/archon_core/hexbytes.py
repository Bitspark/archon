"""Typed, fail-closed hex spellings.

Not a hex helper — every language has one — but the FIXED SIZE. Each decoder accepts exactly
its type's byte count or fails; the length is checked on the TEXT before any byte is decoded,
so a wrong-length input never reaches the decoder. Either case in, lowercase out. No `0x`, no
whitespace, no odd-length bodies.
"""

from .crypto import PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE

__all__ = ["to_hex", "seed_from_hex", "pubkey_from_hex", "signature_from_hex"]

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def to_hex(data: bytes) -> str:
    """Lowercase hex, no prefix."""
    return bytes(data).hex()


def _fixed(text: str, n: int, what: str) -> bytes:
    if len(text) != n * 2:
        raise ValueError(
            f"hexbytes: {what} hex is {len(text)} characters, expected {n * 2}"
        )
    # Python's bytes.fromhex accepts whitespace; archon's grammar does not. Check the
    # alphabet explicitly rather than relying on the decoder's laxer rules — the other
    # cores reject a space here, and agreement is the point.
    for ch in text:
        if ch not in _HEX_DIGITS:
            raise ValueError(f"hexbytes: {what}: non-hex character {ch!r}")
    return bytes.fromhex(text)


def seed_from_hex(text: str) -> bytes:
    """Exactly 32 bytes, or raises."""
    return _fixed(text, SEED_SIZE, "seed")


def pubkey_from_hex(text: str) -> bytes:
    """Exactly 32 bytes, or raises."""
    return _fixed(text, PUBLIC_KEY_SIZE, "public key")


def signature_from_hex(text: str) -> bytes:
    """Exactly 64 bytes, or raises."""
    return _fixed(text, SIGNATURE_SIZE, "signature")
