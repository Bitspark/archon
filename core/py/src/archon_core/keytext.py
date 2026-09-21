"""The canonical key spelling: `ed25519:<64 lowercase hex>`.

One spelling, in every language. The prefix is required; the body is exactly 64 hex digits
decoding to a 32-byte public key. Length and alphabet are part of the grammar, not decoration
— a body of the wrong length is refused even when it is valid hex.
"""

from .crypto import PUBLIC_KEY_SIZE

_PREFIX = "ed25519:"

__all__ = ["encode_key", "decode_key"]

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def encode_key(pubkey: bytes) -> str:
    """`ed25519:` followed by the key as lowercase hex."""
    return _PREFIX + bytes(pubkey).hex()


def decode_key(text: str) -> bytes:
    """The 32 key bytes, or raises — missing prefix, odd length, non-hex, wrong size."""
    if not text.startswith(_PREFIX):
        raise ValueError(f"keytext: missing {_PREFIX!r} prefix")
    body = text[len(_PREFIX) :]
    if len(body) % 2 != 0:
        raise ValueError("keytext: key body has an odd number of hex digits")
    for ch in body:
        if ch not in _HEX_DIGITS:
            raise ValueError(f"keytext: non-hex character in key body: {ch!r}")
    out = bytes.fromhex(body)
    if len(out) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"keytext: decoded key is {len(out)} bytes, expected {PUBLIC_KEY_SIZE}"
        )
    return out
