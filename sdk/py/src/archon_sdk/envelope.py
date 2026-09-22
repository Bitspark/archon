"""The signed envelope — *these bytes, signed by this key, in this domain.*

A fixed binary container, JWS-shaped and deliberately not JWT-shaped::

    "arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ signature[64] ‖ payload

where `signature = sign_in_domain(seed, domain, SCHEME_TAG ‖ payload)`. The domain is bound
cryptographically (it is the RFC 8032 context), the public key is bound by verification, and
the payload is opaque: the envelope says nothing about what it means. **What is not here, on
purpose:** expiry, issuer, audience, key-id, nonce. Each is either policy — whose clock, whose
trust? — or a second spelling of the key, and both belong to the consumer.

`open` takes the domain the *verifier* expects and refuses an envelope that claims another.
The verifier chooses the domain; an envelope never gets to choose it for them. Whether to
trust the key it names is, again, the verifier's.
"""

from dataclasses import dataclass

from archon_core import (
    MAX_DOMAIN_SIZE,
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    public_key_from_seed,
    sign_in_domain,
    verify_in_domain,
)

#: The first four bytes of every envelope.
MAGIC = b"arcn"

#: The envelope format version.
VERSION = 0x01

#: The first byte of every signed envelope message. Distinct from `possession.SCHEME_TAG`.
SCHEME_TAG = 0x02


@dataclass(frozen=True)
class Opened:
    """What `open` returns: the sealing key and the payload, both verified."""

    #: The public key that sealed the envelope. Trusting it is the caller's decision.
    pubkey: bytes
    #: The payload, verbatim.
    payload: bytes


def seal(seed: bytes, domain: str, payload: bytes) -> bytes:
    """Seal `payload` in `domain` with the key behind `seed`.

    Raises `ValueError` on an invalid domain (see `archon_core.sign_in_domain`) or a seed
    that is not 32 bytes. An empty payload is allowed — the signed message is never empty,
    because of the scheme tag.
    """
    payload = bytes(payload)
    # Signing first: it is what validates the domain and the seed, so nothing below is
    # reached with either one wrong.
    signature = sign_in_domain(seed, domain, message_bytes(payload))
    pubkey = public_key_from_seed(seed)
    d = domain.encode("utf-8")
    return MAGIC + bytes([VERSION, len(d)]) + d + pubkey + signature + payload


def open(envelope: bytes, domain: str) -> Opened:  # noqa: A001 - the module is the namespace
    """Open `envelope`, which the caller expects to be sealed in `domain`.

    Raises `ValueError` — never returns a payload — when the bytes are not an envelope
    (magic, version, length), the envelope claims a different domain, or the signature does
    not verify.
    """
    envelope = bytes(envelope)
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if at + n > len(envelope):
            raise ValueError(f"envelope: truncated at byte {len(envelope)}")
        chunk = envelope[at : at + n]
        at += n
        return chunk

    if take(4) != MAGIC:
        raise ValueError("envelope: not an envelope, bad magic")
    version = take(1)[0]
    if version != VERSION:
        raise ValueError(f"envelope: unsupported version {version}")
    dlen = take(1)[0]
    if dlen == 0 or dlen > MAX_DOMAIN_SIZE:
        raise ValueError(f"envelope: domain length {dlen} out of range")
    claimed = take(dlen)
    # The verifier's expectation decides, before any signature is checked. An envelope that
    # names another domain is refused here even when its signature is genuine in that one.
    if claimed != domain.encode("utf-8"):
        raise ValueError("envelope: claims a different domain")
    pubkey = take(PUBLIC_KEY_SIZE)
    signature = take(SIGNATURE_SIZE)
    payload = envelope[at:]
    if not verify_in_domain(pubkey, domain, message_bytes(payload), signature):
        raise ValueError("envelope: signature does not verify")
    return Opened(pubkey=pubkey, payload=payload)


def message_bytes(payload: bytes) -> bytes:
    """The pinned layout of what gets signed: the scheme tag, then the payload verbatim."""
    return bytes([SCHEME_TAG]) + bytes(payload)
