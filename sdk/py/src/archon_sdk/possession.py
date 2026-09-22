"""Proof of possession — *can they sign, right now, for this channel?*

The challenger picks a `nonce` (fresh entropy, at least 16 bytes — its own, never this
package's) and a `binding` (something only this channel has: a session key, a TLS exporter,
the server's identity — the transport's, never this package's). The prover signs a fixed
layout of both in the protocol's domain; the challenger verifies with the prover's public key.

**The binding is what makes this a proof.** A signed nonce alone is relayable: an attacker
facing the server as the victim forwards the server's nonce to the victim under some pretext,
gets it signed, and presents the signature. Bound to the channel, the signature is worthless
anywhere else. So an empty binding is refused outright — the thing it would produce looks like
a proof and is not one.

The signed bytes are `SCHEME_TAG ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖ binding`,
signed with `archon_core.sign_in_domain` in the caller's domain. The tag keeps a possession
message and an envelope payload in the same domain from ever being the same bytes.
"""

from archon_core import sign_in_domain, verify_in_domain

#: The first byte of every possession message. Distinct from `envelope.SCHEME_TAG`.
SCHEME_TAG = 0x01

#: The shortest nonce accepted, in bytes. Below this a proof is guessable, so it is refused
#: rather than weakened.
MIN_NONCE_SIZE = 16

#: The longest nonce or binding, in bytes — the u16 length prefix's bound.
MAX_FIELD_SIZE = 0xFFFF


def prove(seed: bytes, domain: str, nonce: bytes, binding: bytes) -> bytes:
    """Prove possession of the key behind `seed` to a challenger who supplied `nonce` and
    `binding`, in `domain`.

    Raises `ValueError` on an invalid domain (see `archon_core.sign_in_domain`), a seed that
    is not 32 bytes, a nonce shorter than `MIN_NONCE_SIZE`, an empty binding, or either field
    over `MAX_FIELD_SIZE`.
    """
    return sign_in_domain(seed, domain, message_bytes(nonce, binding))


def verify(pubkey: bytes, domain: str, nonce: bytes, binding: bytes, signature: bytes) -> bool:
    """True when `signature` was made by the key behind `pubkey` over this `nonce` and
    `binding` in `domain`.

    Total: every shape failure — bad domain, short nonce, empty binding, wrong-sized key or
    signature — is False, never an exception, so a caller cannot mistake "malformed" for
    "valid".
    """
    try:
        message = message_bytes(nonce, binding)
    except (ValueError, TypeError):
        return False
    return verify_in_domain(pubkey, domain, message, signature)


def message_bytes(nonce: bytes, binding: bytes) -> bytes:
    """The pinned layout of what gets signed. Public so a consumer can pin it too."""
    nonce = bytes(nonce)
    binding = bytes(binding)
    if len(nonce) < MIN_NONCE_SIZE:
        raise ValueError(f"possession: nonce is {len(nonce)} bytes, min {MIN_NONCE_SIZE}")
    if len(nonce) > MAX_FIELD_SIZE:
        raise ValueError(f"possession: nonce is {len(nonce)} bytes, max {MAX_FIELD_SIZE}")
    if len(binding) == 0:
        raise ValueError("possession: binding is empty — an unbound proof is not a proof")
    if len(binding) > MAX_FIELD_SIZE:
        raise ValueError(f"possession: binding is {len(binding)} bytes, max {MAX_FIELD_SIZE}")
    return (
        bytes([SCHEME_TAG])
        + len(nonce).to_bytes(2, "big")
        + nonce
        + len(binding).to_bytes(2, "big")
        + binding
    )
