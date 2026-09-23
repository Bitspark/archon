"""archon core — the identity floor in Python.

Ed25519 key bytes, one canonical text spelling, the SPKI/PKCS-8 codecs, and
domain-separated signing. It answers two questions — are these bytes that key, and is this
signature that key's — and nothing about authority or custody.

This core is held to the same hand-authored oracle as the Go, Rust and TypeScript cores;
if it disagrees with them about whether something is valid, that disagreement is the defect.
"""

from .crypto import (
    MAX_DOMAIN_SIZE,
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    SIGNATURE_SIZE,
    public_key_from_seed,
    sign,
    sign_in_domain,
    verify,
    verify_in_domain,
)
from .hexbytes import pubkey_from_hex, seed_from_hex, signature_from_hex, to_hex
from .keycodec import (
    pkcs8_pem_to_seed,
    pubkey_to_spki_pem,
    seed_to_pkcs8_pem,
    spki_pem_to_pubkey,
)
from .keytext import decode_key, encode_key

__version__ = "0.8.1"

__all__ = [
    "MAX_DOMAIN_SIZE",
    "PUBLIC_KEY_SIZE",
    "SEED_SIZE",
    "SIGNATURE_SIZE",
    "public_key_from_seed",
    "sign",
    "verify",
    "sign_in_domain",
    "verify_in_domain",
    "to_hex",
    "seed_from_hex",
    "pubkey_from_hex",
    "signature_from_hex",
    "encode_key",
    "decode_key",
    "pubkey_to_spki_pem",
    "seed_to_pkcs8_pem",
    "spki_pem_to_pubkey",
    "pkcs8_pem_to_seed",
    "__version__",
]
