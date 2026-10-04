"""The signer contract — *signing capability, not seeds* (ADR 0009 §2–4).

Every helper in this package can take a seed, which is right for a key held in software and
wrong for one that is not: a stored key behind ``archon sign --key``, or any backend a caller
wires in. So each signing helper also comes in three parts — a **pure** ``prepare`` (the exact
request it needs signed), the signer's own work, and a **pure** ``complete`` (the checked
signature, then packaging) — with a ``…_with`` convenience that runs the signer between them.
The seed functions are unchanged.

A `SigningRequest` is three things, and the scheme is a discriminated value, never a scheme
name plus an optional domain: the public key the caller expects, raw Ed25519 (`Raw`) or
Ed25519ph with the domain as the RFC 8032 context (`PhContext`), and the **original** message
bytes — never a digest; a backend that wants a prehash computes it inside its own adapter.

Three rules, all enforced here rather than trusted to a signer:

- A request is validated **before** the signer is called: a wrong-length key or a domain the
  floor refuses never reaches it.
- A signer **reports** what it can do (`Capabilities`), and a request outside that is refused
  before it is called. A signer that cannot carry a context declares raw only; it must never
  sign a `PhContext` request with an empty context instead, and if it does anyway, the check
  below catches it.
- Every returned signature is **verified** against the requested key, scheme, domain and bytes
  — never against values the signer echoes back. That does not prove that a signer signs
  deterministically (ADR 0008 §1.7 requires it); that is a property of the backend, tested
  against the ``domain_sign`` vectors.

The calls are synchronous, like the rest of this package; a signer that prompts or runs a
subprocess blocks, and is cancelled the way the caller cancels any blocking call.

Domain separation is not authorization: whoever may ask for signatures in a domain gets any
signature in that domain. Consent belongs to the caller that knows what the bytes mean.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Union

from archon_core import (
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
    SIGNATURE_SIZE,
    public_key_from_seed,
    sign,
    sign_in_domain,
    verify,
    verify_in_domain,
)

#: The name of raw Ed25519, in `Capabilities`.
RAW = "ed25519-raw"
#: The name of Ed25519ph with a context, in `Capabilities`.
PH_CONTEXT = "ed25519ph-context"


@dataclass(frozen=True)
class Raw:
    """Pure Ed25519 over the message. Carries no domain."""

    kind = RAW


@dataclass(frozen=True)
class PhContext:
    """Ed25519ph with `domain` as the RFC 8032 context."""

    domain: str
    kind = PH_CONTEXT


Scheme = Union[Raw, PhContext]


@dataclass(frozen=True)
class SigningRequest:
    """What a signer is asked to sign. `message` is always the original bytes."""

    expected_public_key: bytes
    scheme: Scheme
    message: bytes


@dataclass(frozen=True)
class Capabilities:
    """What a signer can do. `domains` of None means any domain the floor accepts."""

    schemes: tuple[str, ...]
    domains: Optional[tuple[str, ...]] = None


class Signer(Protocol):
    """A source of signatures. `sign` may prompt, call a subprocess or wait on a device."""

    @property
    def public_key(self) -> bytes: ...

    @property
    def capabilities(self) -> Capabilities: ...

    def sign(self, request: SigningRequest) -> bytes: ...


def validate(request: SigningRequest) -> None:
    """Raise `ValueError` unless `request` is in range: a 32-byte expected key, a known
    scheme, and — for `PhContext` — a domain the floor accepts. The domain is checked by the
    floor's own rule (it signs nothing with a throwaway key), so no copy of ADR 0008 §2 lives
    here to drift."""
    if not isinstance(request.expected_public_key, (bytes, bytearray)) or len(request.expected_public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(f"signer: the expected public key must be {PUBLIC_KEY_SIZE} bytes")
    if not isinstance(request.message, (bytes, bytearray)):
        raise ValueError("signer: the message must be bytes")
    if isinstance(request.scheme, Raw):
        return
    if not isinstance(request.scheme, PhContext):
        raise ValueError(f"signer: unknown scheme {request.scheme!r}")
    sign_in_domain(bytes(SEED_SIZE), request.scheme.domain, b"")


def check_signature(request: SigningRequest, signature: bytes) -> bytes:
    """The signature, if it verifies for exactly what was **requested**: its key, scheme,
    domain and original bytes. Raise `ValueError` otherwise."""
    validate(request)
    key, message = bytes(request.expected_public_key), bytes(request.message)
    ok = isinstance(signature, (bytes, bytearray)) and len(signature) == SIGNATURE_SIZE and (
        verify(key, message, bytes(signature))
        if isinstance(request.scheme, Raw)
        else verify_in_domain(key, request.scheme.domain, message, bytes(signature))
    )
    if not ok:
        raise ValueError("signer: the signature does not verify for the requested key, scheme and message")
    return bytes(signature)


def check_capability(signer: Signer, request: SigningRequest) -> None:
    """Raise `ValueError` unless `signer` claims to be able to sign `request`: its key is the
    expected one, and the scheme and domain are among its capabilities. Called before it is
    called."""
    if bytes(signer.public_key) != bytes(request.expected_public_key):
        raise ValueError("signer: this signer's key is not the expected key")
    caps = signer.capabilities
    if request.scheme.kind not in caps.schemes:
        raise ValueError(f"signer: this signer cannot produce {request.scheme.kind}")
    if isinstance(request.scheme, PhContext) and caps.domains is not None and request.scheme.domain not in caps.domains:
        raise ValueError(f"signer: this signer does not sign in domain {request.scheme.domain!r}")


def sign_with(signer: Signer, request: SigningRequest) -> bytes:
    """Validate, check the signer's capabilities, call it, and return the signature only if it
    verifies for what was requested."""
    validate(request)
    check_capability(signer, request)
    return check_signature(request, signer.sign(request))


class SeedSigner:
    """The software signer: a seed held in this process, both schemes, any domain the floor
    accepts, deterministic by the floor's construction. The seed is copied."""

    def __init__(self, seed: bytes):
        if len(seed) != SEED_SIZE:
            raise ValueError(f"signer: seed is {len(seed)} bytes, want {SEED_SIZE}")
        self._seed = bytes(seed)
        self._public_key = public_key_from_seed(self._seed)

    def __repr__(self) -> str:  # never the seed
        return f"SeedSigner(public_key={self._public_key.hex()})"

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(schemes=(RAW, PH_CONTEXT))

    def sign(self, request: SigningRequest) -> bytes:
        if isinstance(request.scheme, Raw):
            return sign(self._seed, request.message)
        return sign_in_domain(self._seed, request.scheme.domain, request.message)
