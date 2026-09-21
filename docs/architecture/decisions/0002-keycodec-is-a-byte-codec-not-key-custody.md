# 0002 — the key codec is a byte codec, not key custody

**Status:** **ACCEPTED** (2026-08-22) · **Type:** boundary
**Supersedes nothing.** Inherits the substance of thesmos ADR 0013, restated for archon.

## Context

`keycodec` converts between raw 32-byte Ed25519 keys and the two standard PEM
containers — PKCS#8 v1 (private) and SPKI (public), per RFC 5958 and RFC 5280.

Those are the same file formats a *key store* reads and writes. The temptation, every
time, is to let the module grow one convenience: read the key from this path, generate a
fresh one if it is missing, keep it in memory so we do not re-parse. Each step is small.
Together they turn a codec into a custodian, and a custodian is a security boundary.

archon is the identity floor for a constellation of repos. If this module ever holds a
key, every consumer inherits a key-handling surface it did not ask for.

## Decision

**`keycodec` is a pure, IO-free byte codec. It holds no key, reads no file, writes no
file, and draws no randomness.**

Concretely, in all three cores:

- Every function is bytes-in, bytes-out (or an error). No paths, no handles, no
  environment, no clock.
- No RNG. `seedToPkcs8Pem` takes a seed it is *given*; it never invents one. Key
  *generation* is custody, and custody lives in stele.
- No ASN.1 library. The Ed25519 DER is fixed-size, so encode is a constant template with
  the key spliced in, and decode is a template comparison. This is not cleverness — it is
  what keeps the module small enough to read in full, and what lets three languages agree
  byte for byte without three ASN.1 dependencies behaving three ways at the edges.
- Rejection is part of the contract, not an implementation detail. PKCS#8 **v2**, bare
  DER, a cross-template PEM, bad base64, a wrong OID, a short key, bad unused-bits — all
  rejected, and all pinned by the `keycodec` conformance family. A codec that differs on
  what it *refuses* is a codec that differs.

The reject *reason* is deliberately **not** pinned. A core's error message is its own
diagnostic; the reject *decision* is what must agree across three languages.

## Consequences

- A consumer that needs custody needs stele, not archon. That is the correct shape: the
  layer that can read a private key off disk should be a layer you have to go get.
- `keycodec` stays testable with no fixtures and no filesystem — the whole family is
  hex in, PEM out.
- The 15 `keycodec` conformance cases can be authored from the RFC templates
  independently of any implementation, which is what makes them an oracle rather than a
  transcript of whatever the first core happened to do.

## Resolved — the private half stays

The PKCS#8 **private** half (`seedToPkcs8Pem` / `pkcs8PemToSeed`) was left open here as
arguably stele's, not archon's: it is the only part of this module that touches private
key material, even though it never *holds* it. It was kept because narrowing later is
safe and copying less is not.

**stele drew the line itself, and it falls on archon's side of this module.** Asked where
custody ends, stele's maintainers answered: *"CUSTODY AND CEREMONY STAY WHOLLY MINE. Key storage,
encryption at rest (ADR 0012, age), the root ceremony, the key-epoch registry,
compromise-response — operational facts about a running node's secrets, inseparable from
my boot path and my fail-closed guards."*

Every item on that list is a **thing stele does with a key over time**. Not one of them is
*spelling a seed as bytes*. The codec has no RNG, no storage, no lifetime, and no boot
path; it reads a seed it is handed and writes the container RFC 5958 defines. Deleting it
from archon would not move custody one inch toward stele — it would only mean the
private-side container gets re-derived by whoever needs it next, three times, which is the
failure mode [0001](0001-archon-scope.md) exists to prevent.

So the question is closed the way the Decision above already argued, but now on stele's
authority rather than archon's assumption: **a codec is not custody, and the boundary is
drawn at the operational verbs, not at the sensitivity of the bytes.**

⛔ **What stele asked for and will not get from archon.** The same answer said stele has no
principal type — *"[]byte pubkeys threaded through admission and the read-gate"* — and
that *"if archon tier 2 gives me a principal with a PoP envelope I would adopt it."* Tier 2
was subsequently **retired** ([0001](0001-archon-scope.md), Open questions). archon ships no
principal and no PoP envelope, and there is no tier that would. stele's absence is real;
archon is not the repo that fills it.
