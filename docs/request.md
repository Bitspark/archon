# archon request authentication and key enrollment — the profiles

**Status:** provisional draft for [archon#48](https://github.com/Bitspark/archon/issues/48). The
design is ADR [0010](architecture/decisions/0010-request-authentication-and-key-enrollment-profiles.md).
**Every constant and byte layout here is PROVISIONAL** until vectors and the failure tests of §7
exist; until then nothing may pin to it. · **Layer:** `sdk/` (transcripts, parsing, pure
verification) and `server/` (extraction, clock, replay), three lanes (ADR 0005, 0007 §B).

This document defines **only what nothing else defines**: which HTTP components a request proof
covers, the exact bytes that are signed, the strict grammar a verifier accepts, the order in which
it checks, and the enrollment binding. The HTTP signature model is RFC 9421's, the body digest is
RFC 9530's, the field syntax is a strict subset of RFC 8941's, and the signature construction is
archon's (ADR 0008): Ed25519ph with the domain as the RFC 8032 context.

## 1. Provisional constants

| name | value | meaning |
|---|---|---|
| request domain | `archon-request/1` | the RFC 8032 context every request signature is made in |
| profile tag | `archon-request/1` | the `tag` signature parameter; a verifier accepts only this |
| signature label | `archon` | the one dictionary member in `Signature-Input` and `Signature` |
| audience echo | `Archon-Audience` | the header carrying the client's configured audience, checked, never trusted |
| enrollment domain | `archon-enroll/1` | the context of an enrollment proof (§6) |
| identifier size | 16..=64 bytes | the `nonce`'s entropy: at least 128 bits, and a bound |

## 2. The audience

The audience is the service's base URL as login defines it (`docs/login.md` §2): scheme and host
lowercased, default ports omitted, no query, no fragment, trailing slash trimmed. A client takes
it from **its own configuration** for the service it means to call; a verifier takes it from
**its own configuration**. The `Archon-Audience` header carries the client's value so the two can
be **compared byte for byte**. It is never used to decide anything else: the verifier's value is
the only one that builds a signature base.

## 3. The client

Given the request it will send (method, target, header fields, body), its key, its configured
audience and a list of product-declared headers:

1. **Digest the body.** `Content-Digest: sha-256=:<base64 of SHA-256(content)>:` — exactly one
   member, standard base64 with padding, over the content as sent (no content coding in v1), the
   empty string's digest for an empty body.
2. **Echo the audience.** `Archon-Audience: <audience>`.
3. **Choose the coverage**, in this order: `"@method"`, `"@target-uri"`, `"archon-audience"`,
   `"content-digest"`, then `"content-type"` if the request carries one, then each product-declared
   header the request carries, lowercased, in the product's declared order.
4. **Choose the parameters**, in this order: `created` (integer seconds since the epoch), `expires`
   (integer, `created < expires`), `nonce` (16..=64 fresh random bytes, unpadded base64url),
   `keyid` (the principal's canonical key text, `ed25519:<hex>`), `tag` (`archon-request/1`).
5. **Build the signature base** (§4) and sign it: `signInDomain(seed, "archon-request/1", base)`.
6. **Send** `Signature-Input: archon=<inner list with parameters>` and
   `Signature: archon=:<base64 of the 64-byte signature>:`.

### 3.1 What each value may be

Both ends refuse, rather than repair, anything outside these rules. "Visible ASCII" is 0x21–0x7E.

| value | rule |
|---|---|
| audience | visible ASCII; begins `http://` or `https://`; a non-empty authority (up to the next `/`, or the end) with no `@`; no `?` or `#`; does not end in `/`. It is compared byte for byte, never normalised. **The origin** is the audience up to its authority's end. |
| method | 1 or more `tchar` (RFC 9110 token), case kept |
| request-target | origin form: begins `/`; visible ASCII without `#`; 1..=8192 bytes |
| declared header name | 1 or more of `a-z 0-9 -`; not `archon-audience`, `content-digest`, `content-type`, `signature-input` or `signature` (the first three are covered anyway, the last two carry the proof) |
| covered field value | after removing leading and trailing SP and HTAB, 1..=8192 bytes of visible ASCII, SP and HTAB: no CR, LF, NUL, other control, or byte above 0x7E in v1 |
| `nonce` | 16..=64 bytes, as unpadded base64url (`A-Z a-z 0-9 - _`) in its one canonical spelling |
| `created`, `expires` | integers in 0..=999999999999999 (at most 15 digits), `created < expires` |
| base64 in `Signature` and `Content-Digest` | the standard alphabet with `=` padding, in its one canonical spelling (unused bits zero) |
| the verifier's `W`, `δ` | integers, `W ≥ 1`, `δ ≥ 0`, both at most 999999999999999 |

Header names are matched without regard to case. `Signature-Input` and `Signature` appear exactly
once. `Content-Type`, and each product-declared header, is covered **if and only if** the request
carries it: an uncovered one present is refused, and so is a covered one absent.

A retry is a new request: new `created`, new `expires`, new `nonce`, a new signature; the
application's idempotency key, if it uses one, is a product-declared header and stays the same.
A client adapter never follows a redirect with a signed request; it signs the new request anew.

## 4. The signature base

RFC 9421 §2.5, restricted. One line per covered component, in coverage order, each
`"<identifier>": <value>` followed by a line feed (0x0A), then the final line
`"@signature-params": <inner list with parameters>` with **no** trailing line feed:

```
"@method": POST
"@target-uri": https://dawn.example/api/v1/things?x=1
"archon-audience": https://dawn.example/api
"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
"@signature-params": ("@method" "@target-uri" "archon-audience" "content-digest");created=1789034640;expires=1789034700;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="ed25519:…";tag="archon-request/1"
```

- `@method` is the method token exactly as sent (case-sensitive).
- **`@target-uri` is built by the verifier from its configuration, never from the wire's
  authority:** the configured origin (the audience's scheme and authority) followed by the
  request's raw request-target in origin form — path and query exactly as received, not decoded,
  not normalised, duplicates and order kept. A request-target that is not origin form (absolute
  form, authority form, `*`) is refused. The client builds the same string from its own
  configuration and the target it sends.
- A header component's value is the field's value with leading and trailing whitespace removed.
  **A covered field that appears more than once is refused** in v1, rather than combined.
- The `@signature-params` value is the inner list exactly as it appears in `Signature-Input`
  (§5's grammar admits one spelling, so there is nothing to re-serialise).

## 5. What a verifier accepts

A strict subset of RFC 8941, so that each valid request has exactly one spelling:

```
Signature-Input = %s"archon=" inner-list
inner-list      = "(" component *( SP component ) ")" params
component       = DQUOTE ( "@method" / "@target-uri" / lc-field-name ) DQUOTE
params          = ";created=" int ";expires=" int ";nonce=" DQUOTE b64url DQUOTE
                  ";keyid=" DQUOTE principal DQUOTE ";tag=" DQUOTE "archon-request/1" DQUOTE
Signature       = %s"archon=:" base64-64-bytes ":"
Content-Digest  = %s"sha-256=:" base64-32-bytes ":"
int             = 1*15DIGIT           ; no sign, no leading zero unless the value is 0
```

Anything else is refused: another label or a second member, other or reordered parameters, an
`alg` parameter, a component list other than §3's order, an unknown derived component, a missing
covered field, a covered field the request lacks, whitespace other than the single spaces shown.

## 6. Key enrollment

An enrollment proof is the possession scheme (ADR 0004; `sdk/*/possession`) with the server's
fresh nonce (16 bytes or more), in domain `archon-enroll/1`, over this binding:

```
version         u8      0x01
purpose         u16be length ‖ UTF-8   e.g. "add-key", "rotate", "recover"; 1..=255 bytes
audience        u16be length ‖ UTF-8   the configured audience (§2)
transaction     u16be length ‖ bytes   the pending transaction's id; 1..=255 bytes
new key         32 bytes               the public key being enrolled
intent digest   32 bytes               SHA-256 of the service's immutable intent bytes
```

**The rules, refused at construction and false at verification:**

- the purpose is 1..=255 bytes of well-formed UTF-8 with no control character (U+0000–U+001F,
  U+007F);
- the audience is non-empty, well-formed UTF-8, with no control character;
- the transaction id is 1..=255 opaque bytes;
- the new key and the intent digest are exactly 32 bytes each;
- the whole binding fits the possession scheme's u16 field (65535 bytes);
- the nonce is at least 16 bytes, which is the possession scheme's own rule.

**The new key proves itself.** A prover whose key is not the binding's new key is refused, and a
verifier checks the proof under the new key the record names. The bytes are pinned by
`vectors/request.json` (`enroll_binding`, `enroll_prove`, `enroll_verify`), every signature
derived with OpenSSL outside the three cores; the sdk API is `enroll` in Go and Rust and
`enrollBinding` / `proveEnroll` / `verifyEnroll` in TypeScript, each with a signer form
(ADR 0009 §4).

The service creates the pending transaction (authorizing context, intended account, purpose, new
key, nonce, intent digest, expiry) only after validating the session or bootstrap credential, and
the verifier rebuilds the binding **from that record and its configured audience** — the
completion request names the transaction and carries the proof, nothing more. ADR 0010 §7 holds
the rules around it: same session or a reserved bootstrap credential at completion, completion as
the service's atomic operation, no adapter in which possession alone suffices.

## 7. The order a verifier checks, and the gate before this is frozen

A request verifier checks, refusing at the first failure. Steps 1–7 are the sdk's pure verification
(`request.Verify` in Go, `request::verify` in Rust, `verifyRequest` in TypeScript); steps 8–9 are the
server adapter's, which owns the clock, the replay store and what reaches the application:

1. `Signature-Input`, `Signature` and `Content-Digest` parse under §5, exactly once each.
2. `keyid` is a canonical principal; `tag` is the profile's.
3. Every covered component is present, once; the coverage order is §3's; the product-declared
   headers it requires are covered.
4. `Archon-Audience` equals the configured audience, byte for byte.
5. `Content-Digest` equals the SHA-256 of the received content (after transfer framing is removed,
   before any content decoding, before the application sees anything).
6. Freshness: `0 < expires − created ≤ W` and `created − δ ≤ now < expires + δ`, integers, with
   the deployment's `W` and `δ`.
7. The signature verifies under the principal in the request domain over the base §4 builds.
8. Replay: `insertIfAbsent(("archon-request/1", audience, principal, nonce), expires + δ)` returns
   `inserted`; `alreadyPresent` is a replay, `unavailable` fails closed.
9. The application receives an `AuthenticatedRequest`: the principal and the verified descriptor
   (method, target, covered headers, content digest).

**The server adapters.** Each server lane carries steps 8–9 over its own HTTP stack, and is held to
the gate's failure tests through that stack:

- **The replay store** answers one operation:
  `InsertIfAbsent(key, from, until) → inserted | alreadyPresent | unavailable`.
  - `key` is (profile, audience, principal, nonce); `from` is `created − δ`, the earliest moment a
    verifier could accept the proof; `until` is `expires + δ`, after which none can.
  - Concurrent inserts of one key answer `inserted` at most once, across every verifier in the
    acceptance scope. A store that cannot guarantee that, or cannot answer, says `unavailable`, and
    the request **fails closed** (503).
- **The in-memory reference store** is correct for one process. It refuses any entry whose `from`
  is earlier than the moment its process started, because an earlier incarnation might have
  accepted that proof and its memory is gone. A deployment with several verifiers supplies a shared
  store with the same contract.
- **Go:** `server/go/request` — `Verifier{Policy, Store, Clock}` with `Authenticate(*http.Request)`
  and `Middleware(http.Handler)`; `FromContext` gives the handler its `Authenticated`; `Memory` is
  the reference store. The request-target is `RequestURI`, the request line as received. A body
  over 1 MiB is refused (413), never truncated; a content coding or trailer is refused (400).

**The gate (ADR 0010 §8).** These constants and layouts are frozen — and this status line changed —
only when vectors pin the signature bases, signatures (derived outside the cores) and the
enrollment binding, **and** each lane passes, through its real HTTP framework: wrong-key and
dropped-context signers; query and path ambiguity; empty and modified bodies; missing and
duplicated covered fields; expiry bounds; concurrent duplicates; replay-store outage and failover;
restart; enrollment substitution and replay.
