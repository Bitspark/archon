# 0004 — the sdk layer: possession and the envelope, one layer above the floor

**Status:** **ACCEPTED** (2026-09-09) · **Type:** scope

> **Status note, 2026-09-10 (the archon maintainers) — a rule this layer already followed, stated
> once.** At the sdk layer *every* input is runtime data — the challenger's nonce, the
> binding, and the seed, which comes from custody — so a shape failure on any of them is an
> **error** (`Result` / `error` / throw), never a panic. The floor's *"derive panics on a bad
> seed"* stays the floor's: it is right at the layer that holds a seed by construction.
> `possession.Prove` already errors on a short nonce and an empty binding for this reason;
> `login.Prove` (archon#19) errors on a wrong-size seed for the same reason. What #19 exposed
> is that the Go `possession.Prove` and `envelope.Seal` do no length check and inherit
> `SignInDomain`'s panic (rs enforces `&[u8; 32]` by type; ts throws) — closed by a separate
> sdk-only change, no floor change. ADR 0007 §C is the consumer of this rule.
**Re-rules one subtraction of [0001](0001-archon-scope.md):** proof of possession was cut
from archon as *"kosmos's — protocol vocabulary, not a free-standing primitive."* It is a
free-standing scheme here, one layer above the floor. Ruled by the operator on 2026-09-09;
the measurement is `docs/growth-plan.md` §7.

## Context

0001 pointed at kosmos as the owner of proof of possession and of client/server attach.
Measured on 2026-09-09: kosmos has **zero code files** — no go, rs or ts — and no commit
since 2026-07-16. Its charter describes exactly this layer; the pointer pointed at a spec.
Nobody provides possession or a signed container in code, and every new consumer of one
key across several repositories will hand-roll both — badly, because an unbound proof of
possession looks like a proof and is relayable.

Why not in the floor itself: the floor's identity is that thirty-plus vectors cover every
function; sockets, sessions and clocks cannot be pinned by byte vectors; and a proof of
possession is only correct with an input — the channel binding — that the floor cannot
have. (growth-plan §7.2.)

## Decision

**A second layer, in this repository, above the floor:** `sdk/rs` (`archon-sdk`),
`sdk/go` (`github.com/Bitspark/archon/sdk/go`), `sdk/ts` (`@bitspark/archon-sdk`). Each
depends on the floor and nothing else. Consumers who want only the floor import only the
floor. It holds two schemes, both signing in the *caller's* domain through
`sign_in_domain`:

**Possession** — *can they sign, right now, for this channel?* The challenger supplies a
`nonce` (≥ 16 bytes) and a `binding`; the prover signs
`0x01 ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖ binding`. **An empty binding is
refused**: the binding is what makes the proof unrelayable, and a proof without one is
not a proof. A nonce under 16 bytes is refused rather than weakened.

**Envelope** — *these bytes, signed by this key, in this domain.*
`"arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ sig[64] ‖ payload`, with
`sig = sign_in_domain(seed, domain, 0x02 ‖ payload)`. `open` takes the domain the
*verifier* expects and refuses an envelope claiming another: the verifier chooses the
domain, never the envelope. Whether to trust the key it names is the verifier's.

The one-byte scheme tags (`0x01` possession, `0x02` envelope) keep the two from ever
being the same signed bytes in the same domain — pinned by `envelope_open/
possession-sig-rejected`.

**Three lines, drawn at founding:**

1. **Entropy, time and channel binding are arguments. The sdk never sources them.** No
   RNG, no clock, no socket. This is what makes every byte it emits a deterministic
   function of its inputs, and therefore pinnable: `vectors/sdk.json`, 36 cases in 4
   families, three lanes, 108 case-checks, signatures derived with OpenSSL 3.2.4 outside
   all three cores.
2. **JWS, never JWT.** In the envelope: version, domain, key, signature, payload. Out,
   permanently: expiry, issuer, audience, key-id, nonce. Each is either policy — whose
   clock, whose trust? — or a second spelling of the key, and both are the consumer's.
3. **Connection setup stays out.** It *is* the transport. The sdk hands kosmos, or any
   server, the bytes to move; it never opens a socket.

## Consequences

- kosmos's paper charter narrows by exactly this: it keeps attach / invoke / serve,
  resolution, enforcement and custody; possession-scheme and envelope live here, and its
  "typed sign-exchange (closed purpose enum)" is, when built, a consumer of
  `sign_in_domain` plus these two layouts.
- The oracle discipline extends upward unchanged: a second oracle file, the same harness,
  a second family table, three more conformance CLIs. `node conformance/check.mjs` runs
  both.
- `go.work` at the repository root lets `sdk/go` resolve `core/go` from the checkout;
  consumers resolve `sdk/go`'s pseudo-versioned `require` from GitHub. `sdk/ts` consumes
  `core/ts` through a `file:` dependency, which the publish workflow must rewrite to a
  registry version when the sdk is first published.
