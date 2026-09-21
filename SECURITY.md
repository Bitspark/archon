# Security

## Reporting

Report a vulnerability privately, through GitHub's *Report a vulnerability* on this
repository's Security tab, and not in an issue or a pull request. Say what the flaw is,
where it is, and how to observe it; a failing case against `conformance/check.mjs`, or a
seed and a signature, is enough. You will hear back within five working days with whether
it is confirmed and what the fix will be.

## Scope

archon is an identity floor: Ed25519 key bytes, one canonical way to spell a key as text,
the SPKI and PKCS-8 codecs, domain-separated signing, and a proof-of-possession login
scheme. It is the layer a caller trusts to say *these bytes are that key* and *this
signature is that key's*. A way to make it say either falsely is a security report.

Concretely, in any of the three cores:

- A signature that verifies against a message or a key it was not made for — including
  across a domain separator, which exists precisely to keep one context's signature from
  counting in another.
- A key text, PEM or SPKI encoding that round-trips to **different bytes** than it was
  built from, or that is accepted when it is malformed. Length, prefix and alphabet are
  part of the grammar, not decoration.
- **A divergence between the cores.** Rust, Go and TypeScript are held to one oracle in
  `vectors/` on purpose: if they disagree about whether something is a valid key, a valid
  signature or a valid key text, that disagreement is itself the vulnerability, because a
  consumer's two ends may not be in the same language.
- In the login scheme: a statement that binds to an audience it was not issued for, a
  proof that replays, an offer that can be taken twice, or an authority payload that the
  scheme reads rather than passes through. The audience is configured and never read from
  the wire; a way to make the wire decide it is a report.
- Key material reaching a log, an error string, a terminal or a file it was not asked to
  be written to.

## Not in scope

**Custody is not here.** Storing a key, encrypting it at rest, rotating it, running a root
ceremony, or deciding when a key is retired — none of that is archon's, and a flaw in how
a consumer keeps a key is reported to that consumer. `archon key` writes a file you name
and reads a file you name; it manages nothing.

**Authority is not here.** What a key is *allowed* to do is the law layer's question.
`AdmitAuthority` hands the authority payload to the consumer without reading it. A flaw in
what a consumer admits is reported to that consumer.

The conformance harness and the vector tooling are developer tooling that runs on a
checkout's own files; a flaw in them is a bug.

## Supported versions

archon is pre-1.0. The latest minor release is supported, in all three languages together;
a fix ships as a new release across the cores rather than a patch to one of them.
