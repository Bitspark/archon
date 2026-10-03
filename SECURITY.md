# Security

## Reporting

Report a vulnerability privately, through GitHub's *Report a vulnerability* on this
repository's Security tab, and not in an issue or a pull request. Say what the flaw is,
where it is, and how to observe it; a failing case against `conformance/check.mjs`, or a
seed and a signature, is enough. You will hear back within five working days with whether
it is confirmed and what the fix will be.

## Scope

archon is an identity floor: Ed25519 key bytes, one canonical way to spell a key as text,
the SPKI and PKCS-8 codecs, domain-separated signing, a proof-of-possession login scheme,
and the command's password-protected key store. It is the layer a caller trusts to say
*these bytes are that key* and *this signature is that key's*. A way to make it say either
falsely is a security report.

Concretely, in any language archon ships ([languages](docs/languages.md)):

- A signature that verifies against a message or a key it was not made for — including
  across a domain separator, which exists precisely to keep one context's signature from
  counting in another.
- A key text, PEM or SPKI encoding that round-trips to **different bytes** than it was
  built from, or that is accepted when it is malformed. Length, prefix and alphabet are
  part of the grammar, not decoration.
- **A divergence between the cores.** Every core is held to one oracle in `vectors/` and
  one [verification profile](docs/architecture/decisions/0008-the-ed25519-verification-profile.md)
  on purpose: if two disagree about whether something is a valid key, a valid
  signature or a valid key text, that disagreement is itself the vulnerability, because a
  consumer's two ends may not be in the same language.
- In the login scheme: a statement that binds to an audience it was not issued for, a
  proof that replays, an offer that can be taken twice, or an authority payload that the
  scheme reads rather than passes through. The audience is configured and never read from
  the wire; a way to make the wire decide it is a report.
- In the command's key store (`archon key`, [the format](docs/keystore.md)): a stored file
  that opens under a password or a header it was not sealed with, a seed or a password
  written anywhere unencrypted or taken from argv, or a file that one of the three binaries
  reads differently from another.
- Key material reaching a log, an error string, a terminal or a file it was not asked to
  be written to.

## Not in scope

**Custody, past the command's one store, is not here.** The libraries hold no key: `core`
and `sdk` take the seed bytes they are given and never learn a file path, a password or a
directory. The store above is archon's, accepted in
[ADR 0007](docs/architecture/decisions/0007-custody-in-the-command-and-the-login-server-tier.md);
nothing else about keeping a key is — rotating it, running a root ceremony, retiring it,
recovering it, hardware tokens, agents, or how a consumer keeps a key anywhere else. A flaw
there is reported to that consumer. Outside the store, `keygen --out`, `--key-file` and
`--seed-file` write or read a file you name and manage nothing.

**Authority is not here.** What a key is *allowed* to do is the law layer's question.
`AdmitAuthority` hands the authority payload to the consumer without reading it. A flaw in
what a consumer admits is reported to that consumer.

The conformance harness and the vector tooling are developer tooling that runs on a
checkout's own files; a flaw in them is a bug.

## Supported versions

archon is pre-1.0. The latest minor release is supported, in every language together: one
version number spans every registry and tag ([languages](docs/languages.md)), so a fix ships
as a new release across all of them rather than a patch to one.
