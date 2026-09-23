# archon sdk — Java

One layer above the identity floor: proof of possession and the signed envelope.

```xml
<dependency>
  <groupId>dev.bitspark</groupId>
  <artifactId>archon-sdk</artifactId>
  <version>0.8.0</version>
</dependency>
```

It depends on [`dev.bitspark:archon-core`](https://central.sonatype.com/artifact/dev.bitspark/archon-core)
at the same version and nothing else; Maven or Gradle brings the floor — and Bouncy Castle
beneath it — transitively.

```java
import dev.bitspark.archon.core.Crypto;
import dev.bitspark.archon.sdk.Envelope;
import dev.bitspark.archon.sdk.Possession;

byte[] pub = Crypto.publicKeyFromSeed(seed);

// Proof of possession: the challenger picks the nonce and the channel binding.
byte[] proof = Possession.prove(seed, "example/pop/v1", nonce, binding);
Possession.verify(pub, "example/pop/v1", nonce, binding, proof);         // true
Possession.verify(pub, "example/pop/v1", nonce, otherChannel, proof);    // false

// The signed envelope: the verifier chooses the domain, never the envelope.
byte[] sealed = Envelope.seal(seed, "example/env/v1", payload);
Envelope.Opened opened = Envelope.open(sealed, "example/env/v1");        // pubkey(), payload()
Envelope.open(sealed, "example/env/other");  // IllegalArgumentException: claims a different domain
```

## What it is

| | |
|---|---|
| `Possession` | `prove`, `verify`, `messageBytes` — *can they sign, right now, for this channel?* |
| `Envelope` | `seal`, `open`, `messageBytes`, `Opened` — *these bytes, signed by this key, in this domain* |

Both sign in the **caller's** domain through `Crypto.signInDomain`, and each prefixes its
layout with a one-byte scheme tag so a possession proof and an envelope payload in the same
domain can never be the same bytes.

**Entropy, time and channel binding are arguments.** This library never sources them, which
is what makes every byte it emits a deterministic function of its inputs. Verification is
total: `Possession.verify` returns `false` on any shape failure, including a `null`, and never
throws; `Envelope.open` throws `IllegalArgumentException` and never returns an unverified
payload. `Opened`'s accessors return copies.

**Not here yet: the login scheme.** The Go, Rust and TypeScript sdks also carry
`archon-login/1` ([docs/login.md](https://github.com/Bitspark/archon/blob/main/docs/login.md));
this one does not.

## Agreement is the claim

This sdk is held to the same hand-authored oracle as the Go, Rust, TypeScript and Python sdks
— 38 cases in [`vectors/sdk.json`](https://github.com/Bitspark/archon/blob/main/vectors/sdk.json),
recomputed rather than echoed. The conformance CLI lives in test sources and its JSON library
is test-scoped, so neither reaches the published jar.

## Verification

```console
node conformance/check-java-sdk.mjs          # the oracle, against this tree's floor
node conformance/check-java-sdk-package.mjs  # the jar, consumed from nothing but its coordinates
```

## License

Apache-2.0.
