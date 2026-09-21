# archon core — Java

The identity floor in Java: Ed25519 key bytes, one canonical text spelling, the SPKI and
PKCS-8 codecs, and domain-separated signing.

```xml
<dependency>
  <groupId>dev.bitspark</groupId>
  <artifactId>archon-core</artifactId>
  <version>0.6.2</version>
</dependency>
```

```java
import dev.bitspark.archon.core.*;

byte[] seed = new byte[32];
for (int i = 0; i < 32; i++) seed[i] = (byte) i;

byte[] pub = Crypto.publicKeyFromSeed(seed);
KeyText.encodeKey(pub);
// ed25519:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8

byte[] msg = "hello".getBytes(StandardCharsets.UTF_8);
byte[] sig = Crypto.signInDomain(seed, "example.v1", msg);

Crypto.verifyInDomain(pub, "example.v1", msg, sig);  // true
Crypto.verifyInDomain(pub, "other.v1",  msg, sig);   // false — domains do not cross
Crypto.verify(pub, msg, sig);                        // false — never as a raw signature
```

## What it is

Two questions and no others: *are these bytes that key*, and *is this signature that key's*.
Authority and custody belong to their own layers — see the
[repository README](https://github.com/Bitspark/archon).

| class | |
|---|---|
| `Crypto` | `publicKeyFromSeed`, `sign`/`verify`, `signInDomain`/`verifyInDomain` |
| `HexBytes` | `toHex`, and fixed-size decoders that accept exactly N bytes or fail |
| `KeyText` | `encodeKey`/`decodeKey` — `ed25519:<64 hex>` |
| `KeyCodec` | RFC 5280 SPKI and RFC 5958 PKCS-8 v1 PEM, as a byte codec |

## Why Bouncy Castle

`signInDomain` is **Ed25519ph with the domain as the RFC 8032 §5.1 context string**. The JDK's
own `Signature.getInstance("Ed25519")` exposes no context parameter, so it cannot express the
construction. Bouncy Castle's `Ed25519phSigner` takes one directly, and reproduces the oracle's
`domain_sign` vectors byte-for-byte.

It is the single runtime dependency. The conformance CLI's JSON library is **test-scoped** and
does not reach the published jar.

## Agreement is the claim

This core is held to the same hand-authored oracle as the Go, Rust, TypeScript and Python
cores — 60 cases in
[`vectors/identity.json`](https://github.com/Bitspark/archon/blob/main/vectors/identity.json),
recomputed rather than echoed. If it disagrees with the others about whether something is a
valid key, signature or key text, that disagreement is the defect.

## Verification

Signing throws rather than silently signing raw: an empty domain, or one over 255 bytes, is an
error. The bound is on **bytes**, not characters, so a 255-character domain of multibyte code
points is over the limit — the other cores measure it the same way.

Verification is total: every shape failure returns `false`, so a caller cannot mistake
*malformed* for *valid*.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
