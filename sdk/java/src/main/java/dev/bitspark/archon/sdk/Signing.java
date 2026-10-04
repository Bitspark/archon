package dev.bitspark.archon.sdk;

import dev.bitspark.archon.core.Crypto;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The signer contract — <em>signing capability, not seeds</em> (ADR 0009 §2–4).
 *
 * <p>Every helper in this package can take a seed, which is right for a key held in software and
 * wrong for one that is not: a stored key behind {@code archon sign --key}, or any backend a
 * caller wires in. So each signing helper also comes in three parts — a <b>pure</b> {@code
 * prepare} (the exact request it needs signed), the signer's own work, and a <b>pure</b> {@code
 * complete} (the checked signature, then packaging) — with a {@code ...With} convenience that runs
 * the signer between them. The seed methods are unchanged.
 *
 * <p>A {@link Request} is three things, and the scheme is a discriminated value, never a scheme
 * name plus an optional domain: the public key the caller expects, raw Ed25519 ({@link Raw}) or
 * Ed25519ph with the domain as the RFC 8032 context ({@link PhContext}), and the <b>original</b>
 * message bytes — never a digest; a backend that wants a prehash computes it in its own adapter.
 *
 * <p>Three rules, all enforced here rather than trusted to a signer:
 *
 * <ul>
 *   <li>A request is validated <b>before</b> the signer is called: a wrong-length key or a domain
 *       the floor refuses never reaches it.
 *   <li>A signer <b>reports</b> what it can do ({@link Capabilities}), and a request outside that
 *       is refused before it is called. A signer that cannot carry a context declares raw only; it
 *       must never sign a {@link PhContext} request with an empty context instead, and if it does
 *       anyway, the check below catches it.
 *   <li>Every returned signature is <b>verified</b> against the requested key, scheme, domain and
 *       bytes — never against values the signer echoes back. That does not prove that a signer
 *       signs deterministically (ADR 0008 §1.7 requires it); that is a property of the backend,
 *       tested against the {@code domain_sign} vectors.
 * </ul>
 *
 * <p>The calls are synchronous, like the rest of this package; a signer that prompts or runs a
 * subprocess blocks, and is cancelled the way the caller cancels any blocking call.
 *
 * <p>Domain separation is not authorization: whoever may ask for signatures in a domain gets any
 * signature in that domain. Consent belongs to the caller that knows what the bytes mean.
 */
public final class Signing {

  /** The name of raw Ed25519, in {@link Capabilities}. */
  public static final String RAW = "ed25519-raw";

  /** The name of Ed25519ph with a context, in {@link Capabilities}. */
  public static final String PH_CONTEXT = "ed25519ph-context";

  private Signing() {}

  /** Raw Ed25519 over the message, or Ed25519ph with the domain as the RFC 8032 context. */
  public sealed interface Scheme permits Raw, PhContext {
    /** The scheme's name: {@link #RAW} or {@link #PH_CONTEXT}. */
    String kind();
  }

  /** Pure Ed25519. Carries no domain. */
  public record Raw() implements Scheme {
    @Override
    public String kind() {
      return RAW;
    }
  }

  /** Ed25519ph with {@code domain} as the context. */
  public record PhContext(String domain) implements Scheme {
    @Override
    public String kind() {
      return PH_CONTEXT;
    }
  }

  /** What a signer is asked to sign. {@code message} is always the original bytes. */
  public record Request(byte[] expectedPublicKey, Scheme scheme, byte[] message) {
    /** Copies both arrays in, so a request cannot change after it was validated. */
    public Request {
      expectedPublicKey = expectedPublicKey == null ? null : expectedPublicKey.clone();
      message = message == null ? null : message.clone();
    }

    @Override
    public byte[] expectedPublicKey() {
      return expectedPublicKey == null ? null : expectedPublicKey.clone();
    }

    @Override
    public byte[] message() {
      return message == null ? null : message.clone();
    }
  }

  /** What a signer can do. An empty {@code domains} means any domain the floor accepts. */
  public record Capabilities(List<String> schemes, Optional<List<String>> domains) {
    /** Both schemes, any domain. */
    public static Capabilities all() {
      return new Capabilities(List.of(RAW, PH_CONTEXT), Optional.empty());
    }
  }

  /** A source of signatures. {@code sign} may prompt, call a subprocess or wait on a device. */
  public interface Signer {
    /** The key it signs with. */
    byte[] publicKey();

    /** What it can do. */
    Capabilities capabilities();

    /**
     * Signs {@code request}. Called only after the request is validated and within the
     * capabilities; what it returns is checked before anyone uses it.
     */
    byte[] sign(Request request);
  }

  /**
   * Throws unless {@code request} is in range: a 32-byte expected key, a known scheme, and — for
   * {@link PhContext} — a domain the floor accepts. The domain is checked by the floor's own rule
   * (it signs nothing with a throwaway key), so no copy of ADR 0008 §2 lives here to drift.
   *
   * @throws IllegalArgumentException when it is not
   */
  public static void validate(Request request) {
    byte[] key = request == null ? null : request.expectedPublicKey;
    if (key == null || key.length != Crypto.PUBLIC_KEY_SIZE) {
      throw new IllegalArgumentException(
          "signer: the expected public key must be " + Crypto.PUBLIC_KEY_SIZE + " bytes");
    }
    if (request.message == null) {
      throw new IllegalArgumentException("signer: the message must be bytes");
    }
    if (request.scheme() instanceof PhContext ph) {
      Crypto.signInDomain(new byte[Crypto.SEED_SIZE], ph.domain(), new byte[0]);
    } else if (!(request.scheme() instanceof Raw)) {
      throw new IllegalArgumentException("signer: unknown scheme");
    }
  }

  /**
   * The signature, if it verifies for exactly what was <b>requested</b>: its key, scheme, domain
   * and original bytes.
   *
   * @throws IllegalArgumentException when it does not
   */
  public static byte[] checkSignature(Request request, byte[] signature) {
    validate(request);
    boolean ok =
        signature != null
            && signature.length == Crypto.SIGNATURE_SIZE
            && (request.scheme() instanceof PhContext ph
                ? Crypto.verifyInDomain(
                    request.expectedPublicKey, ph.domain(), request.message, signature)
                : Crypto.verify(request.expectedPublicKey, request.message, signature));
    if (!ok) {
      throw new IllegalArgumentException(
          "signer: the signature does not verify for the requested key, scheme and message");
    }
    return signature.clone();
  }

  /**
   * Throws unless {@code signer} claims to be able to sign {@code request}: its key is the
   * expected one, and the scheme and domain are among its capabilities. Called before it is
   * called.
   *
   * @throws IllegalArgumentException when it does not
   */
  public static void checkCapability(Signer signer, Request request) {
    if (!Arrays.equals(signer.publicKey(), request.expectedPublicKey)) {
      throw new IllegalArgumentException("signer: this signer's key is not the expected key");
    }
    Capabilities caps = signer.capabilities();
    if (!caps.schemes().contains(request.scheme().kind())) {
      throw new IllegalArgumentException(
          "signer: this signer cannot produce " + request.scheme().kind());
    }
    if (request.scheme() instanceof PhContext ph
        && caps.domains().isPresent()
        && !caps.domains().get().contains(ph.domain())) {
      throw new IllegalArgumentException(
          "signer: this signer does not sign in domain \"" + ph.domain() + "\"");
    }
  }

  /**
   * Validates, checks the signer's capabilities, calls it, and returns the signature only if it
   * verifies for what was requested.
   *
   * @throws IllegalArgumentException when any of those fails
   */
  public static byte[] signWith(Signer signer, Request request) {
    validate(request);
    checkCapability(signer, request);
    return checkSignature(request, signer.sign(request));
  }

  /**
   * The software signer: a seed held in this process, both schemes, any domain the floor accepts,
   * deterministic by the floor's construction. The seed is copied.
   *
   * @throws IllegalArgumentException when the seed is not 32 bytes
   */
  public static Signer seedSigner(byte[] seed) {
    if (seed == null || seed.length != Crypto.SEED_SIZE) {
      throw new IllegalArgumentException("signer: seed must be " + Crypto.SEED_SIZE + " bytes");
    }
    byte[] held = seed.clone();
    byte[] publicKey = Crypto.publicKeyFromSeed(held);
    return new Signer() {
      @Override
      public byte[] publicKey() {
        return publicKey.clone();
      }

      @Override
      public Capabilities capabilities() {
        return Capabilities.all();
      }

      @Override
      public byte[] sign(Request request) {
        return request.scheme() instanceof PhContext ph
            ? Crypto.signInDomain(held, ph.domain(), request.message)
            : Crypto.sign(held, request.message);
      }

      @Override
      public String toString() {
        return "seedSigner(publicKey)"; // never the seed
      }
    };
  }
}
