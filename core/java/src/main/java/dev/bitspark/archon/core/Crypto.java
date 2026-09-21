package dev.bitspark.archon.core;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed25519phSigner;

/**
 * Ed25519 signing and verification — the floor's only cryptography.
 *
 * <p>Like the other cores, this binds an existing Ed25519 implementation and writes none of its
 * own curve arithmetic. The binding is Bouncy Castle, chosen because {@code sign_in_domain} is
 * Ed25519ph with the domain as the RFC 8032 §5.1 context string, and the JDK's own
 * {@code Signature.getInstance("Ed25519")} exposes no context parameter. Bouncy Castle's
 * {@link Ed25519phSigner} takes one directly.
 *
 * <p>Verification is fail-closed: every shape failure returns {@code false} rather than throwing,
 * so a caller cannot mistake <em>malformed</em> for <em>valid</em>.
 */
public final class Crypto {

  public static final int PUBLIC_KEY_SIZE = 32;
  public static final int SIGNATURE_SIZE = 64;
  public static final int SEED_SIZE = 32;

  /** The longest domain (RFC 8032 context) a signature can be made in, in bytes. */
  public static final int MAX_DOMAIN_SIZE = 255;

  private Crypto() {}

  /** The 32-byte public key for {@code seed}. Throws when the seed is not 32 bytes. */
  public static byte[] publicKeyFromSeed(byte[] seed) {
    return privateKey(seed).generatePublicKey().getEncoded();
  }

  /** A raw Ed25519 signature over {@code message}. */
  public static byte[] sign(byte[] seed, byte[] message) {
    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, privateKey(seed));
    signer.update(message, 0, message.length);
    return signer.generateSignature();
  }

  /** True when {@code signature} is {@code pubkey}'s over {@code message}. False on any failure. */
  public static boolean verify(byte[] pubkey, byte[] message, byte[] signature) {
    if (pubkey.length != PUBLIC_KEY_SIZE || signature.length != SIGNATURE_SIZE) {
      return false;
    }
    // The profile, on BOTH points, before any verification equation.
    if (!pointAcceptable(pubkey, 0) || !pointAcceptable(signature, 0)) {
      return false;
    }
    try {
      Ed25519PublicKeyParameters key = new Ed25519PublicKeyParameters(pubkey, 0);
      Ed25519Signer verifier = new Ed25519Signer();
      verifier.init(false, key);
      verifier.update(message, 0, message.length);
      return verifier.verifySignature(signature);
    } catch (RuntimeException failed) {
      return false;
    }
  }

  /**
   * Signs {@code message} in {@code domain} — Ed25519ph with the domain as the RFC 8032 context.
   *
   * <p>Throws, never silently signs raw, when the domain is empty or longer than
   * {@link #MAX_DOMAIN_SIZE} bytes. An empty domain is "sign in no domain", which is exactly what
   * this method exists to make impossible.
   */
  public static byte[] signInDomain(byte[] seed, String domain, byte[] message) {
    byte[] context = domainBytes(domain);
    Ed25519phSigner signer = new Ed25519phSigner(context);
    signer.init(true, privateKey(seed));
    signer.update(message, 0, message.length);
    return signer.generateSignature();
  }

  /** True when {@code signature} is {@code pubkey}'s over {@code message} IN {@code domain}. */
  public static boolean verifyInDomain(
      byte[] pubkey, String domain, byte[] message, byte[] signature) {
    if (pubkey.length != PUBLIC_KEY_SIZE || signature.length != SIGNATURE_SIZE) {
      return false;
    }
    byte[] context;
    try {
      context = domainBytes(domain);
    } catch (IllegalArgumentException badDomain) {
      return false;
    }
    if (!pointAcceptable(pubkey, 0) || !pointAcceptable(signature, 0)) {
      return false;
    }
    try {
      Ed25519PublicKeyParameters key = new Ed25519PublicKeyParameters(pubkey, 0);
      Ed25519phSigner verifier = new Ed25519phSigner(context);
      verifier.init(false, key);
      verifier.update(message, 0, message.length);
      return verifier.verifySignature(signature);
    } catch (RuntimeException failed) {
      return false;
    }
  }

  /**
   * archon's Ed25519 verification profile, applied to an encoded point before any verification
   * equation. It must hold for BOTH the public key {@code A} and the signature's {@code R} (its
   * first 32 bytes): the point decodes and is on the curve, its encoding is canonical, it is not
   * the identity, and it lies in the prime-order subgroup.
   *
   * <p>⚠ MEASURED, NOT ASSUMED. Bouncy Castle offers two validators and only one of them is this
   * predicate. Against the profile's own points:
   *
   * <pre>
   *                        validatePublicKeyFull   validatePublicKeyPartial
   *   ordinary key         accept                  accept
   *   identity             REJECT                  REJECT
   *   small-order          REJECT                  REJECT
   *   non-canonical        REJECT                  REJECT
   *   MIXED-ORDER          REJECT                  accept        <- the one that matters
   * </pre>
   *
   * <p>{@code Ed25519Signer} validates the public key with the PARTIAL check internally and does
   * not look at {@code R} at all, which is why this core accepted mixed-order keys, an identity
   * {@code R} and a small-order {@code R} before the check was made explicit. {@code [8]P = O} is
   * not a substitute: it catches small-order points and misses mixed-order ones.
   */
  private static boolean pointAcceptable(byte[] encoded, int offset) {
    try {
      return org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(encoded, offset);
    } catch (RuntimeException notAPoint) {
      return false;
    }
  }

  private static Ed25519PrivateKeyParameters privateKey(byte[] seed) {
    if (seed.length != SEED_SIZE) {
      throw new IllegalArgumentException(
          "crypto: seed must be " + SEED_SIZE + " bytes, got " + seed.length);
    }
    return new Ed25519PrivateKeyParameters(seed, 0);
  }

  /**
   * The domain as context bytes, bounds-checked.
   *
   * <p>UTF-8, and the bound is on BYTES rather than characters — a 255-character domain of
   * multibyte code points is over the limit, and the other cores measure it the same way.
   */
  private static byte[] domainBytes(String domain) {
    byte[] bytes = domain.getBytes(StandardCharsets.UTF_8);
    if (bytes.length == 0) {
      throw new IllegalArgumentException("crypto: domain is empty");
    }
    if (bytes.length > MAX_DOMAIN_SIZE) {
      throw new IllegalArgumentException(
          "crypto: domain is " + bytes.length + " bytes, max " + MAX_DOMAIN_SIZE);
    }
    return bytes;
  }
}
