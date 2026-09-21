package example;

import dev.bitspark.archon.core.Crypto;
import dev.bitspark.archon.core.HexBytes;
import dev.bitspark.archon.core.KeyText;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * What an outside consumer of dev.bitspark:archon-core must be able to do.
 *
 * <p>This runs against the artifact as RESOLVED, with no archon source directory reachable.
 * Passing the oracle proves the code; it says nothing about whether the package is right — a
 * jar missing a class, or a POM that forgets to declare Bouncy Castle as a runtime
 * dependency, passes every conformance case and fails here on the first call.
 *
 * <p>Two claims are asserted, chosen because a consumer depends on both and can check
 * neither for itself:
 *
 * <ol>
 *   <li><b>Domain separation holds.</b> A signature made in one domain verifies in that
 *       domain, in no other, and never as a raw signature. This is ADR 0003's property, and
 *       it is cryptographic rather than an encoding convention — a binding that quietly fell
 *       back to raw Ed25519 would fail here rather than interoperate wrongly.
 *   <li><b>The ADR 0008 verification profile is enforced.</b> RFC 8032 permits more than one
 *       verification equation, so implementations genuinely disagree about which signatures
 *       are valid, and the disagreement is silent until two of them meet.
 * </ol>
 *
 * <p>The profile inputs below were not chosen for looking dangerous. They were chosen by
 * measurement: the core's own profile check was disabled and the oracle re-run, and these
 * are inputs that changed verdict. That matters because the obvious candidate does not —
 * the identity public key is refused by Bouncy Castle itself, so asserting it here would
 * pass whether or not archon enforced anything. A mixed-order key and an identity {@code R}
 * are refused only because archon checks for them ahead of its library.
 *
 * <p>There is no Java sdk, so there is no proof-of-possession assertion to make.
 */
public final class Consumer {

  /**
   * ADR 0008 class 4. A = A_good + T8, order 8L: not small order, and not in the prime-order
   * subgroup. k is divisible by 8, so the cofactored AND uncofactored equations both hold —
   * the oracle's note records that every core which merely decodes the point accepts it.
   */
  private static final String MIXED_ORDER_A =
      "05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4";

  private static final String MIXED_ORDER_MESSAGE = "6d697865642d6f72646572233133";

  private static final String MIXED_ORDER_SIG =
      "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"
          + "20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b";

  /** A well-formed public key, used for the class 5 cases below. */
  private static final String HONEST_A =
      "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

  /**
   * ADR 0008 class 5. R is the identity point (r = 0) and S = k·a, so the equation holds
   * under every formulation. RFC 8032 pure verification accepts it; no honest signer
   * produces it. A verifier that validates only the public key never looks here.
   */
  private static final String IDENTITY_R_SIG =
      "0100000000000000000000000000000000000000000000000000000000000000"
          + "04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07";

  /** ADR 0008 class 5. R = T8 (order 8): the cofactored equation holds, the uncofactored does not. */
  private static final String SMALL_ORDER_R_SIG =
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
          + "07379d90f393cba9b041ed03e6df67f7a16828fb9209bd5ab3ab4831f2298908";

  private static final String DOMAIN = "archon/test/v1";

  public static void main(String[] args) {
    byte[] seed = new byte[32];
    for (int i = 0; i < 32; i++) {
      seed[i] = (byte) i;
    }
    byte[] pubkey = Crypto.publicKeyFromSeed(seed);
    byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

    // 1. Domain separation, in all four directions.
    byte[] signature = Crypto.signInDomain(seed, DOMAIN, message);
    check(Crypto.verifyInDomain(pubkey, DOMAIN, message, signature),
        "a domain signature must verify in its own domain");
    check(!Crypto.verifyInDomain(pubkey, "archon/test/v2", message, signature),
        "a domain signature must not verify in another domain");
    check(!Crypto.verify(pubkey, message, signature),
        "a domain signature must never verify as a raw signature");

    byte[] raw = Crypto.sign(seed, message);
    check(Crypto.verify(pubkey, message, raw), "a raw signature must verify raw");
    check(!Crypto.verifyInDomain(pubkey, DOMAIN, message, raw),
        "a raw signature must not verify in any domain");

    // 2. The profile, on the inputs that were measured to be load-bearing.
    byte[] mixedOrderKey = HexBytes.pubkeyFromHex(MIXED_ORDER_A);
    byte[] mixedOrderMessage = hex(MIXED_ORDER_MESSAGE);
    byte[] mixedOrderSig = HexBytes.signatureFromHex(MIXED_ORDER_SIG);
    check(!Crypto.verify(mixedOrderKey, mixedOrderMessage, mixedOrderSig),
        "a mixed-order public key must be refused, though both equations hold");
    check(!Crypto.verifyInDomain(mixedOrderKey, DOMAIN, mixedOrderMessage, mixedOrderSig),
        "a mixed-order public key must be refused in a domain too");

    byte[] honest = HexBytes.pubkeyFromHex(HONEST_A);
    check(!Crypto.verify(honest, message, HexBytes.signatureFromHex(IDENTITY_R_SIG)),
        "an identity R must be refused, though RFC 8032 pure verification accepts it");
    check(!Crypto.verify(honest, message, HexBytes.signatureFromHex(SMALL_ORDER_R_SIG)),
        "a small-order R must be refused");

    // The canonical spelling, which is the other half of the floor's public surface.
    String text = KeyText.encodeKey(pubkey);
    check(Arrays.equals(pubkey, KeyText.decodeKey(text)),
        "the canonical key text must round trip");

    System.out.println("consumer ok: " + text);
  }

  private static byte[] hex(String text) {
    byte[] out = new byte[text.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static void check(boolean condition, String what) {
    if (!condition) {
      throw new AssertionError(what);
    }
  }

  private Consumer() {}
}
