package example;

import dev.bitspark.archon.core.Crypto;
import dev.bitspark.archon.sdk.Envelope;
import dev.bitspark.archon.sdk.Possession;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * What an outside consumer of dev.bitspark:archon-sdk must be able to do, having declared nothing
 * but the sdk.
 *
 * <p>This runs against the artifacts as RESOLVED, with no archon source directory reachable. The
 * {@code dev.bitspark.archon.core} import compiles only because the sdk's POM brought the floor
 * transitively; the signatures verify only because the floor brought Bouncy Castle. Either
 * missing, and this fails before its first assertion.
 *
 * <p>The assertion that matters is the one only archon's own check can make: a GENUINE envelope
 * sealed in another domain must be refused. An opener that trusted the envelope's own domain
 * field — the naive implementation, and the one a library would give you — returns its payload.
 * It was measured, not assumed: with the sdk's domain check replaced by exactly that, this
 * program fails. The floor's load-bearing profile pair is asserted too, through the floor that
 * arrived transitively, so a consumer of the sdk has proof it got the profiled floor.
 */
public final class Consumer {

  private static final HexFormat HEX = HexFormat.of();

  /** ADR 0008 class 4, oracle {@code profile-mixed-order-A-k-divisible}. */
  private static final String MIXED_ORDER_A =
      "05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4";

  private static final String MIXED_ORDER_MESSAGE = "6d697865642d6f72646572233133";
  private static final String MIXED_ORDER_SIG =
      "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"
          + "20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b";

  /** ADR 0008 class 5, oracle {@code profile-identity-R}, against this honest key. */
  private static final String HONEST_A =
      "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

  private static final String IDENTITY_R_SIG =
      "0100000000000000000000000000000000000000000000000000000000000000"
          + "04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07";

  public static void main(String[] args) {
    byte[] seed = new byte[32];
    for (int i = 0; i < 32; i++) {
      seed[i] = (byte) i;
    }
    byte[] pubkey = Crypto.publicKeyFromSeed(seed);

    // 1. Proof of possession: every field binds.
    byte[] nonce = Arrays.copyOf(seed, 16);
    byte[] binding = bytes("channel");
    byte[] proof = Possession.prove(seed, "example/pop/v1", nonce, binding);
    check(Possession.verify(pubkey, "example/pop/v1", nonce, binding, proof),
        "a possession proof must verify for its own nonce, binding and domain");
    check(!Possession.verify(pubkey, "example/pop/v1", nonce, bytes("another channel"), proof),
        "a possession proof must not verify for another channel");
    check(!Possession.verify(pubkey, "example/pop/v2", nonce, binding, proof),
        "a possession proof must not verify in another domain");

    // 2. The envelope, and the refusal only archon's check makes.
    byte[] sealed = Envelope.seal(seed, "example/env/v1", bytes("payload"));
    Envelope.Opened opened = Envelope.open(sealed, "example/env/v1");
    check(Arrays.equals(opened.payload(), bytes("payload")), "an envelope must open to its payload");
    check(Arrays.equals(opened.pubkey(), pubkey), "an envelope must name the key that sealed it");

    byte[] elsewhere = Envelope.seal(seed, "example/env/other", bytes("payload"));
    boolean refused;
    try {
      Envelope.open(elsewhere, "example/env/v1");
      refused = false;
    } catch (IllegalArgumentException expected) {
      refused = true;
    }
    check(refused, "a genuine envelope sealed in another domain must be refused");

    // 3. The floor that arrived transitively is the profiled one.
    check(!Crypto.verify(HEX.parseHex(MIXED_ORDER_A), HEX.parseHex(MIXED_ORDER_MESSAGE),
            HEX.parseHex(MIXED_ORDER_SIG)),
        "the transitive floor must refuse a mixed-order public key");
    check(!Crypto.verify(HEX.parseHex(HONEST_A), bytes("hello"), HEX.parseHex(IDENTITY_R_SIG)),
        "the transitive floor must refuse an identity R");

    System.out.println("consumer ok: sdk possession + envelope on a profiled floor");
  }

  private static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static void check(boolean condition, String what) {
    if (!condition) {
      throw new AssertionError(what);
    }
  }
}
