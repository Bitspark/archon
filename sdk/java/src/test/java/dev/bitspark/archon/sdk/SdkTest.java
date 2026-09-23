package dev.bitspark.archon.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.bitspark.archon.core.Crypto;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the Java sdk.
 *
 * <p>The oracle in vectors/sdk.json is the cross-language authority and is driven by
 * conformance/check-java-sdk.mjs; these cover the same ground from inside Java, plus what the
 * oracle's {@code ok} / {@code error} protocol cannot express: which exception is thrown, that
 * verification never throws, and the two refusals whose oracle cases carry no genuine signature (a
 * short nonce and an empty binding on the VERIFY side — see the tests below).
 */
final class SdkTest {

  private static final byte[] SEED = range(0, 32);
  private static final byte[] OTHER_SEED = range(1, 32);
  private static final String DOMAIN = "example/pop/v1";
  private static final byte[] NONCE = range(0, 16);
  private static final byte[] BINDING = bytes("channel");
  private static final String ENV_DOMAIN = "example/env/v1";

  // --- possession: the layout ------------------------------------------------------------

  @Test
  void possessionLayoutIsPinned() {
    byte[] want = concat(new byte[] {0x01, 0x00, 0x10}, NONCE, new byte[] {0x00, 0x07}, BINDING);
    assertArrayEquals(want, Possession.messageBytes(NONCE, BINDING));
  }

  @Test
  void possessionLayoutBounds() {
    Possession.messageBytes(new byte[Possession.MIN_NONCE_SIZE], bytes("x"));
    Possession.messageBytes(new byte[Possession.MAX_FIELD_SIZE], new byte[Possession.MAX_FIELD_SIZE]);
    assertThrows(IllegalArgumentException.class, () -> Possession.messageBytes(new byte[15], bytes("x")));
    assertThrows(
        IllegalArgumentException.class,
        () -> Possession.messageBytes(new byte[Possession.MAX_FIELD_SIZE + 1], bytes("x")));
    assertThrows(IllegalArgumentException.class, () -> Possession.messageBytes(NONCE, new byte[0]));
    assertThrows(
        IllegalArgumentException.class,
        () -> Possession.messageBytes(NONCE, new byte[Possession.MAX_FIELD_SIZE + 1]));
  }

  // --- possession: prove and verify ------------------------------------------------------

  @Test
  void possessionRoundTripAndEveryFieldBinds() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] proof = Possession.prove(SEED, DOMAIN, NONCE, BINDING);
    assertEquals(64, proof.length);
    assertTrue(Possession.verify(pub, DOMAIN, NONCE, BINDING, proof));
    assertFalse(Possession.verify(pub, DOMAIN, range(1, 16), BINDING, proof));
    assertFalse(Possession.verify(pub, DOMAIN, NONCE, bytes("other channel"), proof));
    assertFalse(Possession.verify(pub, "example/pop/v2", NONCE, BINDING, proof));
    assertFalse(Possession.verify(Crypto.publicKeyFromSeed(OTHER_SEED), DOMAIN, NONCE, BINDING, proof));
  }

  @Test
  void possessionIsDeterministic() {
    assertArrayEquals(
        Possession.prove(SEED, DOMAIN, NONCE, BINDING), Possession.prove(SEED, DOMAIN, NONCE, BINDING));
  }

  @Test
  void aRawSignatureOverTheLayoutIsNotAProof() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] raw = Crypto.sign(SEED, Possession.messageBytes(NONCE, BINDING));
    assertFalse(Possession.verify(pub, DOMAIN, NONCE, BINDING, raw));
  }

  @Test
  void proveRefusesWhatIsNotAProof() {
    assertThrows(IllegalArgumentException.class, () -> Possession.prove(SEED, DOMAIN, new byte[15], BINDING));
    assertThrows(IllegalArgumentException.class, () -> Possession.prove(SEED, DOMAIN, NONCE, new byte[0]));
    assertThrows(IllegalArgumentException.class, () -> Possession.prove(SEED, "", NONCE, BINDING));
    assertThrows(
        IllegalArgumentException.class,
        () -> Possession.prove(Arrays.copyOf(SEED, 31), DOMAIN, NONCE, BINDING));
  }

  /**
   * The oracle's {@code binding-empty-rejected} verify case carries a signature that is not
   * genuine over its own layout, so it is false whether or not the refusal exists. This one IS
   * genuine: the exact bytes the scheme would sign if it allowed an empty binding, signed in the
   * domain. Only the sdk's own check can refuse it.
   */
  @Test
  void verifyRefusesAGenuineSignatureOverAnUnboundLayout() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] unbound = concat(new byte[] {0x01, 0x00, 0x10}, NONCE, new byte[] {0x00, 0x00});
    byte[] genuine = Crypto.signInDomain(SEED, DOMAIN, unbound);
    assertFalse(Possession.verify(pub, DOMAIN, NONCE, new byte[0], genuine));
  }

  /** The same gap for {@code nonce-15-rejected}: a genuine signature over the 15-byte layout. */
  @Test
  void verifyRefusesAGenuineSignatureOverAShortNonce() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] shortNonce = new byte[15];
    byte[] layout = concat(new byte[] {0x01, 0x00, 0x0f}, shortNonce, new byte[] {0x00, 0x07}, BINDING);
    byte[] genuine = Crypto.signInDomain(SEED, DOMAIN, layout);
    assertFalse(Possession.verify(pub, DOMAIN, shortNonce, BINDING, genuine));
  }

  @Test
  void verifyIsTotal() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] proof = Possession.prove(SEED, DOMAIN, NONCE, BINDING);
    assertFalse(Possession.verify(Arrays.copyOf(pub, 31), DOMAIN, NONCE, BINDING, proof));
    assertFalse(Possession.verify(pub, DOMAIN, NONCE, BINDING, Arrays.copyOf(proof, 63)));
    assertFalse(Possession.verify(pub, "", NONCE, BINDING, proof));
    assertFalse(Possession.verify(pub, DOMAIN, null, BINDING, proof));
    assertFalse(Possession.verify(null, DOMAIN, NONCE, BINDING, proof));
    assertFalse(Possession.verify(pub, null, NONCE, BINDING, proof));
    assertFalse(Possession.verify(pub, DOMAIN, NONCE, BINDING, null));
  }

  // --- envelope --------------------------------------------------------------------------

  @Test
  void envelopeLayoutIsPinned() {
    byte[] sealed = Envelope.seal(SEED, ENV_DOMAIN, bytes("payload"));
    byte[] d = bytes(ENV_DOMAIN);
    assertArrayEquals(bytes("arcn"), Arrays.copyOfRange(sealed, 0, 4));
    assertArrayEquals(bytes("arcn"), Envelope.magic());
    assertEquals(Envelope.VERSION, sealed[4]);
    assertEquals(d.length, sealed[5]);
    assertArrayEquals(d, Arrays.copyOfRange(sealed, 6, 6 + d.length));
    int at = 6 + d.length;
    assertArrayEquals(Crypto.publicKeyFromSeed(SEED), Arrays.copyOfRange(sealed, at, at + 32));
    assertArrayEquals(bytes("payload"), Arrays.copyOfRange(sealed, at + 96, sealed.length));
    assertArrayEquals(concat(new byte[] {0x02}, bytes("payload")), Envelope.messageBytes(bytes("payload")));
  }

  @Test
  void envelopeRoundTrip() {
    Envelope.Opened opened = Envelope.open(Envelope.seal(SEED, ENV_DOMAIN, bytes("payload")), ENV_DOMAIN);
    assertArrayEquals(Crypto.publicKeyFromSeed(SEED), opened.pubkey());
    assertArrayEquals(bytes("payload"), opened.payload());
  }

  @Test
  void openedCannotBeAlteredAfterTheCheck() {
    Envelope.Opened opened = Envelope.open(Envelope.seal(SEED, ENV_DOMAIN, bytes("payload")), ENV_DOMAIN);
    opened.payload()[0] ^= 0x01;
    opened.pubkey()[0] ^= 0x01;
    assertArrayEquals(bytes("payload"), opened.payload());
    assertArrayEquals(Crypto.publicKeyFromSeed(SEED), opened.pubkey());
  }

  @Test
  void emptyPayloadIsAllowed() {
    assertEquals(0, Envelope.open(Envelope.seal(SEED, ENV_DOMAIN, new byte[0]), ENV_DOMAIN).payload().length);
  }

  /**
   * A genuine envelope in another domain: an opener that trusted the envelope's own domain field
   * would accept it.
   */
  @Test
  void theVerifierChoosesTheDomain() {
    byte[] sealed = Envelope.seal(SEED, "example/env/other", bytes("payload"));
    IllegalArgumentException refused =
        assertThrows(IllegalArgumentException.class, () -> Envelope.open(sealed, ENV_DOMAIN));
    assertTrue(refused.getMessage().contains("different domain"), refused.getMessage());
  }

  @Test
  void everyTamperIsRefused() {
    byte[] sealed = Envelope.seal(SEED, ENV_DOMAIN, bytes("payload"));
    int d = ENV_DOMAIN.length();
    for (int index : new int[] {0, 4, 5, 6, 6 + d, sealed.length - 1}) {
      byte[] bent = sealed.clone();
      bent[index] ^= 0x01;
      assertThrows(IllegalArgumentException.class, () -> Envelope.open(bent, ENV_DOMAIN), "byte " + index);
    }
    for (int cut : new int[] {0, 3, 5, 6 + d + 31, 6 + d + 95}) {
      byte[] truncated = Arrays.copyOf(sealed, cut);
      assertThrows(IllegalArgumentException.class, () -> Envelope.open(truncated, ENV_DOMAIN), "cut " + cut);
    }
  }

  /**
   * The scheme tags keep the two layouts apart: sign the payload bytes without the envelope's tag
   * and splice that signature in.
   */
  @Test
  void aSignatureWithoutTheEnvelopeTagIsRefused() {
    byte[] sealed = Envelope.seal(SEED, ENV_DOMAIN, bytes("payload"));
    int at = 6 + ENV_DOMAIN.length() + 32;
    byte[] untagged = Crypto.signInDomain(SEED, ENV_DOMAIN, bytes("payload"));
    System.arraycopy(untagged, 0, sealed, at, 64);
    IllegalArgumentException refused =
        assertThrows(IllegalArgumentException.class, () -> Envelope.open(sealed, ENV_DOMAIN));
    assertTrue(refused.getMessage().contains("does not verify"), refused.getMessage());
  }

  @Test
  void sealRefusesABadDomainOrSeed() {
    assertThrows(IllegalArgumentException.class, () -> Envelope.seal(SEED, "", bytes("x")));
    assertThrows(IllegalArgumentException.class, () -> Envelope.seal(SEED, "d".repeat(256), bytes("x")));
    assertThrows(
        IllegalArgumentException.class, () -> Envelope.seal(Arrays.copyOf(SEED, 31), ENV_DOMAIN, bytes("x")));
  }

  // --- helpers ---------------------------------------------------------------------------

  private static byte[] range(int start, int length) {
    byte[] out = new byte[length];
    for (int i = 0; i < length; i++) {
      out[i] = (byte) (start + i);
    }
    return out;
  }

  private static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] p : parts) {
      out.writeBytes(p);
    }
    return out.toByteArray();
  }
}
