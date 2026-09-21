package dev.bitspark.archon.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the Java core.
 *
 * <p>The oracle in vectors/identity.json is the cross-language authority and is driven by
 * conformance/check-java.mjs; these cover the same ground from inside Java, plus the
 * argument-shape failures the oracle has no way to express — its protocol carries only
 * {@code ok} / {@code error}, so a thrown exception or a wrong-sized seed has nowhere to go.
 */
final class CoreTest {

  private static final byte[] SEED = seed();
  private static final byte[] MSG = "hello".getBytes(StandardCharsets.UTF_8);
  private static final String DOMAIN = "example.v1";

  private static byte[] seed() {
    byte[] s = new byte[32];
    for (int i = 0; i < 32; i++) {
      s[i] = (byte) i;
    }
    return s;
  }

  // --- crypto -------------------------------------------------------------------------

  @Test
  void publicKeyIsThirtyTwoBytesAndStable() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    assertEquals(32, pub.length);
    assertArrayEquals(pub, Crypto.publicKeyFromSeed(SEED));
  }

  @Test
  void seedMustBeThirtyTwoBytes() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Crypto.publicKeyFromSeed(Arrays.copyOf(SEED, 31)));
  }

  @Test
  void signVerifyRoundTrip() {
    assertTrue(Crypto.verify(Crypto.publicKeyFromSeed(SEED), MSG, Crypto.sign(SEED, MSG)));
  }

  @Test
  void verifyIsTotalNotThrowing() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] sig = Crypto.sign(SEED, MSG);
    assertFalse(Crypto.verify(pub, "goodbye".getBytes(StandardCharsets.UTF_8), sig));
    assertFalse(Crypto.verify(Arrays.copyOf(pub, 31), MSG, sig));
    assertFalse(Crypto.verify(pub, MSG, Arrays.copyOf(sig, 63)));
    assertFalse(Crypto.verify(pub, MSG, new byte[64]));
  }

  @Test
  void domainSeparationIsCryptographic() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] sig = Crypto.signInDomain(SEED, DOMAIN, MSG);
    assertTrue(Crypto.verifyInDomain(pub, DOMAIN, MSG, sig));
    assertFalse(Crypto.verifyInDomain(pub, "other.v1", MSG, sig), "another domain");
    assertFalse(Crypto.verify(pub, MSG, sig), "never as a raw signature");
    assertFalse(
        Crypto.verifyInDomain(pub, DOMAIN, MSG, Crypto.sign(SEED, MSG)),
        "a raw signature is in no domain");
  }

  @Test
  void domainBounds() {
    assertThrows(IllegalArgumentException.class, () -> Crypto.signInDomain(SEED, "", MSG));
    assertThrows(
        IllegalArgumentException.class,
        () -> Crypto.signInDomain(SEED, "d".repeat(Crypto.MAX_DOMAIN_SIZE + 1), MSG));
    String longest = "d".repeat(Crypto.MAX_DOMAIN_SIZE);
    assertTrue(
        Crypto.verifyInDomain(
            Crypto.publicKeyFromSeed(SEED), longest, MSG, Crypto.signInDomain(SEED, longest, MSG)));
  }

  @Test
  void domainBoundIsBytesNotCharacters() {
    // 128 two-byte code points is 256 bytes: over the limit, though only 128 characters.
    String multibyte = "é".repeat(128);
    assertEquals(256, multibyte.getBytes(StandardCharsets.UTF_8).length);
    assertThrows(
        IllegalArgumentException.class, () -> Crypto.signInDomain(SEED, multibyte, MSG));
  }

  @Test
  void verifyInDomainIsFalseNotThrowingOnABadDomain() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    byte[] sig = Crypto.signInDomain(SEED, DOMAIN, MSG);
    assertFalse(Crypto.verifyInDomain(pub, "", MSG, sig));
    assertFalse(Crypto.verifyInDomain(pub, "d".repeat(256), MSG, sig));
  }

  // --- hexbytes -----------------------------------------------------------------------

  @Test
  void hexIsLowercaseAndFixedSize() {
    assertEquals("00ff", HexBytes.toHex(new byte[] {0, (byte) 0xFF}));
    assertEquals(32, HexBytes.seedFromHex("AA".repeat(32)).length);
    for (String bad : new String[] {"aa".repeat(31), "aa".repeat(33), "", "zz".repeat(32)}) {
      assertThrows(IllegalArgumentException.class, () -> HexBytes.seedFromHex(bad));
    }
  }

  @Test
  void hexDecodersAreTypedByLength() {
    assertEquals(32, HexBytes.pubkeyFromHex("11".repeat(32)).length);
    assertEquals(64, HexBytes.signatureFromHex("11".repeat(64)).length);
    assertThrows(
        IllegalArgumentException.class, () -> HexBytes.pubkeyFromHex("11".repeat(64)));
  }

  // --- keytext ------------------------------------------------------------------------

  @Test
  void keyTextRoundTrip() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    String text = KeyText.encodeKey(pub);
    assertTrue(text.startsWith("ed25519:"));
    assertEquals(text.toLowerCase(java.util.Locale.ROOT), text);
    assertArrayEquals(pub, KeyText.decodeKey(text));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "d75a98",
        "ed25519:abc",
        "ed25519:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "ED25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      })
  void keyTextRefusals(String bad) {
    assertThrows(IllegalArgumentException.class, () -> KeyText.decodeKey(bad));
  }

  // --- keycodec -----------------------------------------------------------------------

  @Test
  void pemRoundTrips() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    assertArrayEquals(pub, KeyCodec.spkiPemToPubkey(KeyCodec.pubkeyToSpkiPem(pub)));
    assertArrayEquals(SEED, KeyCodec.pkcs8PemToSeed(KeyCodec.seedToPkcs8Pem(SEED)));
  }

  @Test
  void pemShape() {
    String pem =
        new String(
            KeyCodec.pubkeyToSpkiPem(Crypto.publicKeyFromSeed(SEED)), StandardCharsets.US_ASCII);
    assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----\n"));
    assertTrue(pem.endsWith("-----END PUBLIC KEY-----\n"));
  }

  @Test
  void pemAcceptsCrlf() {
    String pem = new String(KeyCodec.seedToPkcs8Pem(SEED), StandardCharsets.US_ASCII);
    assertArrayEquals(
        SEED,
        KeyCodec.pkcs8PemToSeed(pem.replace("\n", "\r\n").getBytes(StandardCharsets.US_ASCII)));
  }

  @Test
  void pemRefusesTheWrongBlockAndBadTemplate() {
    assertThrows(
        IllegalArgumentException.class,
        () -> KeyCodec.spkiPemToPubkey(KeyCodec.seedToPkcs8Pem(SEED)));
    assertThrows(IllegalArgumentException.class, () -> KeyCodec.pubkeyToSpkiPem(new byte[31]));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            KeyCodec.spkiPemToPubkey(
                "-----BEGIN PUBLIC KEY-----\nbm90IERFUg==\n-----END PUBLIC KEY-----\n"
                    .getBytes(StandardCharsets.US_ASCII)));
  }
}
