package dev.bitspark.archon.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * The SPKI and PKCS-8 PEM codecs — a BYTE codec, not key custody.
 *
 * <p>For an Ed25519 key the DER is fixed-length and fixed-shape, so this is a template match, not
 * an ASN.1 parser: a 12-byte SPKI prefix or a 16-byte PKCS-8 v1 prefix, then exactly 32 key bytes.
 * Anything else is refused. That is deliberate — a general parser would accept encodings the other
 * cores would not, and agreement is the claim.
 *
 * <p>RFC 5280 (SPKI) and RFC 5958 (PKCS-8 v1). PKCS-8 v2, which carries the public key alongside
 * the private one, is NOT accepted: it is a second spelling of the same key.
 */
public final class KeyCodec {

  private static final byte[] SPKI_PREFIX = {
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
  };
  private static final byte[] PKCS8_PREFIX = {
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
  };

  private static final String PEM_PUBLIC = "PUBLIC KEY";
  private static final String PEM_PRIVATE = "PRIVATE KEY";
  private static final int KEY_LEN = 32;

  private KeyCodec() {}

  /** A public key as an RFC 5280 SPKI PEM block. */
  public static byte[] pubkeyToSpkiPem(byte[] pubkey) {
    return encode(pubkey, SPKI_PREFIX, PEM_PUBLIC);
  }

  /** A seed as an RFC 5958 PKCS-8 v1 PEM block. */
  public static byte[] seedToPkcs8Pem(byte[] seed) {
    return encode(seed, PKCS8_PREFIX, PEM_PRIVATE);
  }

  /** The 32 public-key bytes from an SPKI PEM block, or throws. */
  public static byte[] spkiPemToPubkey(byte[] pem) {
    return decode(pem, SPKI_PREFIX, PEM_PUBLIC);
  }

  /** The 32 seed bytes from a PKCS-8 v1 PEM block, or throws. */
  public static byte[] pkcs8PemToSeed(byte[] pem) {
    return decode(pem, PKCS8_PREFIX, PEM_PRIVATE);
  }

  private static byte[] encode(byte[] key, byte[] prefix, String pemType) {
    if (key.length != KEY_LEN) {
      throw new IllegalArgumentException(
          "keycodec: key must be " + KEY_LEN + " bytes, got " + key.length);
    }
    byte[] der = new byte[prefix.length + KEY_LEN];
    System.arraycopy(prefix, 0, der, 0, prefix.length);
    System.arraycopy(key, 0, der, prefix.length, KEY_LEN);
    String body = Base64.getEncoder().encodeToString(der);
    String pem = "-----BEGIN " + pemType + "-----\n" + body + "\n-----END " + pemType + "-----\n";
    return pem.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] decode(byte[] pemBytes, byte[] prefix, String pemType) {
    String text = new String(pemBytes, StandardCharsets.US_ASCII).replace("\r\n", "\n");
    while (text.endsWith("\n")) {
      text = text.substring(0, text.length() - 1);
    }
    String begin = "-----BEGIN " + pemType + "-----";
    String end = "-----END " + pemType + "-----";
    String[] lines = text.split("\n", -1);
    if (lines.length < 3 || !lines[0].equals(begin) || !lines[lines.length - 1].equals(end)) {
      throw new IllegalArgumentException("keycodec: not a \"" + pemType + "\" PEM block");
    }
    StringBuilder joined = new StringBuilder();
    for (int i = 1; i < lines.length - 1; i++) {
      joined.append(lines[i]);
    }
    byte[] der;
    try {
      // The strict decoder: base64 carrying stray characters is refused rather than skipped,
      // which is what a lenient (MIME) decoder would do.
      der = Base64.getDecoder().decode(joined.toString());
    } catch (IllegalArgumentException bad) {
      throw new IllegalArgumentException("keycodec: invalid base64 in PEM body: " + bad.getMessage());
    }
    if (der.length != prefix.length + KEY_LEN
        || !Arrays.equals(Arrays.copyOf(der, prefix.length), prefix)) {
      throw new IllegalArgumentException(
          "keycodec: DER does not match the " + pemType + " ed25519-key-codec-v1 template");
    }
    return Arrays.copyOfRange(der, prefix.length, der.length);
  }
}
