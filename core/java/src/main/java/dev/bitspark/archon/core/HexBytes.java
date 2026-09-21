package dev.bitspark.archon.core;

/**
 * Typed, fail-closed hex spellings.
 *
 * <p>Not a hex helper — every language has one — but the FIXED SIZE. Each decoder accepts exactly
 * its type's byte count or fails, and the length is checked on the TEXT before any byte is
 * decoded. Either case in, lowercase out. No {@code 0x}, no whitespace, no odd-length bodies.
 */
public final class HexBytes {

  private HexBytes() {}

  /** Lowercase hex, no prefix. */
  public static String toHex(byte[] data) {
    StringBuilder out = new StringBuilder(data.length * 2);
    for (byte b : data) {
      out.append(Character.forDigit((b >> 4) & 0xF, 16));
      out.append(Character.forDigit(b & 0xF, 16));
    }
    return out.toString();
  }

  /** Exactly 32 bytes, or throws. */
  public static byte[] seedFromHex(String text) {
    return fixed(text, Crypto.SEED_SIZE, "seed");
  }

  /** Exactly 32 bytes, or throws. */
  public static byte[] pubkeyFromHex(String text) {
    return fixed(text, Crypto.PUBLIC_KEY_SIZE, "public key");
  }

  /** Exactly 64 bytes, or throws. */
  public static byte[] signatureFromHex(String text) {
    return fixed(text, Crypto.SIGNATURE_SIZE, "signature");
  }

  private static byte[] fixed(String text, int n, String what) {
    if (text.length() != n * 2) {
      throw new IllegalArgumentException(
          "hexbytes: " + what + " hex is " + text.length() + " characters, expected " + n * 2);
    }
    byte[] out = new byte[n];
    for (int i = 0; i < n; i++) {
      int hi = digit(text.charAt(2 * i), what);
      int lo = digit(text.charAt(2 * i + 1), what);
      out[i] = (byte) ((hi << 4) | lo);
    }
    return out;
  }

  /**
   * One hex digit, or a refusal.
   *
   * <p>{@code Character.digit} would also accept non-ASCII digits and other radix-16 characters
   * the grammar does not allow, so the alphabet is checked explicitly. The other cores reject
   * those, and agreement is the point.
   */
  private static int digit(char c, String what) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    throw new IllegalArgumentException("hexbytes: " + what + ": non-hex character '" + c + "'");
  }
}
