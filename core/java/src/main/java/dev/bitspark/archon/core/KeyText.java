package dev.bitspark.archon.core;

/**
 * The canonical key spelling: {@code ed25519:<64 lowercase hex>}.
 *
 * <p>One spelling, in every language. The prefix is required; the body is exactly 64 hex digits
 * decoding to a 32-byte public key. Length and alphabet are part of the grammar, not decoration —
 * a body of the wrong length is refused even when it is valid hex.
 */
public final class KeyText {

  private static final String PREFIX = "ed25519:";

  private KeyText() {}

  /** {@code ed25519:} followed by the key as lowercase hex. */
  public static String encodeKey(byte[] pubkey) {
    return PREFIX + HexBytes.toHex(pubkey);
  }

  /** The 32 key bytes, or throws — missing prefix, odd length, non-hex, wrong size. */
  public static byte[] decodeKey(String text) {
    if (!text.startsWith(PREFIX)) {
      throw new IllegalArgumentException("keytext: missing \"" + PREFIX + "\" prefix");
    }
    String body = text.substring(PREFIX.length());
    if (body.length() % 2 != 0) {
      throw new IllegalArgumentException("keytext: key body has an odd number of hex digits");
    }
    if (body.length() != Crypto.PUBLIC_KEY_SIZE * 2) {
      // Checked before decoding so that a wrong-length body fails as a length error rather than
      // reaching the decoder at all — same order as the other cores.
      throw new IllegalArgumentException(
          "keytext: decoded key is "
              + body.length() / 2
              + " bytes, expected "
              + Crypto.PUBLIC_KEY_SIZE);
    }
    return HexBytes.pubkeyFromHex(body);
  }
}
