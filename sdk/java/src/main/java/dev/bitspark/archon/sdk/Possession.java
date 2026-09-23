package dev.bitspark.archon.sdk;

import dev.bitspark.archon.core.Crypto;

/**
 * Proof of possession — <em>can they sign, right now, for this channel?</em>
 *
 * <p>The challenger picks a {@code nonce} (fresh entropy, at least 16 bytes — its own, never this
 * library's) and a {@code binding} (something only this channel has: a session key, a TLS
 * exporter, the server's identity — the transport's, never this library's). The prover signs a
 * fixed layout of both in the protocol's domain; the challenger verifies with the prover's public
 * key.
 *
 * <p><strong>The binding is what makes this a proof.</strong> A signed nonce alone is relayable:
 * an attacker facing the server as the victim forwards the server's nonce to the victim under some
 * pretext, gets it signed, and presents the signature. Bound to the channel, the signature is
 * worthless anywhere else. So an empty binding is refused outright — the thing it would produce
 * looks like a proof and is not one.
 *
 * <p>The signed bytes are {@code SCHEME_TAG ‖ u16be(len nonce) ‖ nonce ‖ u16be(len binding) ‖
 * binding}, signed with {@link Crypto#signInDomain} in the caller's domain. The tag keeps a
 * possession message and an envelope payload in the same domain from ever being the same bytes.
 */
public final class Possession {

  /** The first byte of every possession message. Distinct from {@link Envelope#SCHEME_TAG}. */
  public static final int SCHEME_TAG = 0x01;

  /** The shortest nonce accepted, in bytes. Below this a proof is guessable, so it is refused. */
  public static final int MIN_NONCE_SIZE = 16;

  /** The longest nonce or binding, in bytes — the u16 length prefix's bound. */
  public static final int MAX_FIELD_SIZE = 0xFFFF;

  private Possession() {}

  /**
   * Prove possession of the key behind {@code seed} to a challenger who supplied {@code nonce}
   * and {@code binding}, in {@code domain}.
   *
   * @throws IllegalArgumentException on an invalid domain (see {@link Crypto#signInDomain}), a
   *     seed that is not 32 bytes, a nonce shorter than {@link #MIN_NONCE_SIZE}, an empty
   *     binding, or either field over {@link #MAX_FIELD_SIZE}
   */
  public static byte[] prove(byte[] seed, String domain, byte[] nonce, byte[] binding) {
    return Crypto.signInDomain(seed, domain, messageBytes(nonce, binding));
  }

  /**
   * True when {@code signature} was made by the key behind {@code pubkey} over this {@code
   * nonce} and {@code binding} in {@code domain}.
   *
   * <p>Total: every shape failure — bad domain, short nonce, empty binding, wrong-sized or
   * missing key or signature — is {@code false}, never an exception, so a caller cannot mistake
   * <em>malformed</em> for <em>valid</em>.
   */
  public static boolean verify(
      byte[] pubkey, String domain, byte[] nonce, byte[] binding, byte[] signature) {
    if (pubkey == null || domain == null || signature == null) {
      return false;
    }
    byte[] message;
    try {
      message = messageBytes(nonce, binding);
    } catch (IllegalArgumentException malformed) {
      return false;
    }
    return Crypto.verifyInDomain(pubkey, domain, message, signature);
  }

  /** The pinned layout of what gets signed. Public so a consumer can pin it too. */
  public static byte[] messageBytes(byte[] nonce, byte[] binding) {
    if (nonce == null || binding == null) {
      throw new IllegalArgumentException("possession: nonce and binding are required");
    }
    if (nonce.length < MIN_NONCE_SIZE) {
      throw new IllegalArgumentException(
          "possession: nonce is " + nonce.length + " bytes, min " + MIN_NONCE_SIZE);
    }
    if (nonce.length > MAX_FIELD_SIZE) {
      throw new IllegalArgumentException(
          "possession: nonce is " + nonce.length + " bytes, max " + MAX_FIELD_SIZE);
    }
    if (binding.length == 0) {
      throw new IllegalArgumentException(
          "possession: binding is empty — an unbound proof is not a proof");
    }
    if (binding.length > MAX_FIELD_SIZE) {
      throw new IllegalArgumentException(
          "possession: binding is " + binding.length + " bytes, max " + MAX_FIELD_SIZE);
    }
    byte[] out = new byte[1 + 2 + nonce.length + 2 + binding.length];
    int at = 0;
    out[at++] = (byte) SCHEME_TAG;
    out[at++] = (byte) (nonce.length >>> 8);
    out[at++] = (byte) nonce.length;
    System.arraycopy(nonce, 0, out, at, nonce.length);
    at += nonce.length;
    out[at++] = (byte) (binding.length >>> 8);
    out[at++] = (byte) binding.length;
    System.arraycopy(binding, 0, out, at, binding.length);
    return out;
  }
}
