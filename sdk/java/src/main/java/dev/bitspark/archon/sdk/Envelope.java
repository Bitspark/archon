package dev.bitspark.archon.sdk;

import dev.bitspark.archon.core.Crypto;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The signed envelope — <em>these bytes, signed by this key, in this domain.</em>
 *
 * <p>A fixed binary container, JWS-shaped and deliberately not JWT-shaped:
 *
 * <pre>
 *   "arcn" ‖ 0x01 ‖ u8(len domain) ‖ domain ‖ pubkey[32] ‖ signature[64] ‖ payload
 * </pre>
 *
 * <p>where {@code signature = signInDomain(seed, domain, SCHEME_TAG ‖ payload)}. The domain is
 * bound cryptographically (it is the RFC 8032 context), the public key is bound by verification,
 * and the payload is opaque: the envelope says nothing about what it means. <strong>What is not
 * here, on purpose:</strong> expiry, issuer, audience, key-id, nonce. Each is either policy —
 * whose clock, whose trust? — or a second spelling of the key, and both belong to the consumer.
 *
 * <p>{@link #open} takes the domain the <em>verifier</em> expects and refuses an envelope that
 * claims another. The verifier chooses the domain; an envelope never gets to choose it for them.
 * Whether to trust the key it names is, again, the verifier's.
 */
public final class Envelope {

  /** The first four bytes of every envelope: {@code "arcn"}. */
  private static final byte[] MAGIC = {0x61, 0x72, 0x63, 0x6e};

  /** The envelope format version. */
  public static final int VERSION = 0x01;

  /** The first byte of every signed envelope message. Distinct from {@link Possession#SCHEME_TAG}. */
  public static final int SCHEME_TAG = 0x02;

  private Envelope() {}

  /** The first four bytes of every envelope, {@code "arcn"}. A fresh copy on every call. */
  public static byte[] magic() {
    return MAGIC.clone();
  }

  /**
   * What {@link #open} returns: the sealing key and the payload, both verified. The accessors
   * return copies, so an {@code Opened} cannot be altered after the check that produced it.
   */
  public static final class Opened {
    private final byte[] pubkey;
    private final byte[] payload;

    private Opened(byte[] pubkey, byte[] payload) {
      this.pubkey = pubkey;
      this.payload = payload;
    }

    /** The public key that sealed the envelope. Trusting it is the caller's decision. */
    public byte[] pubkey() {
      return pubkey.clone();
    }

    /** The payload, verbatim. */
    public byte[] payload() {
      return payload.clone();
    }
  }

  /**
   * Seal {@code payload} in {@code domain} with the key behind {@code seed}. An empty payload is
   * allowed — the signed message is never empty, because of the scheme tag.
   *
   * @throws IllegalArgumentException on an invalid domain (see {@link Crypto#signInDomain}) or a
   *     seed that is not 32 bytes
   */
  public static byte[] seal(byte[] seed, String domain, byte[] payload) {
    if (payload == null) {
      throw new IllegalArgumentException("envelope: payload is required (it may be empty)");
    }
    // Signing first: it is what validates the domain and the seed, so nothing below is reached
    // with either one wrong.
    byte[] signature = Crypto.signInDomain(seed, domain, messageBytes(payload));
    byte[] pubkey = Crypto.publicKeyFromSeed(seed);
    byte[] d = domain.getBytes(StandardCharsets.UTF_8);
    byte[] out =
        new byte
            [MAGIC.length + 2 + d.length + Crypto.PUBLIC_KEY_SIZE + Crypto.SIGNATURE_SIZE
                + payload.length];
    int at = 0;
    System.arraycopy(MAGIC, 0, out, at, MAGIC.length);
    at += MAGIC.length;
    out[at++] = (byte) VERSION;
    out[at++] = (byte) d.length; // <= 255: signInDomain has already checked it
    System.arraycopy(d, 0, out, at, d.length);
    at += d.length;
    System.arraycopy(pubkey, 0, out, at, pubkey.length);
    at += pubkey.length;
    System.arraycopy(signature, 0, out, at, signature.length);
    at += signature.length;
    System.arraycopy(payload, 0, out, at, payload.length);
    return out;
  }

  /**
   * Open {@code envelope}, which the caller expects to be sealed in {@code domain}. Never
   * returns an unverified payload.
   *
   * @throws IllegalArgumentException when the bytes are not an envelope (magic, version,
   *     length), the envelope claims a different domain, or the signature does not verify
   */
  public static Opened open(byte[] envelope, String domain) {
    if (envelope == null || domain == null) {
      throw new IllegalArgumentException("envelope: the envelope and the expected domain are required");
    }
    Reader in = new Reader(envelope);
    if (!Arrays.equals(in.take(MAGIC.length), MAGIC)) {
      throw new IllegalArgumentException("envelope: not an envelope, bad magic");
    }
    int version = in.take(1)[0] & 0xff;
    if (version != VERSION) {
      throw new IllegalArgumentException("envelope: unsupported version " + version);
    }
    int dlen = in.take(1)[0] & 0xff;
    if (dlen == 0 || dlen > Crypto.MAX_DOMAIN_SIZE) {
      throw new IllegalArgumentException("envelope: domain length " + dlen + " out of range");
    }
    byte[] claimed = in.take(dlen);
    // The verifier's expectation decides, before any signature is checked. An envelope that
    // names another domain is refused here even when its signature is genuine in that one.
    if (!Arrays.equals(claimed, domain.getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException("envelope: claims a different domain");
    }
    byte[] pubkey = in.take(Crypto.PUBLIC_KEY_SIZE);
    byte[] signature = in.take(Crypto.SIGNATURE_SIZE);
    byte[] payload = in.rest();
    if (!Crypto.verifyInDomain(pubkey, domain, messageBytes(payload), signature)) {
      throw new IllegalArgumentException("envelope: signature does not verify");
    }
    return new Opened(pubkey, payload);
  }

  /** The pinned layout of what gets signed: the scheme tag, then the payload verbatim. */
  public static byte[] messageBytes(byte[] payload) {
    byte[] out = new byte[1 + payload.length];
    out[0] = (byte) SCHEME_TAG;
    System.arraycopy(payload, 0, out, 1, payload.length);
    return out;
  }

  /** A cursor over the envelope that refuses to read past its end. */
  private static final class Reader {
    private final byte[] bytes;
    private int at;

    Reader(byte[] bytes) {
      this.bytes = bytes;
    }

    byte[] take(int n) {
      if (at + n > bytes.length) {
        throw new IllegalArgumentException("envelope: truncated at byte " + bytes.length);
      }
      byte[] chunk = Arrays.copyOfRange(bytes, at, at + n);
      at += n;
      return chunk;
    }

    byte[] rest() {
      byte[] tail = Arrays.copyOfRange(bytes, at, bytes.length);
      at = bytes.length;
      return tail;
    }
  }
}
