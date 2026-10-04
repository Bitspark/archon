package dev.bitspark.archon.sdk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import dev.bitspark.archon.core.Crypto;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * The signer seam (ADR 0009 §2–4): every helper through a {@link Signing.Signer} produces the SAME
 * bytes the seed methods produce — checked against vectors/sdk.json, whose signatures OpenSSL
 * derived — and every rule the seam enforces is exercised against a signer that breaks it.
 */
final class SignerTest {

  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] SEED = filled(7);
  private static final String DOMAIN = "archon/test/pop";
  private static final byte[] NONCE = new byte[16];
  private static final byte[] BINDING = "b".getBytes(StandardCharsets.UTF_8);

  private static byte[] filled(int b) {
    byte[] out = new byte[32];
    Arrays.fill(out, (byte) b);
    return out;
  }

  private static JsonObject vectors() throws IOException {
    return JsonParser.parseString(Files.readString(Path.of("../../vectors/sdk.json"))).getAsJsonObject();
  }

  private static byte[] hex(JsonObject c, String member) {
    return HEX.parseHex(c.get(member).getAsString());
  }

  @Test
  void throughASeedSignerEveryHelperReproducesTheVectors() throws IOException {
    JsonObject v = vectors();
    int checked = 0;
    int okCases = 0;
    for (JsonElement e : v.getAsJsonArray("possession_prove")) {
      JsonObject c = e.getAsJsonObject();
      if (!c.getAsJsonObject("result").has("ok")) {
        continue;
      }
      okCases++;
      byte[] sig =
          Possession.proveWith(
              Signing.seedSigner(hex(c, "seed")),
              c.get("domain").getAsString(),
              hex(c, "nonce"),
              hex(c, "binding"));
      assertEquals(c.getAsJsonObject("result").get("ok").getAsString(), HEX.formatHex(sig), c.get("name").getAsString());
      checked++;
    }
    for (JsonElement e : v.getAsJsonArray("envelope_seal")) {
      JsonObject c = e.getAsJsonObject();
      if (!c.getAsJsonObject("result").has("ok")) {
        continue;
      }
      okCases++;
      byte[] env =
          Envelope.sealWith(
              Signing.seedSigner(hex(c, "seed")), c.get("domain").getAsString(), hex(c, "payload"));
      assertEquals(c.getAsJsonObject("result").get("ok").getAsString(), HEX.formatHex(env), c.get("name").getAsString());
      checked++;
    }
    // Every ok case: a key slip that skipped them all would otherwise pass in silence.
    assertEquals(okCases, checked);
    assertTrue(checked >= 6, "checked " + checked + " vector cases");
  }

  /** A signer that counts its calls and signs however {@code how} says. */
  private static final class Fake implements Signing.Signer {
    final byte[] publicKey;
    final Signing.Capabilities capabilities;
    final Function<Signing.Request, byte[]> how;
    int calls;

    Fake(byte[] publicKey, Signing.Capabilities capabilities, Function<Signing.Request, byte[]> how) {
      this.publicKey = publicKey;
      this.capabilities = capabilities;
      this.how = how;
    }

    @Override
    public byte[] publicKey() {
      return publicKey.clone();
    }

    @Override
    public Signing.Capabilities capabilities() {
      return capabilities;
    }

    @Override
    public byte[] sign(Signing.Request request) {
      calls++;
      return how.apply(request);
    }
  }

  @Test
  void anOutOfRangeRequestIsRefusedBeforeTheSignerIsCalled() {
    Fake f = new Fake(Crypto.publicKeyFromSeed(SEED), Signing.Capabilities.all(), r -> Crypto.sign(SEED, r.message()));
    assertThrows(IllegalArgumentException.class, () -> Possession.proveWith(f, "", NONCE, BINDING));
    assertThrows(IllegalArgumentException.class, () -> Possession.proveWith(f, DOMAIN, new byte[15], BINDING));
    assertThrows(IllegalArgumentException.class, () -> Envelope.sealWith(f, "d".repeat(256), new byte[0]));
    assertThrows(
        IllegalArgumentException.class,
        () -> Signing.signWith(f, new Signing.Request(new byte[31], new Signing.Raw(), new byte[1])));
    assertEquals(0, f.calls, "the signer must never have been called");
  }

  @Test
  void aSignerIsAskedOnlyForWhatItSaysItCanDo() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    Signing.Request request = Possession.prepare(pub, DOMAIN, NONCE, BINDING);
    Fake rawOnly = new Fake(pub, new Signing.Capabilities(List.of(Signing.RAW), Optional.empty()), r -> Crypto.sign(SEED, r.message()));
    Fake elsewhere =
        new Fake(
            pub,
            new Signing.Capabilities(List.of(Signing.PH_CONTEXT), Optional.of(List.of("archon/test/other"))),
            r -> Crypto.signInDomain(SEED, DOMAIN, r.message()));
    Fake otherKey = new Fake(Crypto.publicKeyFromSeed(filled(8)), Signing.Capabilities.all(), r -> Crypto.sign(SEED, r.message()));
    assertTrue(assertThrows(IllegalArgumentException.class, () -> Signing.signWith(rawOnly, request)).getMessage().contains("cannot produce"));
    assertTrue(assertThrows(IllegalArgumentException.class, () -> Signing.signWith(elsewhere, request)).getMessage().contains("does not sign in domain"));
    assertTrue(assertThrows(IllegalArgumentException.class, () -> Signing.signWith(otherKey, request)).getMessage().contains("not the expected key"));
    assertEquals(0, rawOnly.calls + elsewhere.calls + otherKey.calls);
  }

  @Test
  void aSignatureIsCheckedAgainstTheRequestNeverTheSignersWord() {
    byte[] pub = Crypto.publicKeyFromSeed(SEED);
    Signing.Request request = Possession.prepare(pub, DOMAIN, NONCE, BINDING);
    List<Function<Signing.Request, byte[]>> liars =
        List.of(
            r -> Crypto.signInDomain(filled(8), DOMAIN, r.message()), // another key
            r -> Crypto.sign(SEED, r.message()), // drops the context, signs raw
            r -> Crypto.signInDomain(SEED, "archon/test/other", r.message()), // another domain
            r -> Crypto.signInDomain(SEED, DOMAIN, new byte[] {0}), // other bytes
            r -> Arrays.copyOf(Crypto.signInDomain(SEED, DOMAIN, r.message()), 63)); // 63 bytes
    for (Function<Signing.Request, byte[]> how : liars) {
      Fake f = new Fake(pub, Signing.Capabilities.all(), how);
      assertTrue(
          assertThrows(IllegalArgumentException.class, () -> Signing.signWith(f, request))
              .getMessage()
              .contains("does not verify"));
      assertThrows(IllegalArgumentException.class, () -> Possession.complete(request, how.apply(request)));
    }
  }

  @Test
  void completeAssemblesFromTheRequestAndTheSeedSignerIsDeterministic() {
    Signing.Signer s = Signing.seedSigner(SEED);
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    Signing.Request request = Envelope.prepareSeal(s.publicKey(), "archon/test/env", payload);
    byte[] first = s.sign(request);
    assertArrayEquals(first, s.sign(request), "signing twice gives the same bytes");
    byte[] env = Envelope.completeSeal(request, first);
    assertArrayEquals(payload, Envelope.open(env, "archon/test/env").payload());
    assertThrows(
        IllegalArgumentException.class,
        () -> Envelope.completeSeal(Possession.prepare(s.publicKey(), "d", NONCE, BINDING), first));
    assertArrayEquals(first, Signing.checkSignature(request, first));
  }
}
