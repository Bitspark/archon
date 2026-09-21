package dev.bitspark.archon.core.conformance;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.bitspark.archon.core.Crypto;
import dev.bitspark.archon.core.HexBytes;
import dev.bitspark.archon.core.KeyCodec;
import dev.bitspark.archon.core.KeyText;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

/**
 * Conformance CLI (java) — a dev/CI artifact, not part of the library surface. It lives in test
 * sources and takes a JSON dependency at test scope so that neither reaches the published jar.
 *
 * <p>Implements the {@code conformance v1} protocol: {@code conformance <family>} reads the whole
 * vectors/identity.json on stdin, selects its family's cases, RECOMPUTES each result from the case
 * INPUTS (ignoring the expected value the oracle carries), and writes one NDJSON line per case to
 * stdout in input order.
 *
 * <p>Recomputing rather than echoing is the whole point: a CLI that read {@code result} from the
 * case would agree with the oracle by construction and prove nothing.
 */
public final class Cli {

  private static final Gson GSON = new Gson();

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      System.err.println("usage: conformance <family>");
      System.exit(2);
    }
    String family = args[0];

    JsonObject doc;
    try (InputStreamReader in = new InputStreamReader(System.in, StandardCharsets.UTF_8)) {
      doc = GSON.fromJson(in, JsonObject.class);
    }
    JsonElement familyElement = doc.get(family);
    if (familyElement == null) {
      System.err.println("conformance: no such family: " + family);
      System.exit(1);
    }

    PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
    for (JsonElement element : familyElement.getAsJsonArray()) {
      JsonObject c = element.getAsJsonObject();
      // Some families open with a note object carrying no name.
      if (!c.has("name")) {
        continue;
      }
      JsonObject result = new JsonObject();
      result.addProperty("name", c.get("name").getAsString());

      switch (family) {
        case "pubkey_from_seed" ->
            result.addProperty(
                "pubkey", HexBytes.toHex(Crypto.publicKeyFromSeed(unhex(c, "seed"))));

        case "key_encode" ->
            result.addProperty("text", KeyText.encodeKey(unhex(c, "pubkey")));

        case "keycodec" -> {
          String kind = c.get("kind").getAsString();
          Supplier<String> work =
              switch (kind) {
                case "encode_pkcs8" ->
                    () -> new String(KeyCodec.seedToPkcs8Pem(unhex(c, "key")), StandardCharsets.US_ASCII);
                case "encode_spki" ->
                    () -> new String(KeyCodec.pubkeyToSpkiPem(unhex(c, "key")), StandardCharsets.US_ASCII);
                case "decode_pkcs8" ->
                    () -> HexBytes.toHex(KeyCodec.pkcs8PemToSeed(pem(c)));
                case "decode_spki" ->
                    () -> HexBytes.toHex(KeyCodec.spkiPemToPubkey(pem(c)));
                default -> throw new IllegalStateException("unknown keycodec kind: " + kind);
              };
          result.add("result", attempt(work));
        }

        case "signature_verify" ->
            result.addProperty(
                "valid", Crypto.verify(unhex(c, "pubkey"), unhex(c, "message"), unhex(c, "sig")));

        case "hex_decode" -> {
          String kind = c.get("kind").getAsString();
          String text = c.get("hex").getAsString();
          Supplier<String> work =
              switch (kind) {
                case "seed" -> () -> HexBytes.toHex(HexBytes.seedFromHex(text));
                case "pubkey" -> () -> HexBytes.toHex(HexBytes.pubkeyFromHex(text));
                case "signature" -> () -> HexBytes.toHex(HexBytes.signatureFromHex(text));
                default -> throw new IllegalStateException("unknown hex_decode kind: " + kind);
              };
          result.add("result", attempt(work));
        }

        case "domain_sign" ->
            result.add(
                "result",
                attempt(
                    () ->
                        HexBytes.toHex(
                            Crypto.signInDomain(
                                unhex(c, "seed"),
                                c.get("domain").getAsString(),
                                unhex(c, "message")))));

        case "domain_verify" ->
            result.addProperty(
                "valid",
                Crypto.verifyInDomain(
                    unhex(c, "pubkey"),
                    c.get("domain").getAsString(),
                    unhex(c, "message"),
                    unhex(c, "sig")));

        default -> {
          System.err.println("conformance: unhandled family: " + family);
          System.exit(1);
        }
      }
      out.println(GSON.toJson(result));
    }
    out.flush();
  }

  /** The oracle's two-shape result: {@code {"ok": …}} or {@code {"error": true}}. */
  private static JsonObject attempt(Supplier<String> work) {
    JsonObject result = new JsonObject();
    try {
      result.addProperty("ok", work.get());
    } catch (RuntimeException refused) {
      result.addProperty("error", true);
    }
    return result;
  }

  private static byte[] unhex(JsonObject c, String field) {
    String s = c.get(field).getAsString();
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }

  private static byte[] pem(JsonObject c) {
    return c.get("pem").getAsString().getBytes(StandardCharsets.UTF_8);
  }

  private Cli() {}
}
