package dev.bitspark.archon.sdk.conformance;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.bitspark.archon.sdk.Envelope;
import dev.bitspark.archon.sdk.Possession;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.function.Supplier;

/**
 * Conformance CLI (java, sdk) — a dev/CI artifact, not part of the library surface. It lives in
 * test sources and takes a JSON dependency at test scope so that neither reaches the published
 * jar.
 *
 * <p>The same {@code conformance v1} protocol as the floor's CLI: {@code conformance <family>}
 * reads the whole vectors/sdk.json on stdin, selects its family, RECOMPUTES each result from the
 * case INPUTS (ignoring the expected value the oracle carries), and writes one NDJSON line per
 * case to stdout in input order.
 *
 * <pre>
 *   possession_prove  : in {name, seed, domain, nonce, binding}        out {"name","result":{"ok":"&lt;128-hex&gt;"}|{"error":true}}
 *   possession_verify : in {name, pubkey, domain, nonce, binding, sig} out {"name","valid":&lt;bool&gt;}
 *   envelope_seal     : in {name, seed, domain, payload}               out {"name","result":{"ok":"&lt;hex&gt;"}|{"error":true}}
 *   envelope_open     : in {name, envelope, domain}                    out {"name","result":{"ok":{"pubkey","payload"}}|{"error":true}}
 * </pre>
 */
public final class Cli {

  private static final Gson GSON = new Gson();
  private static final HexFormat HEX = HexFormat.of();

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
    if (familyElement == null || !familyElement.isJsonArray()) {
      System.err.println("conformance: no such family: " + family);
      System.exit(1);
    }

    PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
    for (JsonElement element : familyElement.getAsJsonArray()) {
      JsonObject c = element.getAsJsonObject();
      JsonObject result = new JsonObject();
      result.addProperty("name", c.get("name").getAsString());

      switch (family) {
        case "possession_prove" ->
            result.add(
                "result",
                attempt(
                    () ->
                        HEX.formatHex(
                            Possession.prove(
                                unhex(c, "seed"), text(c, "domain"), unhex(c, "nonce"),
                                unhex(c, "binding")))));

        case "possession_verify" ->
            result.addProperty(
                "valid",
                Possession.verify(
                    unhex(c, "pubkey"), text(c, "domain"), unhex(c, "nonce"),
                    unhex(c, "binding"), unhex(c, "sig")));

        case "envelope_seal" ->
            result.add(
                "result",
                attempt(
                    () ->
                        HEX.formatHex(
                            Envelope.seal(unhex(c, "seed"), text(c, "domain"), unhex(c, "payload")))));

        case "envelope_open" -> {
          JsonObject r = new JsonObject();
          try {
            Envelope.Opened o = Envelope.open(unhex(c, "envelope"), text(c, "domain"));
            JsonObject ok = new JsonObject();
            ok.addProperty("pubkey", HEX.formatHex(o.pubkey()));
            ok.addProperty("payload", HEX.formatHex(o.payload()));
            r.add("ok", ok);
          } catch (RuntimeException refused) {
            r.addProperty("error", true);
          }
          result.add("result", r);
        }

        default -> {
          System.err.println("conformance: no such family: " + family);
          System.exit(1);
        }
      }
      out.println(GSON.toJson(result));
    }
    out.flush();
  }

  // The oracle distinguishes success-with-a-value from failure, never the message.
  private static JsonObject attempt(Supplier<String> work) {
    JsonObject result = new JsonObject();
    try {
      result.addProperty("ok", work.get());
    } catch (RuntimeException refused) {
      result.addProperty("error", true);
    }
    return result;
  }

  // Case inputs that are already known-good hex; a bad one is a broken vector file, not a case.
  private static byte[] unhex(JsonObject c, String field) {
    return HEX.parseHex(c.get(field).getAsString());
  }

  private static String text(JsonObject c, String field) {
    return c.get(field).getAsString();
  }

  private Cli() {}
}
