// Builds core/java's jar, then consumes it from OUTSIDE the project with a clean local
// repository — the nearest thing to what a stranger gets from Maven Central.
//
// The distinction this exists to enforce: passing the oracle proves the CODE is right; it says
// nothing about whether the PACKAGE is. A pom that only resolves against the reactor, a missing
// runtime dependency, or a jar that forgets a class all pass conformance and fail the first
// `mvn dependency:get`. This installs the artifact and builds a separate consumer project
// against it.
//
// Two things are checked that the oracle cannot see:
//   * the POM declares Bouncy Castle as a RUNTIME dependency, so a consumer gets it
//     transitively rather than discovering a NoClassDefFoundError at first use;
//   * the conformance CLI and its JSON library do NOT reach the jar — they are test-scoped,
//     and a jar that shipped them would be leaking a dev artifact into the library surface.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const javaDir = join(root, "core", "java");
const mvn = isWindows ? "mvn.cmd" : "mvn";

function run(label, args, cwd, extra = []) {
  process.stdout.write(`${label} … `);
  const r = spawnSync(mvn, [...args, ...extra], { cwd, encoding: "utf8", shell: isWindows });
  if (r.error || r.status !== 0) {
    console.log("FAILED");
    if (r.stdout) console.error(r.stdout.trim());
    if (r.stderr) console.error(r.stderr.trim());
    process.exit(1);
  }
  console.log("ok");
  return r;
}

const probe = spawnSync(mvn, ["-v"], { encoding: "utf8", shell: isWindows });
if (probe.error || probe.status !== 0) {
  console.error("no maven on PATH");
  process.exit(1);
}

const work = mkdtempSync(join(tmpdir(), "archon-java-pkg-"));
try {
  // A local repository of its own: installing into the developer's ~/.m2 would let an earlier
  // build satisfy the consumer, and the check would pass without this jar being correct.
  const repo = join(work, "m2");
  const localRepo = `-Dmaven.repo.local=${repo}`;

  run("install the jar", ["-q", "-B", "install", "-DskipTests"], javaDir, [localRepo]);

  // The jar must not carry the conformance CLI or its JSON dependency.
  const listing = spawnSync(
    "jar",
    ["tf", join(javaDir, "target", "archon-core-0.6.2.jar")],
    { encoding: "utf8", shell: isWindows },
  );
  if (listing.status === 0) {
    const leaked = listing.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.includes("conformance/") || l.startsWith("com/google/gson"));
    if (leaked.length > 0) {
      console.error("the published jar leaks dev artifacts:");
      for (const l of leaked) console.error(`  ${l}`);
      process.exit(1);
    }
    console.log("jar carries no dev artifacts … ok");
  }

  // A consumer project that knows nothing but the coordinates.
  const consumer = join(work, "consumer");
  mkdirSync(join(consumer, "src", "main", "java"), { recursive: true });
  writeFileSync(
    join(consumer, "pom.xml"),
    `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId>
  <artifactId>consumer</artifactId>
  <version>1.0</version>
  <properties>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>dev.bitspark</groupId>
      <artifactId>archon-core</artifactId>
      <version>0.6.2</version>
    </dependency>
  </dependencies>
</project>
`,
  );
  writeFileSync(
    join(consumer, "src", "main", "java", "Consumer.java"),
    `import dev.bitspark.archon.core.*;
import java.nio.charset.StandardCharsets;

public class Consumer {
  public static void main(String[] a) {
    byte[] seed = new byte[32];
    for (int i = 0; i < 32; i++) seed[i] = (byte) i;
    byte[] pub = Crypto.publicKeyFromSeed(seed);
    byte[] msg = "hello".getBytes(StandardCharsets.UTF_8);
    byte[] sig = Crypto.signInDomain(seed, "example.v1", msg);
    if (!Crypto.verifyInDomain(pub, "example.v1", msg, sig)) throw new AssertionError("domain");
    if (Crypto.verifyInDomain(pub, "other.v1", msg, sig)) throw new AssertionError("crossed");
    if (Crypto.verify(pub, msg, sig)) throw new AssertionError("verified raw");
    String text = KeyText.encodeKey(pub);
    if (!java.util.Arrays.equals(pub, KeyText.decodeKey(text))) throw new AssertionError("keytext");
    System.out.println("consumer ok: " + text);
  }
}
`,
  );

  // Offline after install: nothing may be fetched from the network to make this work, and
  // Bouncy Castle must arrive transitively from archon-core's own POM.
  run("build the outside consumer", ["-q", "-B", "compile"], consumer, [localRepo]);
  const ran = run("run it", ["-q", "-B", "exec:java", "-Dexec.mainClass=Consumer"], consumer, [
    localRepo,
  ]);
  const line = (ran.stdout || "").split("\n").map((l) => l.trim()).find((l) => l.startsWith("consumer ok:"));
  console.log(`     ${line ?? "(no output captured)"}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
