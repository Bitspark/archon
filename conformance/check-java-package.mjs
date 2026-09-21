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
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const javaDir = join(root, "core", "java");
const mvn = isWindows ? "mvn.cmd" : "mvn";

// The version comes from the POM, never from a literal here. It was hardcoded once, and the
// release bump to 0.7.0 left this script asking Maven for an 0.6.2 artifact that no longer
// existed — a package check that fails for its own reason, not the package's, is worse than
// no check, because the red says "your jar is broken" and means "my script is stale".
const POM = readFileSync(join(javaDir, "pom.xml"), "utf8");
const VERSION = (POM.match(/<artifactId>archon-core<\/artifactId>\s*<version>([^<]+)<\/version>/) ?? [])[1];
if (!VERSION) {
  console.error("check-java-package: could not read the version from core/java/pom.xml");
  process.exit(1);
}

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
    ["tf", join(javaDir, "target", `archon-core-${VERSION}.jar`)],
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

  // The consumer is NOT written here. conformance/consumers/java is the same program the
  // release workflow runs against Maven Central, and it exists once so that the local check
  // and the registry check cannot drift: a consumer inlined in this file would be a second
  // opinion about what a consumer needs, and the weaker of the two would never be noticed.
  // Its assertions are load-bearing by measurement — disabling the core's profile check makes
  // the mixed-order case fail — which an inline smoke test was not.
  const consumer = join(work, "consumer");
  cpSync(join(root, "conformance", "consumers", "java"), consumer, {
    recursive: true,
    filter: (source) => basename(source) !== "target",
  });

  // Offline after install: nothing may be fetched from the network to make this work, and
  // Bouncy Castle must arrive transitively from archon-core's own POM.
  const version = `-Darchon.version=${VERSION}`;
  run("build the outside consumer", ["-q", "-B", version, "compile"], consumer, [localRepo]);
  const ran = run("run it", ["-q", "-B", version, "exec:java", "-Dexec.mainClass=example.Consumer"], consumer, [
    localRepo,
  ]);
  const line = (ran.stdout || "").split("\n").map((l) => l.trim()).find((l) => l.startsWith("consumer ok:"));
  console.log(`     ${line ?? "(no output captured)"}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
