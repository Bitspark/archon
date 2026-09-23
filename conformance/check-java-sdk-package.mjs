// Builds sdk/java's jar on the in-tree floor, then consumes it from OUTSIDE the project with a
// clean local repository — the nearest thing to what a stranger gets from Maven Central. The
// sdk's sibling of check-java-package.mjs.
//
// Passing the oracle proves the code; this proves the package. What only an install shows:
//   * the consumer declares NOTHING but archon-sdk, so archon-core and Bouncy Castle must arrive
//     transitively through the sdk's POM — asserted on the resolved classpath, then exercised;
//   * the floor that arrives is this tree's version: the sdk names it as ${project.version}, so
//     lockstep is structural, and this asserts the published POM still says so;
//   * the conformance CLI and its JSON library do NOT reach the sdk jar.
//
// The consumer is conformance/consumers/java-sdk — the same program the release workflow runs
// against Maven Central, so the local check and the registry check cannot drift.

import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const coreDir = join(root, "core", "java");
const sdkDir = join(root, "sdk", "java");
const mvn = isWindows ? "mvn.cmd" : "mvn";

// The versions come from the POMs, never from a literal here.
function versionOf(dir, artifact) {
  const pom = readFileSync(join(dir, "pom.xml"), "utf8");
  const re = new RegExp(`<artifactId>${artifact}</artifactId>\\s*<version>([^<]+)</version>`);
  return (pom.match(re) ?? [])[1];
}
const VERSION = versionOf(sdkDir, "archon-sdk");
const CORE_VERSION = versionOf(coreDir, "archon-core");
if (!VERSION || !CORE_VERSION) {
  console.error("check-java-sdk-package: could not read the versions from the POMs");
  process.exit(1);
}
if (VERSION !== CORE_VERSION) {
  console.error(`lockstep broken: sdk/java is ${VERSION}, core/java is ${CORE_VERSION}`);
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

const work = mkdtempSync(join(tmpdir(), "archon-java-sdk-pkg-"));
try {
  // A local repository of its own: the developer's ~/.m2 could satisfy the consumer with an
  // earlier build, and the check would pass without these jars being correct.
  const repo = join(work, "m2");
  const localRepo = `-Dmaven.repo.local=${repo}`;

  run("install the in-tree floor", ["-q", "-B", "install", "-DskipTests"], coreDir, [localRepo]);
  run("install the sdk jar", ["-q", "-B", "install", "-DskipTests"], sdkDir, [localRepo]);

  // The jar must not carry the conformance CLI or its JSON dependency.
  const listing = spawnSync("jar", ["tf", join(sdkDir, "target", `archon-sdk-${VERSION}.jar`)], {
    encoding: "utf8",
    shell: isWindows,
  });
  if (listing.status !== 0) {
    console.error("could not list the sdk jar");
    process.exit(1);
  }
  const entries = listing.stdout.split("\n").map((l) => l.trim());
  const leaked = entries.filter((l) => l.includes("conformance/") || l.startsWith("com/google/gson"));
  if (leaked.length > 0) {
    console.error("the sdk jar leaks dev artifacts:");
    for (const l of leaked) console.error(`  ${l}`);
    process.exit(1);
  }
  for (const cls of ["dev/bitspark/archon/sdk/Possession.class", "dev/bitspark/archon/sdk/Envelope.class"]) {
    if (!entries.includes(cls)) {
      console.error(`the sdk jar is missing ${cls}`);
      process.exit(1);
    }
  }
  console.log("jar carries the sdk and no dev artifacts … ok");

  // The POM a consumer reads names the floor at this project's own version.
  const installedPom = readFileSync(
    join(repo, "dev", "bitspark", "archon-sdk", VERSION, `archon-sdk-${VERSION}.pom`),
    "utf8",
  );
  const floorDep = installedPom.match(
    /<artifactId>archon-core<\/artifactId>\s*<version>([^<]+)<\/version>/,
  );
  if (!floorDep || (floorDep[1] !== "${project.version}" && floorDep[1] !== VERSION)) {
    console.error(`the sdk POM names archon-core as ${floorDep ? floorDep[1] : "nothing"}, want ${VERSION}`);
    process.exit(1);
  }
  console.log(`the sdk POM names the floor at ${floorDep[1]} … ok`);

  const consumer = join(work, "consumer");
  cpSync(join(root, "conformance", "consumers", "java-sdk"), consumer, {
    recursive: true,
    filter: (source) => basename(source) !== "target",
  });
  const version = `-Darchon.version=${VERSION}`;
  run("build the outside consumer", ["-q", "-B", version, "compile"], consumer, [localRepo]);

  // Transitivity, asserted rather than inferred from the build having worked.
  const cpFile = join(work, "cp.txt");
  run("resolve its classpath", ["-q", "-B", version, "dependency:build-classpath", `-Dmdep.outputFile=${cpFile}`], consumer, [localRepo]);
  const cp = readFileSync(cpFile, "utf8");
  for (const want of [`archon-sdk-${VERSION}.jar`, `archon-core-${VERSION}.jar`, "bcprov-jdk18on"]) {
    if (!cp.includes(want)) {
      console.error(`${want} did not arrive on the consumer's classpath`);
      process.exit(1);
    }
  }
  console.log("archon-core and Bouncy Castle arrived transitively … ok");

  const ran = run("run it", ["-q", "-B", version, "exec:java", "-Dexec.mainClass=example.Consumer"], consumer, [
    localRepo,
  ]);
  const line = (ran.stdout || "").split("\n").map((l) => l.trim()).find((l) => l.startsWith("consumer ok:"));
  if (!line) {
    console.error("the consumer ran but did not report success");
    process.exit(1);
  }
  console.log(`     ${line}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
