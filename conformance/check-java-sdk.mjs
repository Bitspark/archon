// Drives the Java sdk through the shared harness against vectors/sdk.json.
//
// The sdk's sibling of check-java.mjs. Agreement is transitive through the oracle, so "the Java
// sdk agrees with sdk.json" and "the Go sdk agrees with sdk.json" together mean the two agree.
//
// archon-sdk depends on archon-core by COORDINATES, so a plain build would resolve the floor from
// whatever the local repository or Maven Central holds at that version — not from this checkout.
// So the in-tree floor is installed first, and the jar the sdk actually resolved is then asserted
// byte-identical to the one just built. An sdk change that needs a core change would otherwise
// pass here against the published floor and fail after release.
//
// The classpath reaches the CLI through the CLASSPATH environment variable rather than `-cp`:
// on Windows a `-cp` value containing `;` is split by the shell the harness spawns through.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const coreDir = join(root, "core", "java");
const sdkDir = join(root, "sdk", "java");
const mvn = isWindows ? "mvn.cmd" : "mvn";

function run(label, program, args, cwd) {
  process.stdout.write(`${label} … `);
  const r = spawnSync(program, args, { cwd, encoding: "utf8", shell: isWindows });
  if (r.error || r.status !== 0) {
    console.log("FAILED");
    if (r.stdout) console.error(r.stdout.trim());
    if (r.stderr) console.error(r.stderr.trim());
    if (r.error) console.error(r.error.message);
    process.exit(1);
  }
  console.log("ok");
  return r;
}

const probe = spawnSync(mvn, ["-v"], { encoding: "utf8", shell: isWindows });
if (probe.error || probe.status !== 0) {
  console.error("conformance: no maven on PATH — the Java sdk cannot be checked");
  process.exit(1);
}

// Read, never repeat: the version is the POM's.
const coreVersion = (readFileSync(join(coreDir, "pom.xml"), "utf8").match(
  /<artifactId>archon-core<\/artifactId>\s*<version>([^<]+)<\/version>/,
) ?? [])[1];
if (!coreVersion) {
  console.error("check-java-sdk: could not read the version from core/java/pom.xml");
  process.exit(1);
}

run("install the in-tree floor", mvn, ["-q", "-B", "install", "-DskipTests"], coreDir);
run("build sdk/java", mvn, ["-q", "-B", "test-compile"], sdkDir);

const cpFile = join(sdkDir, "target", "classpath.txt");
run("resolve classpath", mvn, [
  "-q", "-B", "dependency:build-classpath",
  `-Dmdep.outputFile=${cpFile}`, "-Dmdep.includeScope=test",
], sdkDir);
if (!existsSync(cpFile)) {
  console.error(`conformance: maven did not write ${cpFile}`);
  process.exit(1);
}
const sep = isWindows ? ";" : ":";
const resolved = readFileSync(cpFile, "utf8").trim();

// The floor the sdk was built against IS this checkout's, byte for byte.
const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const resolvedCore = resolved.split(sep).find((p) => p.includes(`archon-core-${coreVersion}.jar`));
const builtCore = join(coreDir, "target", `archon-core-${coreVersion}.jar`);
if (!resolvedCore || sha(resolvedCore) !== sha(builtCore)) {
  console.error(`the sdk resolved ${resolvedCore ?? "no archon-core"}, not the floor built at ${builtCore}`);
  process.exit(1);
}
console.log(`the floor is this checkout's … ok (${sha(builtCore).slice(0, 16)})`);

const classpath = [join(sdkDir, "target", "classes"), join(sdkDir, "target", "test-classes"), resolved].join(sep);
const harness = join(root, "conformance", "harness.mjs");
const result = spawnSync(
  process.execPath,
  [harness, join(root, "vectors", "sdk.json"), "java dev.bitspark.archon.sdk.conformance.Cli"],
  { stdio: "inherit", env: { ...process.env, CLASSPATH: classpath } },
);
process.exit(result.status ?? 1);
