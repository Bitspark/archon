// Drives the Java core through the shared harness against vectors/identity.json.
//
// Separate from check.mjs for the same reason check-py.mjs is: that script is the tri-core
// check and needs Go, Rust and Node. Making a JDK and Maven prerequisites of it would mean a
// contributor without them can no longer run the one command the README advertises.
//
// It costs nothing, because agreement is transitive THROUGH THE ORACLE rather than pairwise.
// Every core recomputes each case from its inputs and is asserted against the same fixed
// vectors, so "the Java core agrees with the oracle" and "the Go core agrees with the oracle"
// together mean the two agree with each other.
//
// The conformance CLI lives in TEST sources and its JSON dependency is test-scoped, so neither
// reaches the published jar. That is why the classpath below includes test-classes.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const isWindows = process.platform === "win32";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const javaDir = join(root, "core", "java");
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
  console.error("conformance: no maven on PATH — the Java core cannot be checked");
  process.exit(1);
}

// `test-compile`, not `package`: the CLI is in test sources, and this check is about whether
// the code agrees with the oracle. Whether the PACKAGE is right is check-java-package.mjs.
run("build core/java", mvn, ["-q", "-B", "test-compile"], javaDir);

// Maven resolves the full classpath, including Bouncy Castle and the test-scoped JSON library,
// and writes it to a file. Reconstructing it by hand would drift the moment a dependency moves.
const cpFile = join(javaDir, "target", "classpath.txt");
run("resolve classpath", mvn, [
  "-q", "-B", "dependency:build-classpath",
  `-Dmdep.outputFile=${cpFile}`, "-Dmdep.includeScope=test",
], javaDir);

if (!existsSync(cpFile)) {
  console.error(`conformance: maven did not write ${cpFile}`);
  process.exit(1);
}
const sep = isWindows ? ";" : ":";
const classpath = [
  join(javaDir, "target", "classes"),
  join(javaDir, "target", "test-classes"),
  readFileSync(cpFile, "utf8").trim(),
].join(sep);

const harness = join(root, "conformance", "harness.mjs");
const result = spawnSync(
  process.execPath,
  [
    harness,
    join(root, "vectors", "identity.json"),
    `java -cp ${classpath} dev.bitspark.archon.core.conformance.Cli`,
  ],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
