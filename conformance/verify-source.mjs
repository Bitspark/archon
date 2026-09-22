// Read-only verification that a PUBLIC TAG builds and can be consumed by a stranger.
//
// Every other language proves this through a registry: the outside consumers in release.yml
// install a published artifact and run it. C++ has no registry — the CMake package is
// consumed from the immutable tag — so the equivalent proof is this: clone the public
// repository at the tag, anonymously, build the package it contains, INSTALL it, and build a
// consumer against the installation. Nothing from the workspace participates.
//
// That distinction is the whole point and it is easy to lose. A build that succeeds because
// the checkout happens to be sitting in the working directory proves nothing about the tag;
// it proves something about the machine. So the clone is the only source, its HEAD is
// asserted against the SHA the caller resolved, and the consumer is built from the clone's
// own conformance/consumers/cpp against the clone's own installed package.
//
// usage:
//   node conformance/verify-source.mjs resolve <tag>
//   node conformance/verify-source.mjs verify  <tag> <sha> <language>

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPOSITORY = "Bitspark/archon";
const URL = `https://github.com/${REPOSITORY}.git`;
const TAG_PATTERN = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

const [operation, tag, sha, language] = process.argv.slice(2);

if (!TAG_PATTERN.test(tag ?? "")) {
  console.error(`verify-source: '${tag}' is not a release tag of the form vX.Y.Z`);
  process.exit(1);
}

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: "utf8", stdio: "pipe", ...options });
}

function loud(label, command, args, options = {}) {
  process.stdout.write(`  ${label} … `);
  try {
    execFileSync(command, args, { stdio: "pipe", ...options });
    console.log("ok");
  } catch (error) {
    console.log("FAILED");
    const out = (error.stdout?.toString() ?? "") + (error.stderr?.toString() ?? "");
    if (out.trim()) console.error(out.trim().split("\n").slice(-40).join("\n"));
    process.exit(1);
  }
}

// Resolve the tag to the commit it points at, from the PUBLIC remote rather than from any
// local state. `^{}` dereferences an annotated tag to its commit; a lightweight tag has no
// such entry, so both forms are accepted and the dereferenced one preferred.
if (operation === "resolve") {
  const lines = run("git", ["ls-remote", URL, `refs/tags/${tag}`, `refs/tags/${tag}^{}`])
    .trim().split("\n").filter(Boolean);
  if (lines.length === 0) {
    console.error(`verify-source: ${REPOSITORY} has no tag ${tag}`);
    process.exit(1);
  }
  const dereferenced = lines.find((l) => l.endsWith("^{}"));
  const resolved = (dereferenced ?? lines[0]).split(/\s+/)[0];
  console.log(`${tag} is ${resolved} on the public remote`);
  if (process.env.GITHUB_OUTPUT) {
    const { appendFileSync } = await import("node:fs");
    appendFileSync(process.env.GITHUB_OUTPUT, `sha=${resolved}\n`);
  }
  process.exit(0);
}

if (operation !== "verify") {
  console.error("verify-source: expected 'resolve' or 'verify'");
  process.exit(1);
}

const work = mkdtempSync(join(tmpdir(), "archon-verify-source-"));
try {
  const source = join(work, "source");
  loud(`clone ${REPOSITORY} at ${tag}`, "git",
       ["clone", "--depth", "1", "--branch", tag, "--single-branch", URL, source]);

  // The tag could have been moved between resolve and verify. Assert rather than assume:
  // the whole exercise is worthless if the tree being built is not the one that was named.
  const head = run("git", ["rev-parse", "HEAD"], { cwd: source }).trim();
  if (sha && head !== sha) {
    console.error(`verify-source: ${tag} resolved to ${sha} but the clone is at ${head}`);
    process.exit(1);
  }
  console.log(`  clone HEAD is ${head}${sha ? " — matches the resolved SHA" : ""}`);

  if (language !== "cpp") {
    console.error(`verify-source: no source consumer for '${language}' yet`);
    process.exit(1);
  }

  if (!existsSync(join(source, "core", "cpp", "CMakeLists.txt"))) {
    console.error(
      `verify-source: ${tag} contains no core/cpp. The C++ core landed after v0.7.0, so it ` +
      `can only be verified against a tag cut since then — this is not a defect in the tag ` +
      `or in this script.`);
    process.exit(1);
  }

  const build = join(work, "build");
  const prefix = join(work, "prefix");
  const consumer = join(work, "consumer");

  loud("configure the tag's core/cpp", "cmake",
       ["-S", join(source, "core", "cpp"), "-B", build, "-DCMAKE_BUILD_TYPE=Release"]);
  loud("build it", "cmake", ["--build", build]);

  // The oracle, driven by the TAG's harness over the TAG's vectors: a core that agrees with
  // vectors from somewhere else has not been checked against what it shipped with.
  loud("the tag's oracle over the tag's vectors", process.execPath,
       [join(source, "conformance", "harness.mjs"), join(source, "vectors"),
        join(build, process.platform === "win32" ? "archon_conformance.exe" : "archon_conformance")]);

  loud("install the exported package", "cmake", ["--install", build, "--prefix", prefix]);

  // The consumer resolves archon::core through find_package against the INSTALL, which is
  // what caught the missing EXPORT_NAME: the build tree's alias is not exported, so a
  // consumer following the documented target could not configure.
  loud("configure a consumer against the installed package", "cmake",
       ["-S", join(source, "conformance", "consumers", "cpp"), "-B", consumer,
        "-DCMAKE_BUILD_TYPE=Release", `-DCMAKE_PREFIX_PATH=${prefix}`]);
  loud("build the consumer", "cmake", ["--build", consumer]);

  const binary = join(consumer, process.platform === "win32" ? "consumer.exe" : "consumer");
  const output = run(binary, [], { cwd: consumer }).trim();
  console.log(`  ${output}`);
  if (!output.startsWith("consumer ok:")) {
    console.error("verify-source: the consumer did not report success");
    process.exit(1);
  }
  console.log(`\n${tag} builds from public source and its package is consumable.`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
