// Read-only verification that a PUBLIC TAG builds and can be consumed by a stranger.
//
// Every other language proves this through a registry: the outside consumers in release.yml
// install a published artifact and run it. C++, Swift and Haskell have no registry — they
// are consumed from the immutable tag — so the equivalent proof is to consume the tag exactly
// as a stranger would, with nothing from the workspace participating:
//
//   cpp      clone the tag, build and INSTALL the CMake package, build a consumer against
//            the installation (find_package, the exported archon::core target)
//   swift    a consumer depending on archon by `.package(url:, exact:)` — SwiftPM fetches the
//            tag itself — and the revision it resolved is asserted to be the tag's commit
//   haskell  a consumer whose cabal.project names archon by source-repository-package, pinned
//            to the tag's COMMIT so Cabal cannot fetch anything else
//
// That distinction is the whole point and it is easy to lose. A build that succeeds because
// the checkout happens to be sitting in the working directory proves nothing about the tag;
// it proves something about the machine. So the tag's HEAD is asserted against the SHA the
// public remote serves, the consumer program is the TAG's own, and every language also runs
// the tag's oracle over the tag's vectors from a fresh clone.
//
// usage:
//   node conformance/verify-source.mjs resolve <tag>
//   node conformance/verify-source.mjs verify  <tag> <sha> <language>

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

  const verifiers = { cpp: verifyCpp, swift: verifySwift, haskell: verifyHaskell };
  const verify = verifiers[language];
  if (!verify) {
    console.error(`verify-source: no source consumer for '${language}' (have: ${Object.keys(verifiers).join(", ")})`);
    process.exit(1);
  }
  verify(source, work, head);
  console.log(`\n${tag} builds from public source and its ${language} package is consumable.`);
} finally {
  rmSync(work, { recursive: true, force: true });
}

/** A tag cut before a core existed cannot verify it. Say so, rather than fail as a missing file. */
function requireCore(source, path, language) {
  if (!existsSync(join(source, path))) {
    console.error(
      `verify-source: ${tag} contains no ${path}. The ${language} core landed after that tag was ` +
      `cut, so it can only be verified against a later tag — this is not a defect in the tag ` +
      `or in this script.`);
    process.exit(1);
  }
}

/** The oracle, driven by the TAG's harness over the TAG's vectors: a core that agrees with
 *  vectors from somewhere else has not been checked against what it shipped with. */
function tagOracle(source, cli) {
  loud("the tag's oracle over the tag's vectors", process.execPath,
       [join(source, "conformance", "harness.mjs"), join(source, "vectors"), cli]);
}

function expectConsumerOk(binary, cwd) {
  const output = run(binary, [], { cwd }).trim();
  console.log(`  ${output}`);
  if (!output.startsWith("consumer ok:")) {
    console.error("verify-source: the consumer did not report success");
    process.exit(1);
  }
}

function verifyCpp(source, work) {
  requireCore(source, join("core", "cpp", "CMakeLists.txt"), "C++");
  const build = join(work, "build");
  const prefix = join(work, "prefix");
  const consumer = join(work, "consumer");

  loud("configure the tag's core/cpp", "cmake",
       ["-S", join(source, "core", "cpp"), "-B", build, "-DCMAKE_BUILD_TYPE=Release"]);
  loud("build it", "cmake", ["--build", build]);
  tagOracle(source, join(build, process.platform === "win32" ? "archon_conformance.exe" : "archon_conformance"));

  loud("install the exported package", "cmake", ["--install", build, "--prefix", prefix]);

  // The consumer resolves archon::core through find_package against the INSTALL, which is
  // what caught the missing EXPORT_NAME: the build tree's alias is not exported, so a
  // consumer following the documented target could not configure.
  loud("configure a consumer against the installed package", "cmake",
       ["-S", join(source, "conformance", "consumers", "cpp"), "-B", consumer,
        "-DCMAKE_BUILD_TYPE=Release", `-DCMAKE_PREFIX_PATH=${prefix}`]);
  loud("build the consumer", "cmake", ["--build", consumer]);
  expectConsumerOk(join(consumer, process.platform === "win32" ? "consumer.exe" : "consumer"), consumer);
}

// Swift is consumed the way SwiftPM consumes anything: `.package(url:, exact:)` against the
// public repository. So the consumer is NOT pointed at the clone — SwiftPM fetches the tag
// itself, which is the only way to test that Package.swift sits where SwiftPM looks (the
// root), that SwiftPM reads a version from archon's v-prefixed tags, and that the manifest
// builds as a dependency. The clone is used only for the tag's own oracle run.
function verifySwift(source, work, head) {
  requireCore(source, join("core", "swift"), "Swift");
  const scratch = join(work, "swift-build");
  loud("build the tag's Swift core", "swift",
       ["build", "-c", "release", "--package-path", source, "--scratch-path", scratch]);
  tagOracle(source, join(scratch, "release", "ArchonConformance"));

  const consumer = join(work, "swift-consumer");
  cpSync(join(source, "conformance", "consumers", "swift"), consumer, { recursive: true });
  const env = { ...process.env, ARCHON_VERSION: tag.replace(/^v/, "") };
  delete env.ARCHON_PATH;
  loud(`resolve archon ${env.ARCHON_VERSION} by URL and build the consumer`, "swift",
       ["build", "-c", "release", "--package-path", consumer, "--scratch-path", join(consumer, ".build")],
       { env });

  // SwiftPM resolved a tag NAME to a revision. Assert it is the one the public remote named,
  // or the consumer may have been built against something other than the tag under test.
  const resolved = JSON.parse(readFileSync(join(consumer, "Package.resolved"), "utf8"));
  const pin = (resolved.pins ?? resolved.object?.pins ?? []).find(
    (p) => (p.identity ?? p.package ?? "").toLowerCase() === "archon");
  const revision = pin?.state?.revision;
  if (revision !== head) {
    console.error(`verify-source: SwiftPM resolved archon to ${revision}, but ${tag} is ${head}`);
    process.exit(1);
  }
  console.log(`  SwiftPM resolved archon ${env.ARCHON_VERSION} to ${revision} — the tag's commit`);
  expectConsumerOk(join(consumer, ".build", "release", "Consumer"), consumer);
}

/** The path of a built Cabal component. Only the LAST line of `cabal list-bin` is the path:
 *  with a source-repository-package in play, Cabal re-syncs its git checkout first and prints
 *  "HEAD is now at <sha> <subject>" on stdout. Taking the whole output as a path failed, and
 *  was caught running this against a real public commit rather than in CI. */
function listBin(component, builddir, cwd) {
  const lines = run("cabal", ["list-bin", component, `--builddir=${builddir}`], { cwd })
    .split("\n").map((l) => l.trim()).filter(Boolean);
  return lines[lines.length - 1];
}

// Haskell is consumed through Cabal's source-repository-package, pinned to the resolved COMMIT
// rather than the tag name, so Cabal cannot fetch anything but the tree under test. Cabal clones
// the repository itself; the clone here is used only for the tag's own oracle run.
function verifyHaskell(source, work, head) {
  requireCore(source, join("core", "hs"), "Haskell");
  const builddir = join(work, "hs-build");
  const pkg = join(source, "core", "hs");
  loud("build the tag's Haskell core", "cabal",
       ["build", "archon-conformance", `--builddir=${builddir}`], { cwd: pkg });
  const cli = listBin("archon-conformance", builddir, pkg);
  tagOracle(source, cli);

  const consumer = join(work, "hs-consumer");
  cpSync(join(source, "conformance", "consumers", "hs"), consumer, { recursive: true });
  writeFileSync(join(consumer, "cabal.project"), [
    "packages: .",
    "",
    "source-repository-package",
    "  type:     git",
    `  location: ${URL}`,
    `  tag:      ${head}`,
    "  subdir:   core/hs",
    "",
  ].join("\n"));
  loud(`resolve archon at ${head.slice(0, 12)} via source-repository-package and build the consumer`,
       "cabal", ["build", "consumer", `--builddir=${join(consumer, "dist")}`], { cwd: consumer });
  const binary = listBin("consumer", join(consumer, "dist"), consumer);
  expectConsumerOk(binary, consumer);
}
