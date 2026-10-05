// cli/smoke.mjs — the `archon` CLI tier's golden-output pin.
//
// Three native binaries (cli/rs, cli/go, cli/ts) build the SAME `archon` command. This
// script builds all three, runs every deterministic invocation below against each, and
// asserts two things per case: the lanes agree with each other byte-for-byte on stdout
// and exit code, AND they agree with the expected value — which is taken from the oracle
// (vectors/identity.json) or derived with OpenSSL, never from a lane. The one
// deliberately-unpinned edge is keygen without --seed (the RNG), which is only checked
// for shape.
//
//   node cli/smoke.mjs
//
// Same shell-free spawning discipline as conformance/check.mjs.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync,
         statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runQuickstart } from "./quickstart.mjs";

const isWindows = process.platform === "win32";
const exe = isWindows ? ".exe" : "";
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const bin = join(root, "bin");
mkdirSync(bin, { recursive: true });

function build(label, program, args, cwd) {
  process.stdout.write(`build ${label} … `);
  const r = spawnSync(program, args, { cwd, encoding: "utf8", shell: false });
  if (r.error || r.status !== 0) {
    console.log("FAILED");
    if (r.stdout) console.error(r.stdout.trim());
    if (r.stderr) console.error(r.stderr.trim());
    if (r.error) console.error(r.error.message);
    process.exit(1);
  }
  console.log("ok");
}

const goBin = join(bin, `archon-go${exe}`);
const rsBin = join(root, "cli", "rs", "target", "debug", `archon${exe}`);
const tsDir = join(root, "cli", "ts");
const tsEntry = join(tsDir, "dist", "src", "main.js");
const tsc = join(tsDir, "node_modules", "typescript", "bin", "tsc");
if (!existsSync(tsc)) {
  console.error(`run \`npm ci\` in ${tsDir} (and in core/ts) and try again`);
  process.exit(1);
}
build("go", isWindows ? "go.exe" : "go", ["build", "-o", goBin, "./cmd/archon"], join(root, "cli", "go"));
build("rs", isWindows ? "cargo.exe" : "cargo", ["build", "-q"], join(root, "cli", "rs"));
build("ts", process.execPath, [tsc, "-p", "tsconfig.json"], tsDir);

const lanes = [
  { name: "go", argv: [goBin] },
  { name: "rs", argv: [rsBin] },
  { name: "ts", argv: [process.execPath, tsEntry] },
];

// ---- expected values: the oracle and OpenSSL, never a lane -------------------------------
const oracle = JSON.parse(readFileSync(join(root, "vectors", "identity.json"), "utf8"));
const seed11 = oracle.pubkey_from_seed.find((c) => c.name === "seed-11");
const SEED = seed11.seed;
const PUB = seed11.pubkey;
const TEXT = oracle.key_encode.find((c) => c.pubkey === PUB).text;
// The codec cases use their own keys; take them as the oracle states them.
const pkcs8Case = oracle.keycodec.find((c) => c.kind === "encode_pkcs8" && c.result.ok);
const spkiCase = oracle.keycodec.find((c) => c.kind === "encode_spki" && c.result.ok);
const PKCS8_SEED = pkcs8Case.key, PKCS8 = pkcs8Case.result.ok;
const SPKI_PUB = spkiCase.key, SPKI = spkiCase.result.ok;
const HELLO_V1 = oracle.domain_sign.find((c) => c.name === "v1-hello").result.ok; // OpenSSL-derived
const V1_VERIFY = oracle.domain_verify.find((c) => c.name === "v1-in-v1");

const tmp = mkdtempSync(join(tmpdir(), "archon-smoke-"));
const pemPath = join(tmp, "k.pem");
const msgPath = join(tmp, "m.bin");
writeFileSync(msgPath, Buffer.from(V1_VERIFY.message, "hex"));


// `archon login` usage, pinned here so all three lanes print the same help text. The login
// cases in the table below are pre-network: each fails while deriving the audience from the
// invocation URL, which pins the refusals that matter most (archon#16 Finding 1 — the
// audience is never taken from the wire) with no server at all. The one login that DOES
// reach a server is the store-key login further down, against a server this run hosts.
const LOGIN_USAGE =
  "usage: archon login <url> [--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] " +
  "[--authority-file <file>] [--yes]\n" +
  "       archon login --audience <base> [--scope <entry>]... --valid-for <seconds> " +
  "[--key <name> | --seed <hex> | --key-file <pkcs8.pem> | --seed-file <file>] [--authority-file <file>]\n  " +
  "proves possession of your key to the service at <url> so the browser key it names may act for you. " +
  "<url> is the invocation URL <audience>/login/<id>; the audience is derived from it, never taken from the server. " +
  "--key names a key in the store and is the default (archon key default); --key-file is a PKCS#8 file. " +
  "Store password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv.\n  " +
  "with no URL, the CLI OFFERS what you typed and the page finishes: the audience is --audience or ARCHON_AUDIENCE, " +
  "never a page's word; the code and the page address go to stderr, the ledger to stdout after the service answers; " +
  "no confirmation is asked — what you typed is what you sign.\n";

// Each case: args, optional stdin, expected stdout (exact) or a `shape` regex, expected
// exit code. `after` hooks let later cases depend on files earlier ones wrote.
// The version every lane must REPORT: the command's package version, which release.yml's
// manifest guard holds to the tag (and cli/rs/Cargo.toml to it). Only the commit in the
// parentheses is left to shape. Checking the whole line by shape let the Go and TS lanes
// say "0.5.0" from 0.5.0 to 0.8.0 while Rust said the truth.
const CLI_VERSION = JSON.parse(readFileSync(join(root, "cli", "ts", "package.json"), "utf8")).version;
const cases = [
  { name: "--help", args: ["--help"], want: "usage: archon <keygen|key|login|enroll|sign|verify|version> [args]\n", code: 0 },
  { name: "unknown subcommand", args: ["nope"], want: "", code: 2 },
  { name: `version is ${CLI_VERSION}`, args: ["version"],
    shape: new RegExp(`^archon ${CLI_VERSION.replace(/\./g, "\\.")} \\(.+\\)\\n$`), code: 0 },
  { name: "key encode", args: ["key", "encode", PUB], want: `${TEXT}\n`, code: 0 },
  { name: "key decode", args: ["key", "decode", TEXT], want: `${PUB}\n`, code: 0 },
  { name: "key encode refuses 31 bytes", args: ["key", "encode", PUB.slice(0, 62)], want: "", code: 1 },
  { name: "key decode refuses bad prefix", args: ["key", "decode", `sha256:${PUB}`], want: "", code: 1 },
  { name: "key pkcs8 encode", args: ["key", "pkcs8", "encode", PKCS8_SEED], want: PKCS8, code: 0 },
  { name: "key pkcs8 decode (stdin)", args: ["key", "pkcs8", "decode"], stdin: PKCS8, want: `${PKCS8_SEED}\n`, code: 0 },
  { name: "key spki encode", args: ["key", "spki", "encode", SPKI_PUB], want: SPKI, code: 0 },
  { name: "key spki decode (stdin)", args: ["key", "spki", "decode"], stdin: SPKI, want: `${SPKI_PUB}\n`, code: 0 },
  { name: "key spki decode refuses a PKCS#8 block", args: ["key", "spki", "decode"], stdin: PKCS8, want: "", code: 1 },
  { name: "key pub --seed (text)", args: ["key", "pub", "--seed", SEED], want: `${TEXT}\n`, code: 0 },
  { name: "key pub --seed --format hex", args: ["key", "pub", "--seed", SEED, "--format", "hex"], want: `${PUB}\n`, code: 0 },
  { name: "key pub bad --format errors before reading", args: ["key", "pub", "--format", "pem"], want: "", code: 1 },
  { name: "key pub --in and --seed exclusive", args: ["key", "pub", "--in", "x", "--seed", SEED], want: "", code: 1 },
  { name: "keygen --seed --out", args: ["keygen", "--seed", SEED, "--out", pemPath], want: `${TEXT}\n`, code: 0 },
  { name: "key pub --in (the file keygen wrote)", args: ["key", "pub", "--in", pemPath, "--format", "hex"], want: `${PUB}\n`, code: 0 },
  { name: "keygen (random) shape", args: ["keygen", "--out", join(tmp, "r.pem")], shape: /^ed25519:[0-9a-f]{64}\n$/, code: 0 },
  { name: "sign --seed --domain (OpenSSL reference)", args: ["sign", "--seed", SEED, "--domain", "archon/test/v1", "--in", msgPath], want: `${HELLO_V1}\n`, code: 0 },
  { name: "sign --key-file --domain (stdin message)", args: ["sign", "--key-file", pemPath, "--domain", "archon/test/v1"], stdin: Buffer.from(V1_VERIFY.message, "hex"), want: `${HELLO_V1}\n`, code: 0 },
  { name: "sign refuses empty --domain", args: ["sign", "--seed", SEED, "--domain", "", "--in", msgPath], want: "", code: 1 },
  // archon's own protocol domains are signed only by the commands that show what they mean.
  { name: "sign --seed refuses archon's own domain", args: ["sign", "--seed", SEED, "--domain", "archon-login/1", "--in", msgPath], want: "", code: 1 },
  { name: "sign --key-file refuses any archon- domain (--json)", args: ["sign", "--key-file", pemPath, "--domain", "archon-enroll/1", "--in", msgPath, "--json"],
    want: '{"version":1,"error":"domain"}\n', code: 1 },
  { name: "sign needs a key", args: ["sign", "--in", msgPath], want: "", code: 1 },
  { name: "verify in domain (key text)", args: ["verify", "--pubkey", TEXT, "--sig", HELLO_V1, "--domain", "archon/test/v1", "--in", msgPath], want: "valid\n", code: 0 },
  { name: "verify in domain (hex key)", args: ["verify", "--pubkey", PUB, "--sig", HELLO_V1, "--domain", "archon/test/v1", "--in", msgPath], want: "valid\n", code: 0 },
  { name: "verify in other domain → invalid", args: ["verify", "--pubkey", PUB, "--sig", HELLO_V1, "--domain", "archon/test/v2", "--in", msgPath], want: "invalid\n", code: 1 },
  { name: "verify domain sig raw → invalid", args: ["verify", "--pubkey", PUB, "--sig", HELLO_V1, "--in", msgPath], want: "invalid\n", code: 1 },
  { name: "verify refuses 63-byte sig", args: ["verify", "--pubkey", PUB, "--sig", HELLO_V1.slice(0, 126), "--in", msgPath], want: "", code: 1 },
  { name: "login --help", args: ["login", "--help"], want: LOGIN_USAGE, code: 0 },
  { name: "login needs a url", args: ["login"], want: "", code: 1 },
  { name: "login refuses a flag as the url", args: ["login", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses a url with no login mount", args: ["login", "https://h.example/api/8f3c", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses the wrong mount", args: ["login", "https://h.example/signin/8f3c", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses too few segments", args: ["login", "https://h.example/login", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses a foreign scheme", args: ["login", "ftp://h.example/login/1", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses a query on the invocation url", args: ["login", "https://h.example/login/1?next=evil", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses a fragment on the invocation url", args: ["login", "https://h.example/login/1#x", "--seed", SEED], want: "", code: 1 },
  { name: "login refuses an unknown flag", args: ["login", "https://h.example/login/1", "--nope", "x"], want: "", code: 1 },
];

let failures = 0;
let checked = 0;
for (const c of cases) {
  const results = lanes.map((lane) => {
    const [program, ...pre] = lane.argv;
    const r = spawnSync(program, [...pre, ...c.args], { input: c.stdin, encoding: "utf8", shell: false });
    return { lane: lane.name, stdout: r.stdout ?? "", code: r.status, stderr: r.stderr ?? "", error: r.error };
  });
  let bad = false;
  for (const r of results) {
    if (r.error) { console.error(`FAIL ${c.name} [${r.lane}]: ${r.error.message}`); bad = true; continue; }
    const stdoutOk = c.shape ? c.shape.test(r.stdout) : r.stdout === c.want;
    if (!stdoutOk || r.code !== c.code) {
      console.error(`FAIL ${c.name} [${r.lane}]: exit ${r.code} (want ${c.code})\n       stdout ${JSON.stringify(r.stdout)}\n       want   ${JSON.stringify(c.shape ? String(c.shape) : c.want)}`);
      if (r.stderr) console.error(r.stderr.trim().split("\n").slice(0, 3).map((l) => `       stderr ${l}`).join("\n"));
      bad = true;
    }
  }
  // Lanes must also agree with EACH OTHER — a shape case is where this bites.
  const first = results[0];
  for (const r of results.slice(1)) {
    if (!c.shape && (r.stdout !== first.stdout || r.code !== first.code)) {
      console.error(`FAIL ${c.name}: ${r.lane} disagrees with ${first.lane}`);
      bad = true;
    }
    if (c.shape && r.code !== first.code) {
      console.error(`FAIL ${c.name}: ${r.lane} exit ${r.code} != ${first.lane} exit ${first.code}`);
      bad = true;
    }
  }
  if (bad) failures++;
  else { checked++; console.log(`ok   ${c.name}`); }
}
// ---- the key store: cross-binary custody (ADR 0007 §A) ----------------------------
//
// A key written by ONE binary must open in the other two. That is the whole reason the
// 134-byte format is a format rather than three implementations, and no amount of
// same-lane round-tripping demonstrates it. The destructive-operation lines are pinned
// here too (docs/keystore.md section 6): the wording is a promise about scope, so it must
// not drift between lanes or between releases.
const storeHome = join(tmp, "store");
const PASSWORD = "smoke password with a space";

function runStore(lane, args, extraEnv = {}) {
  const [program, ...pre] = lane.argv;
  const r = spawnSync(program, [...pre, ...args], {
    encoding: "utf8",
    shell: false,
    env: { ...process.env, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: PASSWORD, ...extraEnv },
  });
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.status };
}

function expect(label, got, want) {
  if (got === want) {
    checked++;
    console.log(`ok   ${label}`);
    return;
  }
  failures++;
  console.error(`FAIL ${label}\n       got  ${JSON.stringify(got)}\n       want ${JSON.stringify(want)}`);
}

// The store path appears in the `rm` lines. It is the same for every lane here, but
// scrubbing it keeps the pin about WORDING rather than about where the temp dir landed.
const scrub = (text) => text.split(join(storeHome, "keys")).join("<store>");

// 1. One lane writes the key. Every lane then has to live with those bytes.
const writer = lanes[0];
expect(
  `key store: ${writer.name} writes the shared key`,
  runStore(writer, ["key", "add", "shared", "--seed", SEED, "--unrestricted"]).stdout,
  `stored shared (${TEXT}) from --seed; the source file is untouched.\n`,
);

// 2. Every lane lists it identically — WITHOUT a password, from the header alone.
for (const lane of lanes) {
  expect(
    `key store: ${lane.name} lists the shared key`,
    runStore(lane, ["key", "list", "--json"]).stdout,
    `[{"name":"shared","principal":"${TEXT}","status":"usable","claimed_policy":{"mode":"unrestricted"}}]\n`,
  );
}

// 3. Every lane OPENS what another lane sealed, and recovers the same seed. This is the
//    cross-binary property; the PEM is then read back through `key pub` so the check is
//    against the oracle's public key rather than against a lane's own output.
for (const lane of lanes) {
  const out = join(tmp, `exported-${lane.name}.pem`);
  const wrote = runStore(lane, ["key", "export", "shared", "--reveal", "--out", out]);
  expect(
    `key store: ${lane.name} opens the key ${writer.name} sealed`,
    wrote.stdout,
    `wrote the seed of shared to ${out}; the store's copy remains.\n`,
  );
  const back = runStore(lane, ["key", "pub", "--in", out, "--format", "hex"]);
  expect(`key store: ${lane.name} recovered the right seed`, back.stdout, `${PUB}\n`);
}

// 3b. THE STORE'S CONSUMER: every lane LOGS IN from the key go sealed — ADR 0007 §A's
//     "add-with-one, list-and-login-with-another", the half that was not yet true. This is
//     the one login in the smoke run that reaches a server, and the server is this run's
//     own: server/ts's Handler mounted over node:http, so it is a real cli↔server round trip
//     through both tiers rather than a fourth copy of the route. The smoke plays the BROWSER
//     (begin, then collect), each lane plays the CLI, and what the browser collects is
//     checked against the ORACLE's key from vectors/identity.json — never a lane's output.
//
//     The lanes are spawned ASYNCHRONOUSLY here and nowhere else. spawnSync blocks the event
//     loop, and an in-process server cannot answer while it is blocked — every lane would sit
//     in its 30-second timeout. Everything else in this file stays spawnSync on purpose.
{
  for (const [pkg, ...p] of [["server/ts", "server", "ts"], ["sdk/ts", "sdk", "ts"], ["core/ts", "core", "ts"]]) {
    if (!existsSync(join(root, ...p, "dist", "src", "index.js"))) {
      console.error(`run \`npm ci && npm run build\` in ${pkg} and try again`);
      process.exit(1);
    }
  }
  // By file:// URL, not by bare specifier: nothing under cli/ resolves @bitspark/* from
  // here, and each package's own imports resolve from its own node_modules. The URL form
  // is what makes this correct on Windows, where a bare path is not a valid import.
  const mod = (...p) => import(pathToFileURL(join(root, ...p, "dist", "src", "index.js")).href);
  const { Handler, COLLECT_HEADER } = await mod("server", "ts");
  const { proveCollect, verifyLogin } = await mod("sdk", "ts");
  const { encodeKey, getPublicKey } = await mod("core", "ts");

  const hex = (b) => Buffer.from(b).toString("hex");
  const unhex = (h) => new Uint8Array(Buffer.from(h, "hex"));

  // The browser's key K: the smoke's own, any key but the login key. Its public half is what
  // the statement names, and its seed is what the collect proof is made with.
  const kSeed = new Uint8Array(32).map((_, i) => 0x40 + i);
  const K = getPublicKey(kSeed);
  const K_TEXT = encodeKey(K);
  const SCOPE = ["read:projects", "read:campaigns"];
  const VALID_FOR = 28800;

  // node:http → the Web platform's Request the Handler takes, and back: the same bridge as
  // server/ts/examples/serve.ts, inlined because an example is a script, not an import.
  let handler;
  let origin;
  let requests = 0;
  const server = createServer((incoming, outgoing) => {
    void (async () => {
      requests++;
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value === undefined) continue;
        for (const one of Array.isArray(value) ? value : [value]) headers.append(name, one);
      }
      const init = { method: incoming.method ?? "GET", headers };
      if (body.byteLength > 0) init.body = body;
      const response = await handler.handle(new Request(new URL(incoming.url ?? "/", origin), init));
      const out = {};
      response.headers.forEach((v, n) => { out[n] = v; });
      outgoing.writeHead(response.status, out);
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    })().catch((e) => {
      outgoing.writeHead(500);
      outgoing.end(String(e));
    });
  });
  // 127.0.0.1 by number, bound and dialled: `localhost` resolves ::1-first on modern Node
  // and one lane's client would take the first address. Loopback raises no firewall prompt.
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const audience = `${origin}/api`;
  // `page` so the offers form's origin mark is exercised (3c), `intervalSeconds: 1` so each
  // lane's first-poll delay there is a second rather than the default five.
  handler = new Handler({ audience, mount: "/api/login", intervalSeconds: 1, page: `${origin}/login` });

  // The lanes, spawned without blocking the loop, with runStore's env. `onStderr` sees the
  // stderr text so far on every chunk: the offers form prints its code there, and the smoke
  // has to play the page WHILE the lane waits — which is the whole reason these are async.
  const runStoreAsync = (lane, args, extraEnv = {}, onStderr = undefined) => new Promise((resolve) => {
    const [program, ...pre] = lane.argv;
    const child = spawn(program, [...pre, ...args], {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: PASSWORD, ...extraEnv },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (d) => { stderr += d; onStderr?.(stderr); });
    child.on("close", (code) => resolve({ stdout, stderr, code }));
  });
  const exitOf = (r) => (r.code === 0 ? "0" : `${r.code}: ${r.stderr.trim()}`);

  // The `until` wall-clock end is each lane's own second; every other byte is pinned.
  const scrubTime = (s) => s.replace(/until about \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/, "until about <t>");
  const WANT =
    `${audience} asks you to let browser key ${K_TEXT} act as you:\n` +
    SCOPE.map((s) => `  ${s}\n`).join("") +
    "for 8h0m0s, until about <t>\n" +
    "signing with the store key shared\n" +
    `signed as ${TEXT}. the browser is in.\n`;

  for (const lane of lanes) {
    // The browser begins a login...
    const begun = await fetch(`${audience}/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ browser: K_TEXT, scope: SCOPE, valid_for: VALID_FOR }),
    });
    expect(`login: ${lane.name} — the browser's begin is accepted`, String(begun.status), "201");
    const opened = await begun.json();
    const req = { id: unhex(opened.id), nonce: unhex(opened.nonce), browser: K, scope: SCOPE, validFor: VALID_FOR };

    // ...the lane logs in from the key go sealed, and a person would have seen this...
    const r = await runStoreAsync(lane, ["login", `${audience}/login/${opened.id}`, "--key", "shared", "--yes"]);
    expect(`login: ${lane.name} logs in from the key ${writer.name} sealed`, exitOf(r), "0");
    expect(`login: ${lane.name} shows the statement and the outcome`, scrubTime(r.stdout), WANT);

    // ...and the browser collects the answer and checks it against the ORACLE.
    const got = await fetch(`${audience}/login/${opened.id}/answer`, {
      headers: { [COLLECT_HEADER]: hex(proveCollect(kSeed, audience, req)) },
    });
    expect(`login: ${lane.name} — the browser collects the answer`, String(got.status), "200");
    const answer = await got.json();
    expect(`login: ${lane.name} signed as the oracle's key`, answer.principal, TEXT);
    expect(`login: ${lane.name}'s proof verifies for the oracle's key`,
      String(verifyLogin(unhex(PUB), audience, req, unhex(answer.possession))), "true");
  }

  // A name not in the store is refused BEFORE any request: the server sees nothing.
  const before = requests;
  const refused = await runStoreAsync(lanes[lanes.length - 1], ["login", `${audience}/login/00`, "--key", "nobody", "--yes"]);
  expect("login: --key nobody is refused with nothing on stdout", `${refused.code} ${refused.stdout}`, "1 ");
  expect("login: --key nobody carries the store's own wording",
    String(refused.stderr.includes(`no key named "nobody" in archon's store`)), "true");
  expect("login: --key nobody made no request", String(requests - before), "0");

  // A path is the person's own argument, but it is shown inside the statement they approve, so
  // a display-unsafe code point in a --key-file path is escaped as \uxxxx in every lane, like any
  // other shown text (docs/login.md §5). The file is never read: stdin is closed, so the question
  // is answered no, and nothing is signed. Built from code points so this file holds none.
  {
    const RLO = String.fromCodePoint(0x202e);
    const BACKSLASH = String.fromCharCode(92);
    const unsafePath = join(tmp, `k${RLO}ey.pem`);
    writeFileSync(unsafePath, "never read: the question is answered no\n");
    const escaped = join(tmp, `k${BACKSLASH}u202eey.pem`);
    for (const lane of lanes) {
      const begun = await fetch(`${audience}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ browser: K_TEXT, scope: SCOPE, valid_for: VALID_FOR }),
      });
      const opened = await begun.json();
      const r = await runStoreAsync(lane, ["login", `${audience}/login/${opened.id}`, "--key-file", unsafePath]);
      expect(`login: ${lane.name} escapes a display-unsafe code point in a --key-file path`,
        r.stdout.includes(`signing with the key file ${escaped}\n`) && !r.stdout.includes(RLO) ? "escaped" : r.stdout, "escaped");
      expect(`login: ${lane.name} signs nothing when the question is not answered`,
        r.stdout.includes("refused. nothing was signed.") ? "refused" : `${r.code} ${r.stdout} ${r.stderr}`, "refused");
    }
  }

  // 3c. THE OFFERS FORM (docs/login.md §4.1): every lane STARTS a login — no URL, its own
  //     audience, its own code — and the smoke plays the page from the code the lane prints on
  //     STDERR, the channel §4.1 puts it on: it reads the offer, begins on it with K, and
  //     collects the answer once the lane has answered. The ledger the lane prints on stdout is
  //     pinned byte for byte, the code is asserted NOT to be on stdout, the page line IS on
  //     stderr marked on-origin, and the answer is verified against the ORACLE's key as above.
  const OFFER_SCOPE = ["read:projects", "read:campaigns"];
  const LEDGER =
    `you offered ${audience} to let browser key ${K_TEXT} act as you:\n` +
    OFFER_SCOPE.map((s) => `  ${s}\n`).join("") +
    "for 8h0m0s, until about <t>\n" +
    "signed with the store key shared\n" +
    "the service accepted the login. the browser is in.\n";
  const CODE_LINE = /^code: ([0-9a-f]{32})$/m;
  // The page's part: read the offer, then begin on it with K and exactly what was offered.
  const playThePage = async (label, code, scope, validFor) => {
    const read = await fetch(`${audience}/login/offers/${code}`);
    expect(`offer: ${label} — the page reads the open offer`, `${read.status} ${(await read.json()).request}`, "200 null");
    const begun = await fetch(`${audience}/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ browser: K_TEXT, scope, valid_for: validFor, offer: code }),
    });
    expect(`offer: ${label} — the page begins on the offer`, String(begun.status), "201");
    return begun.json();
  };
  // Runs the offers form for one lane and plays the page the moment the code appears.
  const offer = async (lane, args, extraEnv, scope, validFor) => {
    let code;
    let page;
    const r = await runStoreAsync(lane, args, extraEnv, (stderrSoFar) => {
      const m = CODE_LINE.exec(stderrSoFar);
      if (m && code === undefined) {
        code = m[1];
        page = playThePage(lane.name, code, scope, validFor);
      }
    });
    return { r, code, opened: page === undefined ? undefined : await page };
  };

  for (const lane of lanes) {
    const { r, code, opened } = await offer(lane,
      ["login", "--audience", audience, "--scope", OFFER_SCOPE[0], "--scope", OFFER_SCOPE[1],
       "--valid-for", String(VALID_FOR), "--key", "shared"],
      {}, OFFER_SCOPE, VALID_FOR);
    expect(`offer: ${lane.name} offers a login and answers the request that took it`, exitOf(r), "0");
    expect(`offer: ${lane.name} prints the ledger on stdout`, scrubTime(r.stdout), LEDGER);
    expect(`offer: ${lane.name} keeps the code off stdout`, String(code !== undefined && !r.stdout.includes(code)), "true");
    expect(`offer: ${lane.name} marks the page on the service's own origin`,
      String(r.stderr.includes(`page: ${origin}/login#${code} (on the service's own origin)\n`)), "true");

    // ...and the page collects the answer and checks it against the ORACLE.
    const req = { id: unhex(opened.id), nonce: unhex(opened.nonce), browser: K, scope: OFFER_SCOPE, validFor: VALID_FOR };
    const got = await fetch(`${audience}/login/${opened.id}/answer`, {
      headers: { [COLLECT_HEADER]: hex(proveCollect(kSeed, audience, req)) },
    });
    expect(`offer: ${lane.name} — the page collects the answer`, String(got.status), "200");
    const answer = await got.json();
    expect(`offer: ${lane.name} signed as the oracle's key`, answer.principal, TEXT);
    expect(`offer: ${lane.name}'s proof verifies for the oracle's key`,
      String(verifyLogin(unhex(PUB), audience, req, unhex(answer.possession))), "true");
  }

  // A non-canonical audience is refused BEFORE any request: the server sees nothing.
  {
    const before = requests;
    const refused = await runStoreAsync(lanes[lanes.length - 1],
      ["login", "--audience", `${audience}/`, "--scope", "read:projects", "--valid-for", "60", "--key", "shared"]);
    expect("offer: a non-canonical --audience is refused with nothing on stdout", `${refused.code} ${refused.stdout}`, "1 ");
    expect("offer: a non-canonical --audience made no request", String(requests - before), "0");
  }

  // ARCHON_AUDIENCE is the configured default: the same login with no --audience at all.
  {
    const lane = lanes[0];
    const { r, opened } = await offer(lane,
      ["login", "--scope", "read:projects", "--valid-for", "60", "--key", "shared"],
      { ARCHON_AUDIENCE: audience }, ["read:projects"], 60);
    expect(`offer: ${lane.name} takes its audience from ARCHON_AUDIENCE`, exitOf(r), "0");
    expect(`offer: ${lane.name}'s ledger names the configured audience`,
      String(r.stdout.startsWith(`you offered ${audience} to let browser key ${K_TEXT} act as you:\n  read:projects\n`)), "true");
    expect(`offer: ${lane.name}'s request was taken`, String(opened !== undefined), "true");
  }

  // fetch keeps connections alive; close them or server.close waits on them forever.
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}

// 3c. `sign --key` (ADR 0009 §5): every lane signs with the key go sealed, and the signature
//     is the ORACLE's (OpenSSL-derived), never a lane's. The refusals are pinned by their
//     machine-mode category, which is the part a calling tool branches on; the sentence on
//     stderr is free to change. Two of them run with NO password source and NO terminal
//     (detached: a new session on POSIX, no console on Windows): one proves the password is
//     never sought anywhere else, the other that an unexpected key is refused BEFORE the
//     password — a refusal that came after the prompt would read `password`.
{
  const OTHER_TEXT = oracle.key_encode.find((c) => c.pubkey !== PUB).text;
  const multibyte = oracle.domain_sign.find((c) => c.name === "domain-multibyte");
  const multibyteMsg = join(tmp, "multibyte.bin");
  writeFileSync(multibyteMsg, Buffer.from(multibyte.message, "hex"));
  const noPassword = (({ ARCHON_KEY_PASSWORD, ...rest }) => ({ ...rest, ARCHON_HOME: storeHome }))(process.env);
  const runSign = (lane, args, { input, env, detached } = {}) => {
    const [program, ...pre] = lane.argv;
    const r = spawnSync(program, [...pre, ...args], {
      encoding: "utf8",
      shell: false,
      input,
      detached: detached === true,
      env: env ?? { ...process.env, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: PASSWORD },
    });
    return `${r.stdout ?? ""}[${r.status}]`;
  };
  const record = (domainMember, sig) =>
    `{"version":1,"principal":"${TEXT}","scheme":"ed25519ph-context","domain":${domainMember},"signature":"${sig}"}\n`;
  const refused = (category) => `{"version":1,"error":"${category}"}\n[1]`;
  const storeSign = ["sign", "--key", "shared", "--domain", "archon/test/v1", "--expect", TEXT];
  const cases = [
    ["signs with the store key (OpenSSL reference)", [...storeSign, "--in", msgPath], {}, `${HELLO_V1}\n[0]`],
    ["reads the message from stdin", storeSign, { input: Buffer.from(V1_VERIFY.message, "hex") }, `${HELLO_V1}\n[0]`],
    ["--json prints the versioned record", [...storeSign, "--in", msgPath, "--json"], {},
      `${record('"archon/test/v1"', HELLO_V1)}[0]`],
    ["--json writes a multibyte domain as itself (OpenSSL reference)",
      ["sign", "--key", "shared", "--domain", multibyte.domain, "--expect", TEXT, "--in", multibyteMsg, "--json"], {},
      `${record(`"${multibyte.domain}"`, multibyte.result.ok)}[0]`],
    ["refuses --key without --domain: the store does not sign raw",
      ["sign", "--key", "shared", "--expect", TEXT, "--in", msgPath, "--json"], {}, refused("usage")],
    ["refuses --key without --expect",
      ["sign", "--key", "shared", "--domain", "archon/test/v1", "--in", msgPath, "--json"], {}, refused("usage")],
    ["refuses a domain the core refuses",
      ["sign", "--key", "shared", "--domain", "", "--expect", TEXT, "--in", msgPath, "--json"], {}, refused("domain")],
    ["refuses a key the store does not have",
      ["sign", "--key", "nobody", "--domain", "archon/test/v1", "--expect", TEXT, "--in", msgPath, "--json"], {}, refused("no-key")],
    ["refuses a wrong password", [...storeSign, "--in", msgPath, "--json"],
      { env: { ...process.env, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: "not the password" } }, refused("unlock-failed")],
    ["refuses an unexpected key before asking for a password",
      ["sign", "--key", "shared", "--domain", "archon/test/v1", "--expect", OTHER_TEXT, "--in", msgPath, "--json"],
      { env: noPassword, detached: true }, refused("key-mismatch")],
    ["with no password given, finds no terminal and signs nothing", [...storeSign, "--in", msgPath, "--json"],
      { env: noPassword, detached: true }, refused("password")],
    ["refuses archon's own domain, with the password at hand",
      ["sign", "--key", "shared", "--domain", "archon-request/1", "--expect", TEXT, "--in", msgPath, "--json"], {}, refused("domain")],
    // A key the store lacks and no password: a refusal from the header read would be `no-key`,
    // from the password `password`, so `domain` proves the reservation is checked first.
    ["refuses archon's own domain before the header or a password",
      ["sign", "--key", "nobody", "--domain", "archon-login/1", "--expect", TEXT, "--in", msgPath, "--json"],
      { env: noPassword, detached: true }, refused("domain")],
  ];
  for (const lane of lanes) {
    for (const [label, args, opts, want] of cases) {
      expect(`sign --key: ${lane.name} ${label}`, runSign(lane, args, opts), want);
    }
  }

  // The machine mode's escaping, which no oracle vector exercises: `"` and `\` in a domain.
  // The domain member is pinned as written here by hand; the signature by its shape, and by
  // the three lanes agreeing on it (its value is the OpenSSL-pinned cases' business above).
  const odd = 'archon/"quoted"\\path';
  const oddPrefix = `{"version":1,"principal":"${TEXT}","scheme":"ed25519ph-context","domain":"archon/\\"quoted\\"\\\\path","signature":"`;
  const oddOut = lanes.map((lane) => runSign(lane, ["sign", "--seed", SEED, "--domain", odd, "--in", msgPath, "--json"]));
  for (const [i, lane] of lanes.entries()) {
    const out = oddOut[i];
    const shaped = out.startsWith(oddPrefix) && /^[0-9a-f]{128}"\}\n\[0\]$/u.test(out.slice(oddPrefix.length));
    expect(`sign --json: ${lane.name} escapes a quote and a backslash in the domain`,
      shaped && out === oddOut[0] ? "escaped, and the lanes agree" : out, "escaped, and the lanes agree");
  }

  // Display-unsafe code points (docs/login.md §5) are written as \uxxxx, never as themselves:
  // a right-to-left override, a zero-width space and a tag character (astral, so a UTF-16
  // surrogate pair). The value is unchanged; what reaches a terminal is not the raw character.
  // Every lane must write the same bytes.
  const unsafe = "x/\u202e/\u200b/\u{e0041}/v1";
  const unsafePrefix = `{"version":1,"principal":"${TEXT}","scheme":"ed25519ph-context","domain":"x/\\u202e/\\u200b/\\udb40\\udc41/v1","signature":"`;
  const unsafeOut = lanes.map((lane) => runSign(lane, ["sign", "--seed", SEED, "--domain", unsafe, "--in", msgPath, "--json"]));
  for (const [i, lane] of lanes.entries()) {
    const out = unsafeOut[i];
    const shaped = out.startsWith(unsafePrefix) && /^[0-9a-f]{128}"\}\n\[0\]$/u.test(out.slice(unsafePrefix.length));
    expect(`sign --json: ${lane.name} escapes display-unsafe code points in the domain`,
      shaped && out === unsafeOut[0] ? "escaped, and the lanes agree" : out, "escaped, and the lanes agree");
  }

  // The reserved prefix is byte-exact, as a domain is (ADR 0008 §2): a different case is an
  // ordinary domain, and every lane signs in it, with the store key, identically.
  const folded = lanes.map((lane) => runSign(lane,
    ["sign", "--key", "shared", "--domain", "Archon-login/1", "--expect", TEXT, "--in", msgPath]));
  for (const [i, lane] of lanes.entries()) {
    const out = folded[i];
    expect(`sign --key: ${lane.name} signs in Archon-login/1 (the reservation is byte-exact)`,
      /^[0-9a-f]{128}\n\[0\]$/u.test(out) && out === folded[0] ? "signed, and the lanes agree" : out,
      "signed, and the lanes agree");
  }

  // THE CONTROLLING TERMINAL, on Linux where a pseudo-terminal can be driven unattended: the
  // message arrives on stdin (a file), the password is typed into the terminal, and the person
  // is shown what they are signing — length and SHA-256, computed here, not by a lane — before
  // the prompt. A lane that read the password from stdin would take the message for it.
  // Windows has no unattended equivalent (a pseudo-console needs a host to drive it), so there
  // the no-terminal refusal above is what is pinned.
  if (process.platform === "linux") {
    const PTY = [
      "import os, pty, sys",
      "msg, out, password, argv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]",
      "pid, fd = pty.fork()",
      "if pid == 0:",
      "    os.dup2(os.open(msg, os.O_RDONLY), 0)",
      "    os.dup2(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 1)",
      "    os.execv(argv[0], argv)",
      "seen, sent = b'', False",
      "while True:",
      "    try:",
      "        chunk = os.read(fd, 1024)",
      "    except OSError:",
      "        break",
      "    if not chunk:",
      "        break",
      "    seen += chunk",
      "    if not sent and seen.endswith(b'password: '):",
      "        os.write(fd, password.encode() + bytes([13]))",
      "        sent = True",
      "_, status = os.waitpid(pid, 0)",
      // One stream, binary, so the exit code cannot be overtaken by the transcript: text
      // written to sys.stdout sits in its buffer while sys.stdout.buffer writes go straight by.
      "sys.stdout.buffer.write(str(os.waitstatus_to_exitcode(status)).encode() + bytes([10]) + seen)",
    ].join("\n");
    const message = readFileSync(msgPath);
    const shown = `signing ${message.length} bytes (sha256 ${createHash("sha256").update(message).digest("hex")}) ` +
      `in domain "archon/test/v1" with shared (${TEXT})`;
    for (const lane of lanes) {
      const out = join(tmp, `pty-${lane.name}.out`);
      const r = spawnSync("python3", ["-c", PTY, msgPath, out, PASSWORD, ...lane.argv, ...storeSign], {
        encoding: "utf8",
        shell: false,
        env: noPassword,
        timeout: 120_000,
      });
      if (r.error) {
        failures++;
        console.error(`FAIL sign --key: ${lane.name} terminal prompt: python3 did not run: ${r.error.message}`);
        continue;
      }
      const [code, ...transcript] = (r.stdout ?? "").split("\n");
      const signed = existsSync(out) ? readFileSync(out, "utf8") : "";
      expect(`sign --key: ${lane.name} takes the password from the terminal, the message from stdin`,
        `${signed}[${code}]`, `${HELLO_V1}\n[0]`);
      expect(`sign --key: ${lane.name} shows what it signs before the password`,
        transcript.join("\n").includes(shown) ? "shown" : transcript.join("\n"), "shown");
    }
  }
}

// 4. Refusals every lane owes: no --reveal, a wrong password, a duplicate name, and the
//    name rules (a trailing dot and a reserved device name with an extension).
for (const lane of lanes) {
  expect(`key store: ${lane.name} refuses export without --reveal`,
    String(runStore(lane, ["key", "export", "shared", "--out", join(tmp, "no.pem")]).code), "1");
  expect(`key store: ${lane.name} refuses a wrong password`,
    String(runStore(lane, ["key", "export", "shared", "--reveal", "--out", join(tmp, "no.pem")],
      { ARCHON_KEY_PASSWORD: "not the password" }).code), "1");
  expect(`key store: ${lane.name} refuses a duplicate name`,
    String(runStore(lane, ["key", "add", "shared", "--seed", SEED, "--unrestricted"]).code), "1");
  expect(`key store: ${lane.name} refuses a trailing dot`,
    String(runStore(lane, ["key", "add", "alice.", "--seed", SEED, "--unrestricted"]).code), "1");
  expect(`key store: ${lane.name} refuses CON.key`,
    String(runStore(lane, ["key", "add", "CON.key", "--seed", SEED, "--unrestricted"]).code), "1");
}

// 5. A file that is not a key is never LISTED as one (that is what the magic buys), is
//    refused by rm, and --force says what it could not read.
writeFileSync(join(storeHome, "keys", "stray"), "this is not a key file");
for (const lane of lanes) {
  expect(`key store: ${lane.name} does not list a stray file`,
    runStore(lane, ["key", "list", "--json"]).stdout,
    `[{"name":"shared","principal":"${TEXT}","status":"usable","claimed_policy":{"mode":"unrestricted"}}]\n`);
  expect(`key store: ${lane.name} refuses to rm a stray file`,
    String(runStore(lane, ["key", "rm", "stray"]).code), "1");
}
// 5b. The Argon2id bounds (docs/keystore.md §2) are checked when the header is PARSED, so
//     `list`, which reads nothing else, shows exactly the in-bounds entries in every lane,
//     and names on stderr each one it skipped. The files are the shared key's with only m, t
//     or p rewritten: their tags no longer verify, which `list` never looks at. An edge at
//     its bound is listed; one step past it is not. m = 2 GiB is checked here rather than by
//     a vector, because deriving at it is too slow for a conformance run.
{
  const shared = readFileSync(join(storeHome, "keys", "shared"));
  const withParams = (m, t, p) => {
    const f = Buffer.from(shared);
    f.writeUInt32BE(m, 5);
    f.writeUInt32BE(t, 9);
    f[13] = p;
    return f;
  };
  const edges = {
    "edge-m-floor": withParams(8, 1, 1),
    "edge-m-under": withParams(7, 1, 1),
    "edge-m-max": withParams(2 * 1024 * 1024, 1, 1),
    "edge-m-over": withParams(2 * 1024 * 1024 + 1, 1, 1),
    "edge-t-max": withParams(1024, 10, 1),
    "edge-t-over": withParams(1024, 11, 1),
    "edge-p4-under": withParams(31, 1, 4),
  };
  for (const [name, bytes] of Object.entries(edges)) writeFileSync(join(storeHome, "keys", name), bytes);
  const listed = ["edge-m-floor", "edge-m-max", "edge-t-max", "shared"]
    .map((name) => `{"name":"${name}","principal":"${TEXT}","status":"usable","claimed_policy":{"mode":"unrestricted"}}`).join(",");
  const skipped = ["edge-m-over", "edge-m-under", "edge-p4-under", "edge-t-over", "stray"];
  for (const lane of lanes) {
    const r = runStore(lane, ["key", "list", "--json"]);
    expect(`key store: ${lane.name} lists exactly the in-bounds entries`, r.stdout, `[${listed}]\n`);
    const named = r.stderr.split(/\r?\n/u)
      .map((line) => /^archon key list: skipped (\S+): /u.exec(line)?.[1]).filter(Boolean);
    expect(`key store: ${lane.name} names each skipped entry on stderr`, named.join(" "), skipped.join(" "));
  }
  for (const name of Object.keys(edges)) rmSync(join(storeHome, "keys", name));
}
expect("key store: rm --force says what it could not read",
  scrub(runStore(lanes[lanes.length - 1], ["key", "rm", "stray", "--force"]).stdout),
  "removed stray (unreadable header: bad magic: not an archon key file) from archon's store at " +
    `${join("<store>", "stray")}; any copy of this key outside it is untouched.\n`);

// 5c. Version 2's context policy (docs/keystore.md §8), in every lane, on files one lane wrote.
{
  const noPassword = (({ ARCHON_KEY_PASSWORD, ...rest }) => ({ ...rest, ARCHON_HOME: storeHome }))(process.env);
  const run = (lane, args, { env, detached } = {}) => {
    const [program, ...pre] = lane.argv;
    const r = spawnSync(program, [...pre, ...args], {
      encoding: "utf8",
      shell: false,
      detached: detached === true,
      env: env ?? { ...process.env, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: PASSWORD },
    });
    return { out: `${r.stdout ?? ""}[${r.status}]`, stderr: r.stderr ?? "" };
  };
  const refused = (category) => `{"version":1,"error":"${category}"}\n[1]`;
  const keyFile = (name) => join(storeHome, "keys", name);

  // There is no default policy: a new key names one, or nothing is written.
  for (const lane of lanes) {
    expect(`key policy: ${lane.name} key add refuses a key with no policy`,
      run(lane, ["key", "add", "nopolicy", "--seed", SEED]).out.endsWith("[1]") && !existsSync(keyFile("nopolicy"))
        ? "refused" : "written", "refused");
    expect(`key policy: ${lane.name} keygen --store refuses a key with no policy`,
      run(lane, ["keygen", "--seed", SEED, "--store", "nopolicy"]).out.endsWith("[1]") && !existsSync(keyFile("nopolicy"))
        ? "refused" : "written", "refused");
  }

  // One lane seals two allowlisted keys; the contexts are given out of order and listed sorted.
  const writer = lanes[0];
  run(writer, ["key", "add", "limited", "--seed", SEED, "--allow", "archon/test/v1"]);
  run(writer, ["key", "add", "twoctx", "--seed", SEED, "--allow", "archon/test/v2", "--allow", "archon/test/v1"]);
  // A version-1 file (vectors/keystore.json), a version-3 one, and a malformed version-2 one.
  const oracle = JSON.parse(readFileSync(join(root, "vectors", "keystore.json"), "utf8"));
  const v1 = Buffer.from(oracle.keystore_open.find((c) => c.name === "v1-basic").file, "hex");
  const v1Password = oracle.keystore_open.find((c) => c.name === "v1-basic").password;
  const V1_TEXT = "ed25519:" + v1.subarray(30, 62).toString("hex");
  writeFileSync(keyFile("legacy"), v1);
  writeFileSync(keyFile("future"), Buffer.concat([v1.subarray(0, 4), Buffer.from([3]), v1.subarray(5)]));
  const v2 = readFileSync(keyFile("limited"));
  writeFileSync(keyFile("broken"), Buffer.concat([v2.subarray(0, 62), Buffer.from([2]), v2.subarray(63)]));

  const row = (name, principal, status, policy) =>
    `{"name":"${name}","principal":"${principal}","status":"${status}","claimed_policy":${policy}}`;
  const listed = "[" + [
    row("legacy", V1_TEXT, "migration-required", "null"),
    row("limited", TEXT, "usable", '{"mode":"allowlist","contexts":["archon/test/v1"]}'),
    row("shared", TEXT, "usable", '{"mode":"unrestricted"}'),
    row("twoctx", TEXT, "usable", '{"mode":"allowlist","contexts":["archon/test/v1","archon/test/v2"]}'),
  ].join(",") + "]\n[0]";
  const signIn = (key, domain, expectText = TEXT) =>
    ["sign", "--key", key, "--domain", domain, "--expect", expectText, "--in", msgPath, "--json"];
  for (const lane of lanes) {
    const list = run(lane, ["key", "list", "--json"]);
    expect(`key policy: ${lane.name} lists every readable entry, with its status and claimed policy`, list.out, listed);
    expect(`key policy: ${lane.name} names the unreadable entries on stderr`,
      ["broken", "future"].every((n) => list.stderr.includes(`archon key list: skipped ${n}: `)) ? "named" : list.stderr, "named");
    expect(`key policy: ${lane.name} signs inside the list (OpenSSL reference)`,
      run(lane, signIn("limited", "archon/test/v1")).out,
      `{"version":1,"principal":"${TEXT}","scheme":"ed25519ph-context","domain":"archon/test/v1","signature":"${HELLO_V1}"}\n[0]`);
    // With no password and no terminal: a refusal after the header would read `password`.
    expect(`key policy: ${lane.name} refuses outside the list, before any password`,
      run(lane, signIn("limited", "archon/test/v2"), { env: noPassword, detached: true }).out, refused("policy"));
    expect(`key policy: ${lane.name} refuses a version-1 entry as migration-required`,
      run(lane, signIn("legacy", "archon/test/v1", V1_TEXT), { env: noPassword, detached: true }).out, refused("migration-required"));
    expect(`key policy: ${lane.name} refuses an unknown version as unsupported`,
      run(lane, signIn("future", "archon/test/v1"), { env: noPassword, detached: true }).out, refused("unsupported"));
    expect(`key policy: ${lane.name} refuses a broken policy as malformed`,
      run(lane, signIn("broken", "archon/test/v1"), { env: noPassword, detached: true }).out, refused("malformed"));
    const exported = join(tmp, `limited-${lane.name}.pem`);
    expect(`key policy: ${lane.name} refuses to export an allowlisted entry`,
      run(lane, ["key", "export", "limited", "--reveal", "--out", exported]).out.endsWith("[1]") && !existsSync(exported)
        ? "refused" : "exported", "refused");
    expect(`key policy: ${lane.name} refuses to make a version-1 entry the default`,
      run(lane, ["key", "default", "legacy"]).out, "[1]");
    const login = run(lane, ["login", "https://h.example/login/1", "--key", "limited", "--yes"]);
    expect(`key policy: ${lane.name} refuses a login the policy does not list, before any request`,
      login.out === "[1]" && login.stderr.includes("may not sign in archon-login/1") ? "refused" : login.stderr, "refused");
    expect(`key policy: ${lane.name} shows the claimed policy`,
      run(lane, ["key", "policy", "twoctx"]).out,
      `twoctx (${TEXT}): allow "archon/test/v1", "archon/test/v2" (claimed by the header; proven only at unlock)\n[0]`);
    const before = readFileSync(keyFile("limited"));
    expect(`key policy: ${lane.name} refuses to change a policy with no person at a terminal`,
      run(lane, ["key", "policy", "limited", "--unrestricted"], { env: noPassword, detached: true }).out.endsWith("[1]") &&
        readFileSync(keyFile("limited")).equals(before) ? "refused, file untouched" : "changed",
      "refused, file untouched");
  }

  // Converting, on Linux where a pseudo-terminal can be driven unattended: each lane converts its
  // own copy of the version-1 file, answering y and typing the password at the terminal; then
  // every lane signs with every converted copy, and the signatures verify and agree.
  if (process.platform === "linux") {
    const PTY = [
      "import os, pty, sys",
      "password, argv = sys.argv[1], sys.argv[2:]",
      "pid, fd = pty.fork()",
      "if pid == 0:",
      "    os.execv(argv[0], argv)",
      "seen, answered, typed = b'', False, False",
      "while True:",
      "    try:",
      "        chunk = os.read(fd, 1024)",
      "    except OSError:",
      "        break",
      "    if not chunk:",
      "        break",
      "    seen += chunk",
      "    if not answered and seen.endswith(b'[y/N] '):",
      "        os.write(fd, b'y' + bytes([13]))",
      "        answered = True",
      "    if answered and not typed and seen.endswith(b'password: '):",
      "        os.write(fd, password.encode() + bytes([13]))",
      "        typed = True",
      "_, status = os.waitpid(pid, 0)",
      "sys.stdout.buffer.write(str(os.waitstatus_to_exitcode(status)).encode() + bytes([10]) + seen)",
    ].join("\n");
    for (const lane of lanes) {
      const name = `converted-${lane.name}`;
      writeFileSync(keyFile(name), v1);
      const r = spawnSync("python3", ["-c", PTY, v1Password, ...lane.argv, "key", "policy", name, "--allow", "archon/test/v1"], {
        encoding: "utf8",
        shell: false,
        env: noPassword,
        timeout: 120_000,
      });
      const [code, ...transcript] = (r.stdout ?? "").split("\n");
      const shown = transcript.join("\n");
      expect(`key policy: ${lane.name} converts a version-1 entry at the terminal`,
        code === "0" && shown.includes("policy:  version 1, no policy") && shown.includes('becomes: allow "archon/test/v1"') &&
          readFileSync(keyFile(name))[4] === 2 ? "converted" : `${code} ${shown}`, "converted");
    }
    // A conversion keeps the key's own password: the version-1 file's, not this store's usual one.
    const v1Env = { ...process.env, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: v1Password };
    for (const converter of lanes) {
      const signatures = lanes.map((lane) =>
        run(lane, signIn(`converted-${converter.name}`, "archon/test/v1", V1_TEXT), { env: v1Env }).out);
      const sig = /"signature":"([0-9a-f]{128})"/u.exec(signatures[0] ?? "")?.[1] ?? "";
      expect(`key policy: what ${converter.name} converted signs in every lane, identically`,
        signatures.every((s) => s === signatures[0] && s.endsWith("[0]")) ? "agree" : signatures.join(" | "), "agree");
      expect(`key policy: what ${converter.name} converted verifies`,
        run(lanes[0], ["verify", "--pubkey", V1_TEXT, "--sig", sig, "--domain", "archon/test/v1", "--in", msgPath]).out,
        "valid\n[0]");
      rmSync(keyFile(`converted-${converter.name}`));
    }
  }
  for (const name of ["limited", "twoctx", "legacy", "future", "broken"]) rmSync(keyFile(name));
}

// 5d. `archon enroll` (docs/enroll.md §4, ADR 0013), in every lane, with the key go sealed.
//     The challenge token is the sdk's (sdk/ts), for the oracle's key, and the proof each lane
//     prints is checked with the sdk's verifier — never against a lane. Everywhere: the policy
//     refusal names the full `key policy` command, an audience is required, and with no terminal
//     nothing is shown or signed. On Linux, where a pseudo-terminal can be driven: each lane
//     shows the statement, asks, takes "y", and prints a proof the sdk verifies; the three
//     lanes print the same token, Ed25519 being deterministic; and a "n" signs nothing.
{
  const sdk = await import(pathToFileURL(join(root, "sdk", "ts", "dist", "src", "index.js")).href);
  const AUDIENCE = "https://bitshelf.dev/api";
  const noPassword = (({ ARCHON_KEY_PASSWORD, ...rest }) => ({ ...rest, ARCHON_HOME: storeHome }))(process.env);
  const noAudience = (({ ARCHON_AUDIENCE, ...rest }) => ({ ...rest, ARCHON_HOME: storeHome, ARCHON_KEY_PASSWORD: PASSWORD }))(process.env);
  const run = (lane, args, { env, detached } = {}) => {
    const [program, ...pre] = lane.argv;
    const r = spawnSync(program, [...pre, ...args], {
      encoding: "utf8",
      shell: false,
      detached: detached === true,
      env: env ?? { ...noAudience },
    });
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.status };
  };
  const unhex = (h) => new Uint8Array(Buffer.from(h, "hex"));
  const deadline = Math.floor(Date.now() / 1000) + 3600;
  const intentBytes = sdk.encodeEnrollIntent({
    blind: new Uint8Array(16).fill(0x5a), accountId: "u_8f3c2a", accountName: "julia (bitspark)",
    purpose: "add-key", restrictions: ["read:projects"],
  });
  const challenge = {
    audience: AUDIENCE, transaction: Uint8Array.of(0x8f, 0x3c), nonce: new Uint8Array(16).fill(0xab),
    newKey: unhex(PUB), intent: intentBytes, deadline,
  };
  const tokenPath = join(tmp, "enroll-challenge.txt");
  writeFileSync(tokenPath, `${sdk.encodeEnrollChallenge(challenge)}\n`);
  const { request } = sdk.enrollChallengeRequest(challenge);

  run(lanes[0], ["key", "add", "nonenroll", "--seed", SEED, "--allow", "thesmos/fact/v2"]);
  const fix = "    archon key policy nonenroll --allow thesmos/fact/v2 --allow archon-enroll/1";
  for (const lane of lanes) {
    const refused = run(lane, ["enroll", "--key", "nonenroll", "--audience", AUDIENCE, "--challenge-file", tokenPath]);
    expect(`enroll: ${lane.name} refuses a key whose policy lacks archon-enroll/1, naming the command`,
      refused.code === 1 && refused.stdout === "" && refused.stderr.includes(fix) ? "refused" : `${refused.code} ${refused.stdout} ${refused.stderr}`, "refused");
    const unaimed = run(lane, ["enroll", "--key", "shared", "--challenge-file", tokenPath]);
    expect(`enroll: ${lane.name} needs an audience the person selected`,
      unaimed.code === 1 && unaimed.stdout === "" && unaimed.stderr.includes("no audience") ? "refused" : `${unaimed.code} ${unaimed.stderr}`, "refused");
    const alone = run(lane, ["enroll", "--key", "shared", "--audience", AUDIENCE, "--challenge-file", tokenPath], { detached: true });
    expect(`enroll: ${lane.name} asks on a terminal or not at all`,
      alone.code === 1 && alone.stdout === "" && alone.stderr.includes("no terminal to ask on") ? "refused" : `${alone.code} ${alone.stdout} ${alone.stderr}`, "refused");
  }
  rmSync(join(storeHome, "keys", "nonenroll"));

  if (process.platform === "linux") {
    const PTY = [
      "import os, pty, sys",
      "out, answer, argv = sys.argv[1], sys.argv[2], sys.argv[3:]",
      "pid, fd = pty.fork()",
      "if pid == 0:",
      "    os.dup2(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 1)",
      "    os.execv(argv[0], argv)",
      "seen, sent = b'', False",
      "while True:",
      "    try:",
      "        chunk = os.read(fd, 1024)",
      "    except OSError:",
      "        break",
      "    if not chunk:",
      "        break",
      "    seen += chunk",
      "    if not sent and seen.endswith(b'[y/N] '):",
      "        os.write(fd, answer.encode() + bytes([13]))",
      "        sent = True",
      "_, status = os.waitpid(pid, 0)",
      "sys.stdout.buffer.write(str(os.waitstatus_to_exitcode(status)).encode() + bytes([10]) + seen)",
    ].join("\n");
    const at = new Date(deadline * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const STATEMENT =
      `${AUDIENCE} asks you to add a key to an account:\n` +
      "  account:      julia (bitspark)\n" +
      "  account id:   u_8f3c2a\n" +
      `  key:          ${TEXT}\n` +
      "  restrictions:\n    read:projects\n" +
      "the service may give this key the account's authority.\n" +
      `the request's deadline is about ${at}, the service's word; it is not the key's expiry.\n` +
      "signing with the store key shared\n" +
      'add this key to the account "julia (bitspark)"? [y/N] ';
    const env = { ...noAudience };
    const tokens = [];
    for (const lane of lanes) {
      for (const answer of ["y", "n"]) {
        const out = join(tmp, `enroll-${lane.name}-${answer}.out`);
        const r = spawnSync("python3", ["-c", PTY, out, answer, ...lane.argv,
          "enroll", "--key", "shared", "--audience", AUDIENCE, "--challenge-file", tokenPath], {
          encoding: "utf8", shell: false, env, timeout: 120_000,
        });
        if (r.error) {
          failures++;
          console.error(`FAIL enroll: ${lane.name} terminal: python3 did not run: ${r.error.message}`);
          continue;
        }
        const [code, ...rest] = (r.stdout ?? "").split("\n");
        const transcript = rest.join("\n").split(String.fromCharCode(13)).join("");
        const printed = existsSync(out) ? readFileSync(out, "utf8") : "";
        expect(`enroll: ${lane.name} shows the statement and asks (${answer})`,
          transcript.includes(STATEMENT) ? "shown" : transcript, "shown");
        if (answer === "n") {
          expect(`enroll: ${lane.name} signs nothing on "n"`,
            `${code} ${printed === "" && transcript.includes("refused. nothing was signed.") ? "nothing" : printed}`, "0 nothing");
          continue;
        }
        const line = printed.trim();
        let verified = "no token";
        try {
          const p = sdk.decodeEnrollProof(line);
          verified = String(sdk.verifyEnroll(AUDIENCE, request, p.proof) && Buffer.from(p.newKey).toString("hex") === PUB);
        } catch (e) {
          verified = `${e instanceof Error ? e.message : String(e)}: ${printed}`;
        }
        expect(`enroll: ${lane.name}'s proof token verifies for the oracle's key`, `${code} ${verified}`, "0 true");
        expect(`enroll: ${lane.name} says the proof is produced, not that the key is enrolled`,
          transcript.includes("proof produced. paste it into the service's page: the key is enrolled only when the page completes.") ? "said" : transcript, "said");
        tokens.push(line);
      }
    }
    expect("enroll: the three lanes print the same proof token",
      tokens.length === lanes.length && tokens.every((t) => t === tokens[0]) ? "agree" : tokens.join(" | "), "agree");
  }
}

// 6. The removal line itself, from the last lane, and then the store is empty for all.
expect("key store: rm names what it removed, and its scope",
  scrub(runStore(lanes[lanes.length - 1], ["key", "rm", "shared"]).stdout),
  `removed shared (${TEXT}) from archon's store at ${join("<store>", "shared")}; ` +
    "any copy of this key outside it is untouched.\n");
for (const lane of lanes) {
  expect(`key store: ${lane.name} sees an empty store`,
    runStore(lane, ["key", "list", "--json"]).stdout, "[]\n");
}

// ---- the password file's mode (ADR 0007 §A) ---------------------------------------
//
// POSIX only, and skipped elsewhere on purpose: Windows has no mode bits, so there is
// nothing to check and the lanes claim nothing (docs/keystore.md section 4). This is the
// one rule in section A that shipped as a sentence before it shipped as code, so it is
// pinned here rather than left to a comment.
if (process.platform !== "win32") {
  const loose = join(tmp, "loose-password");
  writeFileSync(loose, `${PASSWORD}\n`, { mode: 0o644 });
  const tight = join(tmp, "tight-password");
  writeFileSync(tight, `${PASSWORD}\n`, { mode: 0o600 });

  // The store needs a key to try to open; write one with the first lane.
  runStore(writer, ["key", "add", "moded", "--seed", SEED, "--unrestricted"]);

  // On fd 3 AND on fd 0: `--password-fd 0 < pw.txt` is the same regular file arriving on
  // stdin, and the rule must not depend on which descriptor carries it. The Rust lane used
  // to short-circuit fd 0 to stdin and skip the check (lane A's, found while wiring
  // `login --key`); the fd 0 rows are the case that would have caught it.
  for (const lane of lanes) {
    for (const [label, file, wantCode] of [
      ["refuses a world-readable password file", loose, 1],
      ["accepts an owner-only password file", tight, 0],
    ]) {
      for (const onFd of [3, 0]) {
        const fd = openSync(file, "r");
        const [program, ...pre] = lane.argv;
        const r = spawnSync(program, [...pre, "key", "export", "moded", "--reveal",
                                      "--out", join(tmp, `moded-${lane.name}.pem`),
                                      "--password-fd", String(onFd)], {
          encoding: "utf8",
          shell: false,
          // The password file is the child's fd 3, or its stdin; ARCHON_KEY_PASSWORD is
          // deliberately absent so --password-fd is the only source.
          stdio: onFd === 0 ? [fd, "pipe", "pipe"] : ["pipe", "pipe", "pipe", fd],
          // ARCHON_KEY_PASSWORD is REMOVED, not set to undefined: node stringifies env values,
          // so an undefined would arrive as the literal "undefined" and be a valid password.
          env: (({ ARCHON_KEY_PASSWORD, ...rest }) => ({ ...rest, ARCHON_HOME: storeHome }))(process.env),
        });
        closeSync(fd);
        expect(`key store: ${lane.name} ${label} on fd ${onFd}`, String(r.status), String(wantCode));
      }
    }
  }
  runStore(writer, ["key", "rm", "moded"]);
}

// ---- the private-key file's mode (GHSA-32mc-pxw9-43jc) ----------------------------
//
// `keygen --out` writes a private key, so the file it creates is the owner's alone: 0600,
// in every lane. The Rust lane wrote it with the default mode, 0644 under the usual umask,
// readable by every local user, from 0.6.1 through 0.10.0. The Go and TS lanes always
// created it 0600. Each lane writes a FRESH file: like os.WriteFile and writeFileSync, the
// mode applies when the file is created. The children inherit umask 022, the common default
// and the one under which the defect shows. Under 077 every lane would pass and the row
// would prove nothing. POSIX only, for the reason the section above gives.
if (process.platform !== "win32") {
  const previousUmask = process.umask(0o022);
  for (const lane of lanes) {
    const keyFile = join(tmp, `keygen-mode-${lane.name}.pem`);
    const [program, ...pre] = lane.argv;
    const r = spawnSync(program, [...pre, "keygen", "--seed", SEED, "--out", keyFile],
                        { encoding: "utf8", shell: false });
    expect(`keygen --out: ${lane.name} exits 0`, String(r.status), "0");
    const mode = existsSync(keyFile) ? (statSync(keyFile).mode & 0o777).toString(8) : "missing";
    expect(`keygen --out: ${lane.name} creates the private key 0600`, mode, "600");
  }
  process.umask(previousUmask);
}

// ---- the README's quickstart, as written (issue #49) ------------------------------
//
// The first commands an adopter copies. For three releases they did not work — `keygen
// --out` wrote a PEM that `sign --seed` cannot read — because nothing ran them. Now every
// lane runs the README's own block, verbatim, through cli/quickstart.mjs: a mismatch between
// what keygen writes and what sign reads goes red here, on the pull request, not on a user.
for (const lane of lanes) {
  for (const r of runQuickstart(join(root, "README.md"), lane.argv)) {
    if (r.ok) { checked++; console.log(`ok   quickstart [${lane.name}] $ ${r.command}`); }
    else { failures++; console.error(`FAIL quickstart [${lane.name}] $ ${r.command}\n       ${r.detail}`); }
  }
}

rmSync(tmp, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} failing case(s) across ${lanes.length} lane(s)`);
  process.exit(1);
}
console.log(`\nall lanes agree: ${checked} cases × ${lanes.length} binaries`);
