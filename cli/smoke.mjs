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
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync,
         writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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
  { name: "--help", args: ["--help"], want: "usage: archon <keygen|key|login|sign|verify|version> [args]\n", code: 0 },
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
  runStore(writer, ["key", "add", "shared", "--seed", SEED]).stdout,
  `stored shared (${TEXT}) from --seed; the source file is untouched.\n`,
);

// 2. Every lane lists it identically — WITHOUT a password, from the header alone.
for (const lane of lanes) {
  expect(
    `key store: ${lane.name} lists the shared key`,
    runStore(lane, ["key", "list", "--json"]).stdout,
    `[{"name":"shared","principal":"${TEXT}"}]\n`,
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
  const scrubTime = (s) => s.replace(/until \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/, "until <t>");
  const WANT =
    `${audience} asks you to let browser key ${K_TEXT} act as you:\n` +
    SCOPE.map((s) => `  ${s}\n`).join("") +
    "for 8h0m0s, until <t>\n" +
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
    "for 8h0m0s, until <t>\n" +
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

// 4. Refusals every lane owes: no --reveal, a wrong password, a duplicate name, and the
//    name rules (a trailing dot and a reserved device name with an extension).
for (const lane of lanes) {
  expect(`key store: ${lane.name} refuses export without --reveal`,
    String(runStore(lane, ["key", "export", "shared", "--out", join(tmp, "no.pem")]).code), "1");
  expect(`key store: ${lane.name} refuses a wrong password`,
    String(runStore(lane, ["key", "export", "shared", "--reveal", "--out", join(tmp, "no.pem")],
      { ARCHON_KEY_PASSWORD: "not the password" }).code), "1");
  expect(`key store: ${lane.name} refuses a duplicate name`,
    String(runStore(lane, ["key", "add", "shared", "--seed", SEED]).code), "1");
  expect(`key store: ${lane.name} refuses a trailing dot`,
    String(runStore(lane, ["key", "add", "alice.", "--seed", SEED]).code), "1");
  expect(`key store: ${lane.name} refuses CON.key`,
    String(runStore(lane, ["key", "add", "CON.key", "--seed", SEED]).code), "1");
}

// 5. A file that is not a key is never LISTED as one (that is what the magic buys), is
//    refused by rm, and --force says what it could not read.
writeFileSync(join(storeHome, "keys", "stray"), "this is not a key file");
for (const lane of lanes) {
  expect(`key store: ${lane.name} does not list a stray file`,
    runStore(lane, ["key", "list", "--json"]).stdout,
    `[{"name":"shared","principal":"${TEXT}"}]\n`);
  expect(`key store: ${lane.name} refuses to rm a stray file`,
    String(runStore(lane, ["key", "rm", "stray"]).code), "1");
}
expect("key store: rm --force says what it could not read",
  scrub(runStore(lanes[lanes.length - 1], ["key", "rm", "stray", "--force"]).stdout),
  "removed stray (unreadable header: not 134 bytes (got 22)) from archon's store at " +
    `${join("<store>", "stray")}; any copy of this key outside it is untouched.\n`);

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
  runStore(writer, ["key", "add", "moded", "--seed", SEED]);

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

rmSync(tmp, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} failing case(s) across ${lanes.length} lane(s)`);
  process.exit(1);
}
console.log(`\nall lanes agree: ${checked} cases × ${lanes.length} binaries`);
