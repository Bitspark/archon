// The whole exchange, end to end, on archon's published packages: a service (service.mjs), a
// key-less client (client.mjs), and a person with the `archon` command. Every step is checked,
// and the run exits 1 if any differs from what is printed here as expected.
//
//   npm ci && node run.mjs
//
// Two logins. In the first the person presents a team the service admits them to, and the
// client is let in. In the second they present one it does not: the person's proof is fine,
// the service's `admit` refuses it, and the client is left waiting with nothing to collect.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beginLogin } from "./client.mjs";
import { authorityText, startService } from "./service.mjs";

const here = dirname(fileURLToPath(import.meta.url));

// The `archon` the person runs: the published @bitspark/archon-cli, by its own bin entry.
const cliPackage = join(here, "node_modules", "@bitspark", "archon-cli");
const cliMain = join(cliPackage, JSON.parse(readFileSync(join(cliPackage, "package.json"), "utf8")).bin.archon);

let failures = 0;
function check(what, got, want) {
  if (got === want) {
    console.log(`  ok   ${what}`);
  } else {
    failures++;
    console.log(`  FAIL ${what}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`);
  }
}

// Asynchronous on purpose: the service lives in this process, and a blocking spawn would
// stop it from answering the very command it is waiting for. Output is echoed line by line
// as it arrives, so it interleaves with the service's log in the order things happened.
function archon(cwd, ...args) {
  console.log(`\n$ archon ${args.join(" ")}`);
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cliMain, ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    const out = { stdout: "", stderr: "" };
    for (const [name, stream, mark] of [["stdout", child.stdout, ""], ["stderr", child.stderr, "(stderr) "]]) {
      let pending = "";
      stream.setEncoding("utf8").on("data", (d) => {
        out[name] += d;
        const lines = (pending + d).split("\n");
        pending = lines.pop();
        for (const line of lines) console.log(`  │ ${mark}${line}`);
      });
      stream.on("end", () => { if (pending) console.log(`  │ ${mark}${pending}`); });
    }
    child.on("close", (code) => resolve({ code, ...out }));
  });
}

const dir = mkdtempSync(join(tmpdir(), "archon-login-example-"));
let service;
try {
  console.log(`archon ${(await archon(dir, "version")).stdout.trim().replace(/^archon /, "")}, in ${dir}`);

  // The person's key. `keygen --out` writes a PKCS#8 PEM; a person keeping keys would use
  // `archon key add` and `login --key <name>` instead, which needs a password to unlock.
  const keygen = await archon(dir, "keygen", "--out", "person.pem", "--pub-out", "person.txt", "--pub-format", "text");
  const person = readFileSync(join(dir, "person.txt"), "utf8").trim();
  check("keygen made a key", keygen.code, 0);

  service = await startService({ members: new Map([[person, ["projects"]]]), log: (l) => console.log(`  ${l}`) });
  console.log(`\nservice: ${service.audience} — ${person} is in team "projects", and no other`);

  // --- 1. admitted -------------------------------------------------------------------------
  console.log("\n1. The person presents team \"projects\".");
  const first = await beginLogin(service.audience, { scope: ["read:projects"], validFor: 3600 });
  console.log(`client: began a login for browser ${first.browser}; the person is given ${first.url}`);
  writeFileSync(join(dir, "projects.team"), "projects");
  // --yes stands in for the person reading the statement and typing y.
  const yes = await archon(dir, "login", first.url, "--key-file", "person.pem", "--authority-file", "projects.team", "--yes");
  check("archon login exits 0", yes.code, 0);
  check("archon login says the browser is in", yes.stdout.trimEnd().split("\n").at(-1), `signed as ${person}. the browser is in.`);

  const got = await first.collect();
  console.log(`client: collected ${JSON.stringify({ principal: got.principal, authority: got.authority })}`);
  check("the client collects the answer", got.status, 200);
  check("it names the person", got.principal, person);
  check("the person's proof verifies at the client", got.verified, true);
  check("the authority is the file the person named", authorityText(new TextEncoder().encode(JSON.stringify(got.authority))), "projects");

  // --- 2. refused by admit -----------------------------------------------------------------
  console.log("\n2. The same person presents team \"campaigns\".");
  const second = await beginLogin(service.audience, { scope: ["read:campaigns"], validFor: 3600 });
  console.log(`client: began a login for browser ${second.browser}; the person is given ${second.url}`);
  writeFileSync(join(dir, "campaigns.team"), "campaigns");
  const no = await archon(dir, "login", second.url, "--key-file", "person.pem", "--authority-file", "campaigns.team", "--yes");
  check("archon login exits 1", no.code, 1);
  check("archon login does not say the browser is in", no.stdout.includes("the browser is in"), false);

  const waiting = await second.poll();
  console.log(`client: polled once — ${waiting.status} ${waiting.error}`);
  check("the client has nothing to collect", `${waiting.status} ${waiting.error}`, "202 authorization_pending");
} finally {
  await service?.close();
  rmSync(dir, { recursive: true, force: true });
}

console.log(failures === 0 ? "\nevery step as expected" : `\n${failures} step(s) differed`);
process.exit(failures === 0 ? 0 : 1);
