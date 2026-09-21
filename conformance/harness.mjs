// Language-agnostic conformance harness (the `conformance v1` protocol archon inherits
// from thesmos ADR 0006).
//
// Drives one or more conformance CLIs as BLACK BOXES over the shared
// vectors/identity.json and asserts each emitted result against the hand-authored oracle
// (the expected value carried in the vector itself) — so every core is checked against
// the standard, and therefore against each other. The harness knows nothing of the CLIs'
// languages or internals; it only spawns them and reads their NDJSON.
//
// This is the whole reason archon is three implementations rather than one library with
// two bindings: a key spelled by the Rust core must be readable by the Go core, byte for
// byte, or the identity floor is not a floor.
//
// usage: node conformance/harness.mjs <vectorsDir>[/<oracle>.json] "<cli-cmd>" ["<cli-cmd>" ...]
//   each <cli-cmd> is run as `<cli-cmd> <family>` with the whole oracle document on
//   stdin; it selects its family's cases, recomputes each result (ignoring the expected
//   value), and emits one NDJSON line per case to stdout, in input order.
//
//   Two oracles live in vectors/: identity.json (the floor, driven by the core/* CLIs) and
//   sdk.json (the layer above it, driven by the sdk/* CLIs). A bare directory selects
//   identity.json; the family table is chosen by the oracle's file name.

import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { runCli } from "./spawn.mjs";

const argv = process.argv.slice(2);
const vectorsArg = argv.shift();
const clis = argv;
if (!vectorsArg || clis.length === 0) {
  console.error('usage: node conformance/harness.mjs <vectorsDir>[/<oracle>.json] "<cli-cmd>" ...');
  process.exit(2);
}
const oraclePath = vectorsArg.endsWith(".json") ? vectorsArg : join(vectorsArg, "identity.json");
const oracleName = basename(oraclePath);

const oracle = JSON.parse(readFileSync(oraclePath, "utf8"));
// The CLIs select their own family out of the whole document and ignore the expected
// value; sending the document verbatim keeps the harness free of per-family reshaping.
const input = JSON.stringify(oracle);

// Canonical JSON (keys sorted recursively) so the per-case compare is independent of the
// key order a CLI or the oracle happens to emit — needed for the `result` objects.
function stable(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(",")}}`;
}

// `want(case)` is the expected result hand-authored in the oracle, `got(line)` the CLI's
// recomputed result; they are compared as canonical JSON. Every family here carries a
// `name`, and the name is asserted per case so a drop+duplicate — which preserves the
// count — cannot slip past the positional compare.
const FAMILIES = [
  // Ed25519 public-key derivation (RFC 8032 §5.1.5). Pure: seed in, pubkey out.
  { name: "pubkey_from_seed", want: (c) => c.pubkey, got: (l) => l.pubkey },
  // The canonical key text `ed25519:<lowercase-hex>` — the one spelling of a public key
  // the constellation agrees on, so a key copied out of one core's log parses in another.
  { name: "key_encode", want: (c) => c.text, got: (l) => l.text },
  // The PKCS#8 v1 / SPKI PEM codec (RFC 5958 / RFC 5280). Both the accepted bytes and
  // the REJECTED ones are pinned: a codec that differs on what it refuses is a codec
  // that differs.
  { name: "keycodec", want: (c) => c.result, got: (l) => l.result },
  // Verify semantics, including the cases where implementations historically diverge:
  // non-canonical S, small-order public keys, wrong-length inputs. A core that says
  // `true` where another says `false` splits the constellation in half.
  { name: "signature_verify", want: (c) => c.valid, got: (l) => l.valid },
  // The typed fixed-size hex decoders (seed 32 / pubkey 32 / signature 64). What is
  // REFUSED is the content: a 31-byte "seed" accepted by one core is a key that exists
  // in one lane and not the others.
  { name: "hex_decode", want: (c) => c.result, got: (l) => l.result },
  // Domain-separated signing (Ed25519ph with the domain as RFC 8032 context). The
  // signature is deterministic, so it is pinned outright — derived with OpenSSL, not a
  // core — and so are the two refusals (empty domain, domain over 255 bytes).
  { name: "domain_sign", want: (c) => c.result, got: (l) => l.result },
  // Domain-separated verify. The crossings are the point: a signature from domain A
  // presented in domain B, and a raw signature presented in any domain, are `false`
  // in every core, cryptographically — one key can serve many protocols only if this
  // holds identically everywhere.
  { name: "domain_verify", want: (c) => c.valid, got: (l) => l.valid },
];

// The layer above the floor (vectors/sdk.json, ADR 0004). Same discipline, one level up:
// every output is a deterministic function of the case's inputs — entropy, time and
// binding are inputs, never sourced — so it pins exactly the way the floor does.
const SDK_FAMILIES = [
  // Proof of possession: the signature over the pinned nonce+binding layout in the
  // caller's domain, and the two refusals (short nonce, empty binding).
  { name: "possession_prove", want: (c) => c.result, got: (l) => l.result },
  // The substitutions are the content: each of nonce, binding, domain and key must
  // bind, and neither a raw signature nor a bare-nonce signature is a proof.
  { name: "possession_verify", want: (c) => c.valid, got: (l) => l.valid },
  // The envelope's exact bytes — container and signature — for a payload, an empty
  // payload, and the 255-byte domain bound.
  { name: "envelope_seal", want: (c) => c.result, got: (l) => l.result },
  // Open under the verifier's expected domain; every tamper, swap and truncation refused.
  { name: "envelope_open", want: (c) => c.result, got: (l) => l.result },
];

const LOGIN_FAMILIES = [
  // One URL, one audience, in every lane: the strict grammar of docs/login.md §2.1, refused
  // rather than normalised; the id comes back decoded.
  { name: "login_audience", want: (c) => c.result, got: (l) => l.result },
  // The binding both login proofs are made over: role ‖ audience ‖ K ‖ id ‖ scope ‖ valid_for,
  // length-prefixed, and every construction refusal (docs/login.md §3.2).
  { name: "login_binding", want: (c) => c.result, got: (l) => l.result },
  // The person's proof: possession in archon-login/1 over the nonce and the login binding.
  { name: "login_prove", want: (c) => c.result, got: (l) => l.result },
  // Every bound field binds; no other signature shape is a proof; total on bad shapes.
  { name: "login_verify", want: (c) => c.valid, got: (l) => l.valid },
  // The browser's collect proof, only from the key the request names.
  { name: "login_collect_prove", want: (c) => c.result, got: (l) => l.result },
  { name: "login_collect_verify", want: (c) => c.valid, got: (l) => l.valid },
];

// The command's own layer (vectors/keystore.json, ADR 0007 §A). Custody is the
// CLI tier's, so this oracle is driven by the cli/* lanes rather than core/* or sdk/*.
// Salt, nonce, password and parameters are case INPUTS - the randomness is the command's,
// never the format's - which is what makes a password-derived file pinnable at all.
const KEYSTORE_FAMILIES = [
  // The 134-byte file as a function of its inputs, plus the empty-password refusal.
  { name: "keystore_seal", want: (c) => c.result, got: (l) => l.result },
  // Round-trips, and every tamper, truncation and inconsistency refused.
  { name: "keystore_open", want: (c) => c.result, got: (l) => l.result },
  // The name rules as pure string cases: no crypto, and the three lanes must agree.
  { name: "keystore_name", want: (c) => c.result, got: (l) => l.result },
];

const TABLES = {
  "identity.json": FAMILIES,
  "sdk.json": SDK_FAMILIES,
  "login.json": LOGIN_FAMILIES,
  "keystore.json": KEYSTORE_FAMILIES,
};
const families = TABLES[oracleName];
if (!families) {
  console.error(`no family table for oracle ${oracleName} (known: ${Object.keys(TABLES).join(", ")})`);
  process.exit(2);
}

let failures = 0;
let checked = 0;

for (const cli of clis) {
  for (const fam of families) {
    const cases = oracle[fam.name];
    if (!Array.isArray(cases)) {
      console.error(`FAIL ${cli} ${fam.name}: family missing from the oracle`);
      failures++;
      continue;
    }

    const res = runCli(cli, fam.name, input);
    if (res.error || res.status !== 0) {
      console.error(`FAIL ${cli} ${fam.name}: exited ${res.status}${res.error ? ` (${res.error.message})` : ""}`);
      if (res.stderr) console.error(res.stderr.trim().split("\n").slice(0, 5).map((l) => `       ${l}`).join("\n"));
      failures++;
      continue;
    }

    const lines = res.stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    if (lines.length !== cases.length) {
      console.error(`FAIL ${cli} ${fam.name}: emitted ${lines.length} lines for ${cases.length} cases`);
      failures++;
      continue;
    }

    let famFailures = 0;
    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];
      const l = lines[i];
      if (l.name !== c.name) {
        console.error(`FAIL ${cli} ${fam.name}[${i}]: name ${JSON.stringify(l.name)} != ${JSON.stringify(c.name)}`);
        famFailures++;
        continue;
      }
      const want = stable(fam.want(c));
      const got = stable(fam.got(l));
      if (want !== got) {
        console.error(`FAIL ${cli} ${fam.name} ${c.name}\n       want ${want}\n       got  ${got}`);
        famFailures++;
      }
      checked++;
    }
    failures += famFailures;
    if (famFailures === 0) console.log(`ok   ${cli} ${fam.name} (${cases.length})`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} failure(s) across ${clis.length} core(s)`);
  process.exit(1);
}
console.log(`\nall cores agree: ${checked} case-checks, ${clis.length} core(s)`);
