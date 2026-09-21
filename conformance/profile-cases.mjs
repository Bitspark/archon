// The Ed25519 verification profile's adversarial classes (ADR 0008), generated rather than
// recalled, so the vectors that pin them can be re-derived and audited.
//
//   node conformance/profile-cases.mjs emit           print the cases as JSON (the source of
//                                                     the `profile-*` cases in vectors/identity.json)
//   node conformance/profile-cases.mjs measure <cli>… drive the cases through cores and print
//                                                     what each ACCEPTS — the disagreement map,
//                                                     with no expected value applied
//
// Every case here is a REJECTION under the profile: a public key or an R that is not a
// non-identity element of the prime-order subgroup, a non-canonical encoding, or an S out of
// range. Each comes with a signature that some RFC-8032-conforming verifier accepts, because
// a rejection nobody would ever accept pins nothing. The signatures are crafted with the
// signer's own scalar (a "signer" who knows the secret for the prime-order part of A), which
// is what an adversary can do; the crafting is test-vector generation, not a signing path.
//
// Point construction uses @noble/curves' arithmetic — the TS core's own dependency — and the
// small-order points are the eight torsion points found by multiplying an order-8 point, not
// a list typed in from memory. Their order is asserted before anything is emitted.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runCli } from "./spawn.mjs";

// @noble/curves and @noble/hashes are the TS core's dependencies, installed under
// core/ts/node_modules, which this directory does not resolve from. Load them from there:
// the generator uses the arithmetic the TS core ships with, not a second copy.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const noble = (pkg, file) => import(pathToFileURL(join(root, "core", "ts", "node_modules", "@noble", pkg, file)).href);
const { ed25519 } = await noble("curves", "ed25519.js");
const { sha512 } = await noble("hashes", "sha2.js");

const Point = ed25519.Point;
const L = Point.Fn.ORDER;
const p = Point.Fp.ORDER;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const utf8 = (s) => new TextEncoder().encode(s);
const cat = (...bs) => { const out = new Uint8Array(bs.reduce((n, b) => n + b.length, 0)); let o = 0; for (const b of bs) { out.set(b, o); o += b.length; } return out; };
const leToBig = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const bigToLe32 = (n) => { const out = new Uint8Array(32); for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; } return out; };
const mod = (a, m) => ((a % m) + m) % m;

// ---- the signer whose prime-order key the crafted objects borrow --------------------------
// seed-11 (0x11 × 32) is the oracle's own key — pubkey_from_seed.seed-11, the signer of
// signature_verify.valid and of every domain_sign case — so the crafted cases sit next to
// genuine ones over the same key.
const SEED = unhex("11".repeat(32));
const ext = ed25519.utils.getExtendedPublicKey(SEED);
const A_GOOD = ext.point;                 // the genuine public key point
const a = ext.scalar;                     // its clamped secret scalar
const prefix = ext.prefix;                // RFC 8032 §5.1.6 nonce prefix
if (hex(A_GOOD.toBytes()) !== "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737") {
  throw new Error("seed 11 no longer derives the oracle's valid key");
}

// dom2 for Ed25519ph with a context (RFC 8032 §5.1); raw Ed25519 has no prefix.
const dom2 = (ctx) => cat(utf8("SigEd25519 no Ed25519 collisions"), Uint8Array.of(1, ctx.length), ctx);
const challenge = (Rbytes, Abytes, M, ctx) => {
  const ph = ctx ? sha512(M) : M;
  const pre = ctx ? dom2(ctx) : new Uint8Array(0);
  return mod(leToBig(sha512(cat(pre, Rbytes, Abytes, ph))), L);
};

// Craft (R ‖ S) such that [S]B = R_prime + [k]A_prime holds for the PRIME-ORDER parts, with
// k computed over the exact bytes a verifier will hash (Rbytes, Abytes as given). The bytes
// may encode torsion, non-canonical spellings, or the identity — that is the point.
function craft({ Rpoint, Rbytes, Abytes, M, ctx, r }) {
  if (r === undefined) r = mod(leToBig(sha512(cat(prefix, M))), L);   // deterministic, like RFC 8032
  const R = Rpoint ?? Point.BASE.multiply(r);
  Rbytes = Rbytes ?? R.toBytes();
  const k = challenge(Rbytes, Abytes, M, ctx);
  const S = mod(r + k * a, L);
  return { sig: hex(cat(Rbytes, bigToLe32(S))), k };
}

// ---- the torsion subgroup, found, not typed ----------------------------------------------
// An order-8 point: any point whose 8-fold is the identity but whose 4-fold is not. Search
// the encodings ZIP-215 lists as small-order until one has order exactly 8, then derive the
// other seven by multiplication so the set is closed by construction.
const T8_CANDIDATES = ["c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"];
let T8;
for (const h of T8_CANDIDATES) {
  const P = Point.fromHex(h, true);
  if (P.multiplyUnsafe(8n).is0() && !P.multiplyUnsafe(4n).is0()) { T8 = P; break; }
}
if (!T8) throw new Error("no order-8 point found");
const torsion = [];                       // [i]T8 for i in 0..7, with its order
for (let i = 0n; i < 8n; i++) {
  const P = T8.multiplyUnsafe(i);
  const order = [1n, 2n, 4n, 8n].find((n) => P.multiplyUnsafe(n).is0());
  torsion.push({ i, P, order, bytes: P.toBytes() });
}
if (!torsion[0].P.is0() || torsion.filter((t) => t.order === 8n).length !== 4) throw new Error("torsion subgroup is not the one expected");

// Non-canonical spellings of a point: y + p when y < 19 (fits in 255 bits), and the
// x-sign bit set when x = 0 (RFC 8032 §5.1.3 says reject; ZIP-215 decoders accept).
function nonCanonical(P) {
  const out = [];
  const { x, y } = P.toAffine();
  const b = P.toBytes();
  if (y + p < (1n << 255n)) { const c = bigToLe32(y + p); c[31] |= b[31] & 0x80; out.push({ why: "y encoded as y+p", bytes: c }); }
  if (x === 0n) { const c = Uint8Array.from(b); c[31] |= 0x80; out.push({ why: "x = 0 with the sign bit set", bytes: c }); }
  return out;
}

// Find a message whose challenge k is, or is not, divisible by n, by appending a counter.
function findMessage(base, Rbytes, Abytes, ctx, n, divisible) {
  for (let c = 0; c < 4096; c++) {
    const M = utf8(`${base}#${c}`);
    const k = challenge(Rbytes, Abytes, M, ctx);
    if ((k % n === 0n) === divisible) return M;
  }
  throw new Error("no message found");
}

// ---- cases -------------------------------------------------------------------------------
const sv = [];   // signature_verify: {name, pubkey, message, sig, valid:false, note}
const dv = [];   // domain_verify:    {name, pubkey, domain, message, sig, valid:false, note}
const DOMAIN = "archon/test/v1";
const CTX = utf8(DOMAIN);
const CLASS = (name, note) => ({ name, note });

// 1. A is the identity (order 1): R = B, S = 1 verifies for EVERY message and EVERY context
//    under the uncofactored equation, because [k]O = O. The advice's counterexample.
{
  const A = torsion[0].bytes, sig = hex(cat(Point.BASE.toBytes(), bigToLe32(1n)));
  sv.push({ ...CLASS("profile-identity-A", "ADR 0008 class 1: A is the identity point. R = B, S = 1 satisfies [S]B = R + [k]A for every k, so this one signature verifies over every message; a verifier that admits the identity as a key admits a universal signature. Profile: a public key must be a non-identity element of the prime-order subgroup — false."), pubkey: hex(A), message: hex(utf8("hello")), sig, valid: false });
  sv.push({ name: "profile-identity-A-other-message", pubkey: hex(A), message: hex(utf8("different message")), sig, valid: false });
  dv.push({ ...CLASS("profile-identity-A-in-domain", "ADR 0008 class 1 in a domain: the same universal signature, presented as a domain signature. The separation property of ADR 0003 cannot hold for a key whose every signature is valid everywhere — false."), pubkey: hex(A), domain: DOMAIN, message: hex(utf8("hello")), sig, valid: false });
  dv.push({ name: "profile-identity-A-in-other-domain", pubkey: hex(A), domain: "archon/test/v2", message: hex(utf8("hello")), sig, valid: false });
}

// 2. A is a small-order point (order 2, 4, 8): with R = B and S = 1 the uncofactored
//    equation holds exactly when the point's order divides k; the cofactored equation holds
//    always. One message of each kind per point, so the class is pinned, not one outcome.
for (const t of torsion.slice(1)) {
  const R = Point.BASE.toBytes(), sig = hex(cat(R, bigToLe32(1n)));
  const yes = findMessage("small-order", R, t.bytes, null, t.order, true);
  const no = findMessage("small-order", R, t.bytes, null, t.order, false);
  sv.push({ ...CLASS(`profile-small-order-${t.order}-A-${t.i}-k-divisible`, `ADR 0008 class 2: A = [${t.i}]T8, a point of order ${t.order}. R = B, S = 1. The challenge k for this message is divisible by ${t.order}, so [k]A = O and the uncofactored equation holds; the cofactored one holds for every message. Profile: a small-order public key is not a key — false.`), pubkey: hex(t.bytes), message: hex(yes), sig, valid: false });
  sv.push({ name: `profile-small-order-${t.order}-A-${t.i}-k-not-divisible`, pubkey: hex(t.bytes), message: hex(no), sig, valid: false });
}

// 3. Non-canonical spellings of small-order points, as A. Each names the same point as a
//    canonical case above; a decoder that reduces y mod p or ignores the sign bit on x = 0
//    admits it. Profile: encodings are canonical, and the point is rejected anyway — false.
for (const t of torsion) {
  for (const nc of nonCanonical(t.P)) {
    const R = Point.BASE.toBytes(), sig = hex(cat(R, bigToLe32(1n)));
    const M = t.order === 1n ? utf8("hello") : findMessage("non-canonical", R, nc.bytes, null, t.order, true);
    sv.push({ ...CLASS(`profile-non-canonical-A-${t.i}-${nc.why.replace(/[^a-z0-9]+/g, "-")}`, `ADR 0008 class 3: A is [${t.i}]T8 (order ${t.order}) spelled non-canonically — ${nc.why}. RFC 8032 §5.1.3 rejects the encoding; ZIP-215 decoders accept it and see the small-order point. Profile: false.`), pubkey: hex(nc.bytes), message: hex(M), sig, valid: false });
  }
}

// 4. A is MIXED-order: the genuine key plus a torsion point, A = A_good + T8. Not small
//    order, so a small-order check passes it; not in the prime-order subgroup. The signer
//    who holds A_good's scalar signs with A's bytes in the challenge: the cofactored equation
//    then holds for every message (the torsion vanishes under ×8) and the uncofactored one
//    holds exactly when 8 | k. This is the class where "reject small-order keys" and
//    "prime-order subgroup" part ways. Profile: false, both messages, both modes.
{
  const Amix = A_GOOD.add(T8), Ab = Amix.toBytes();
  if (Amix.isSmallOrder() || Amix.isTorsionFree()) throw new Error("mixed-order construction failed");
  for (const [divisible, tag] of [[true, "k-divisible"], [false, "k-not-divisible"]]) {
    // R depends on the message and the message on k, which depends on R: fix r first.
    const r = 7n;
    const Rb = Point.BASE.multiply(r).toBytes();
    const M = findMessage("mixed-order", Rb, Ab, null, 8n, divisible);
    const { sig } = craft({ Rbytes: Rb, Abytes: Ab, M, r });
    sv.push({ ...(divisible ? CLASS("profile-mixed-order-A-k-divisible", "ADR 0008 class 4: A = A_good + T8 has order 8L — not small order, not in the prime-order subgroup. Signed by A_good's holder with A's bytes in the challenge. k is divisible by 8 here, so BOTH the cofactored and the uncofactored equation hold: every current core that decodes the point accepts this. Profile: a public key is in the prime-order subgroup — false.") : { name: "profile-mixed-order-A-k-not-divisible" }), pubkey: hex(Ab), message: hex(M), sig, valid: false });
    const Md = findMessage("mixed-order-domain", Rb, Ab, CTX, 8n, divisible);
    const d = craft({ Rbytes: Rb, Abytes: Ab, M: Md, ctx: CTX, r });
    dv.push({ ...(divisible ? CLASS("profile-mixed-order-A-in-domain-k-divisible", "ADR 0008 class 4 in a domain: the mixed-order key, Ed25519ph with the domain as context, k divisible by 8 — both equations hold. Profile: false.") : { name: "profile-mixed-order-A-in-domain-k-not-divisible" }), pubkey: hex(Ab), domain: DOMAIN, message: hex(Md), sig: d.sig, valid: false });
  }
}

// 5. R is small order. With A genuine and S = k·a (r = 0), [S]B = [k]A, so the equation
//    needs R = O: the identity R passes both equations; a torsion R passes only the
//    cofactored one. Profile: R is a non-identity element of the prime-order subgroup —
//    false for both, and for the identity's non-canonical spelling.
{
  const Ab = A_GOOD.toBytes();
  const M = utf8("hello");
  const O = craft({ Rpoint: Point.ZERO, Abytes: Ab, M, r: 0n });
  sv.push({ ...CLASS("profile-identity-R", "ADR 0008 class 5: R is the identity point (r = 0) and S = k·a, so [S]B = [k]A = R + [k]A under every equation. RFC 8032 pure verification accepts it; no honest signer produces it. Profile: R is a non-identity element of the prime-order subgroup — false."), pubkey: hex(Ab), message: hex(M), sig: O.sig, valid: false });
  const T = craft({ Rpoint: T8, Abytes: Ab, M, r: 0n });
  sv.push({ ...CLASS("profile-small-order-R", "ADR 0008 class 5: R = T8 (order 8), S = k·a. The cofactored equation holds (8·T8 = O); the uncofactored one does not. A verifier that checks only A for small order accepts this. Profile: false."), pubkey: hex(Ab), message: hex(M), sig: T.sig, valid: false });
  const ncO = nonCanonical(Point.ZERO).find((n) => n.why.startsWith("y encoded"));
  const N = craft({ Rpoint: Point.ZERO, Rbytes: ncO.bytes, Abytes: Ab, M, r: 0n });
  sv.push({ ...CLASS("profile-non-canonical-R", "ADR 0008 class 5 + 3: R is the identity spelled as y = p + 1, and k is computed over those bytes, as a verifier would. A decoder that reduces y accepts it. Profile: false."), pubkey: hex(Ab), message: hex(M), sig: N.sig, valid: false });
  const Od = craft({ Rpoint: Point.ZERO, Abytes: Ab, M, ctx: CTX, r: 0n });
  dv.push({ ...CLASS("profile-identity-R-in-domain", "ADR 0008 class 5 in a domain: R = O, S = k·a with the Ed25519ph challenge. Profile: false."), pubkey: hex(Ab), domain: DOMAIN, message: hex(M), sig: Od.sig, valid: false });
  const Td = craft({ Rpoint: T8, Abytes: Ab, M, ctx: CTX, r: 0n });
  dv.push({ ...CLASS("profile-small-order-R-in-domain", "ADR 0008 class 5 in a domain: R = T8. Profile: false."), pubkey: hex(Ab), domain: DOMAIN, message: hex(M), sig: Td.sig, valid: false });
}

// 6. S at the boundary. The oracle already pins S + L (non-canonical-s). S = L is the
//    smallest out-of-range value and reduces to 0; S = L − 1 is in range and simply wrong.
//    Both false — one by the range rule, one by the equation.
{
  const Ab = A_GOOD.toBytes(), M = utf8("hello");
  const Rb = Point.BASE.multiply(7n).toBytes();
  sv.push({ ...CLASS("profile-S-equals-L", "ADR 0008 class 6: S = L exactly. Out of range (0 ≤ S < L); a verifier that reduces S mod L sees 0. Profile: false."), pubkey: hex(Ab), message: hex(M), sig: hex(cat(Rb, bigToLe32(L))), valid: false });
  sv.push({ ...CLASS("profile-S-equals-L-minus-1", "ADR 0008 class 6: S = L − 1, the largest in-range scalar, over a genuine key and R = [7]B. In range, so the equation decides, and it does not hold — false. Pinned so the range check is not written as S ≤ L − 2 anywhere."), pubkey: hex(Ab), message: hex(M), sig: hex(cat(Rb, bigToLe32(L - 1n))), valid: false });
}

const cases = { signature_verify: sv, domain_verify: dv };

// ---- emit / measure ----------------------------------------------------------------------
const mode = process.argv[2];
if (mode === "emit") {
  process.stdout.write(JSON.stringify(cases, null, 2) + "\n");
} else if (mode === "measure") {
  // Wrap the cases in a full oracle document so the CLIs' family selection works unchanged.
  const oracle = JSON.parse(readFileSync(join(root, "vectors", "identity.json"), "utf8"));
  const doc = { ...oracle, signature_verify: sv, domain_verify: dv };
  const input = JSON.stringify(doc);
  const clis = process.argv.slice(3);
  if (!clis.length) { console.error("usage: profile-cases.mjs measure \"<cli>\" …"); process.exit(2); }
  const results = {};
  for (const cli of clis) {
    for (const fam of ["signature_verify", "domain_verify"]) {
      const res = runCli(cli, fam, input);
      if (res.error || res.status !== 0) { console.error(`${cli} ${fam}: exited ${res.status} ${res.stderr?.trim() ?? ""}`); continue; }
      for (const line of res.stdout.trim().split("\n").filter(Boolean)) {
        const l = JSON.parse(line);
        (results[l.name] ??= {})[cli] = l.valid;
      }
    }
  }
  const short = (c) => c.replace(/^.*[\\/]/, "").replace(/\.exe$/, "").replace(/^conformance-?/, "") || c;
  console.log(["case", ...clis.map(short)].join("\t"));
  for (const [name, r] of Object.entries(results)) console.log([name, ...clis.map((c) => r[c] === undefined ? "?" : r[c] ? "ACCEPT" : "reject")].join("\t"));
} else {
  console.error("usage: node conformance/profile-cases.mjs emit | measure \"<cli>\" …");
  process.exit(2);
}
