# conformance

Three implementations of the same encodings are three chances to disagree. This directory
is what stops that.

```
node conformance/check.mjs
```

builds all three cores' conformance CLIs, drives each as a black box over
[`../vectors/identity.json`](../vectors/identity.json), and asserts every emitted result
against the oracle carried in the vector itself. Every core is checked against the
standard — and therefore against every other core.

That is the whole setup. A fresh clone needs a Rust toolchain, Go 1.25 and Node 22 on
PATH; `npm ci` for the TypeScript core runs itself if `node_modules` is missing, and the
command works from any directory (paths derive from the script's own location, not from
cwd). The same command is what [CI](../.github/workflows/conformance.yml) runs on every
push and pull request — there is no second, blessed invocation that only the robot knows.

## The protocol

`conformance v1`, inherited from thesmos ADR 0006. A CLI is invoked as
`<cli> <family>`, receives the **whole** oracle document on stdin, selects its family's
cases, recomputes each result from the case **inputs** (ignoring the expected value), and
writes one NDJSON line per case to stdout **in input order**.

| family | in | out |
|---|---|---|
| `pubkey_from_seed` | `{name, seed}` | `{"name","pubkey":"<64-hex>"}` |
| `key_encode` | `{name, pubkey}` | `{"name","text":"<key text>"}` |
| `keycodec` | `{name, kind, key or pem}` | `{"name","result":{"ok":"…"} or {"error":true}}` |
| `signature_verify` | `{name, pubkey, message, sig}` | `{"name","valid":<bool>}` |

The harness compares as **canonical JSON** (keys sorted recursively), so a core's key
order can never be the thing that passes or fails. It also asserts each case's `name`
positionally, so a drop-plus-duplicate — which preserves the count — cannot slip past.

## Files

| | |
|---|---|
| `check.mjs` | build all three, then run the harness. The one command. |
| `harness.mjs` | the driver. Knows nothing about any core's language or internals. |
| `spawn.mjs` | shell-free, cross-platform process invocation. Copied verbatim from thesmos — pure plumbing. |

The CLIs themselves live with their cores: `core/rs/src/bin/conformance.rs` (behind the
`conformance-cli` feature, so the published library keeps exactly one dependency),
`core/go/cmd/conformance`, `core/ts/conformance/cli.ts`.

## Adding a case

Add it to `vectors/identity.json` with the expected value **hand-authored from the RFC**,
not pasted from a core's output. A vector copied out of an implementation pins whatever
that implementation does, including its bugs; a vector derived from the standard pins the
standard. Then run `check.mjs` and watch all three cores agree — or find out which one
does not.
