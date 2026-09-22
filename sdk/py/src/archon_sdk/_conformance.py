"""Conformance CLI (python, sdk) — a dev/CI artifact, not part of the library surface.

The same `conformance v1` protocol as the floor's CLI: `conformance <family>` reads the whole
vectors/sdk.json on stdin, selects its family, RECOMPUTES each result from the case INPUTS
(ignoring the expected value the oracle carries), and writes one NDJSON line per case to
stdout in input order.

    possession_prove  : in {name, seed, domain, nonce, binding}        out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
    possession_verify : in {name, pubkey, domain, nonce, binding, sig} out {"name","valid":<bool>}
    envelope_seal     : in {name, seed, domain, payload}               out {"name","result":{"ok":"<hex>"}|{"error":true}}
    envelope_open     : in {name, envelope, domain}                    out {"name","result":{"ok":{"pubkey","payload"}}|{"error":true}}

Recomputing rather than echoing is the whole point: a CLI that read `result` from the case
would agree with the oracle by construction and prove nothing.
"""

import json
import sys

from . import envelope, possession


def _attempt(fn):
    """The oracle's two-shape result: {"ok": …} or {"error": true}. It distinguishes success
    from failure, never the message."""
    try:
        return {"ok": fn()}
    except Exception:  # noqa: BLE001 - every failure is one refusal to the oracle
        return {"error": True}


def _unhex(text: str) -> bytes:
    # Case inputs that are *already* known-good hex; a bad one is a broken vector file, not a
    # case the family is testing.
    return bytes.fromhex(text)


def _opened(env_hex: str, domain: str) -> dict:
    o = envelope.open(_unhex(env_hex), domain)
    return {"pubkey": o.pubkey.hex(), "payload": o.payload.hex()}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: conformance <family>", file=sys.stderr)
        return 2
    family = argv[0]

    doc = json.load(sys.stdin)
    cases = doc.get(family)
    if not isinstance(cases, list):
        print(f"conformance: no such family: {family}", file=sys.stderr)
        return 1

    out_lines = []
    for case in cases:
        name = case["name"]
        if family == "possession_prove":
            out = {
                "name": name,
                "result": _attempt(
                    lambda: possession.prove(
                        _unhex(case["seed"]), case["domain"], _unhex(case["nonce"]), _unhex(case["binding"])
                    ).hex()
                ),
            }
        elif family == "possession_verify":
            out = {
                "name": name,
                "valid": possession.verify(
                    _unhex(case["pubkey"]),
                    case["domain"],
                    _unhex(case["nonce"]),
                    _unhex(case["binding"]),
                    _unhex(case["sig"]),
                ),
            }
        elif family == "envelope_seal":
            out = {
                "name": name,
                "result": _attempt(
                    lambda: envelope.seal(_unhex(case["seed"]), case["domain"], _unhex(case["payload"])).hex()
                ),
            }
        elif family == "envelope_open":
            out = {"name": name, "result": _attempt(lambda: _opened(case["envelope"], case["domain"]))}
        else:
            print(f"conformance: no such family: {family}", file=sys.stderr)
            return 1
        out_lines.append(json.dumps(out))

    sys.stdout.write("".join(line + "\n" for line in out_lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
