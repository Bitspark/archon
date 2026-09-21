"""Conformance CLI (python) — a dev/CI artifact, not part of the library surface.

Implements the `conformance v1` protocol: `conformance <family>` reads the whole
vectors/identity.json on stdin, selects its family's cases, RECOMPUTES each result from the
case INPUTS (ignoring the expected value the oracle carries), and writes one NDJSON line per
case to stdout in input order. The harness drives this and the other cores as black boxes and
asserts each line against the oracle.

    pubkey_from_seed : in {name, seed}                  out {"name","pubkey":"<64-hex>"}
    key_encode       : in {name, pubkey}                out {"name","text":"<key text>"}
    keycodec         : in {name, kind, key?|pem?}       out {"name","result":{"ok":…}|{"error":true}}
    signature_verify : in {name, pubkey, message, sig}  out {"name","valid":<bool>}
    hex_decode       : in {name, kind, hex}             out {"name","result":{"ok":"<hex>"}|{"error":true}}
    domain_sign      : in {name, seed, domain, message} out {"name","result":{"ok":"<128-hex>"}|{"error":true}}
    domain_verify    : in {name, pubkey, domain, message, sig} out {"name","valid":<bool>}

Recomputing rather than echoing is the whole point: a CLI that read `result` from the case
would agree with the oracle by construction and prove nothing.
"""

import json
import sys

from . import crypto, hexbytes, keycodec, keytext


def _result_of(value, err):
    """The oracle's two-shape result: {"ok": …} or {"error": true}."""
    return {"error": True} if err is not None else {"ok": value}


def _try(fn):
    try:
        return fn(), None
    except Exception as exc:  # noqa: BLE001 - every failure is one refusal to the oracle
        return None, exc


def _unhex(text: str) -> bytes:
    # Case inputs that are *already* known-good hex; a bad one is a broken vector file,
    # not a case the family is testing.
    return bytes.fromhex(text)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: conformance <family>", file=sys.stderr)
        return 2
    family = argv[0]

    doc = json.load(sys.stdin)
    cases = doc.get(family)
    if cases is None:
        print(f"conformance: no such family: {family}", file=sys.stderr)
        return 1

    out_lines = []
    for case in cases:
        # The oracle carries a leading note object in some families; it has no name.
        if "name" not in case:
            continue
        out = {"name": case["name"]}

        if family == "pubkey_from_seed":
            pub = crypto.public_key_from_seed(_unhex(case["seed"]))
            out["pubkey"] = hexbytes.to_hex(pub)

        elif family == "key_encode":
            out["text"] = keytext.encode_key(_unhex(case["pubkey"]))

        elif family == "keycodec":
            kind = case["kind"]
            if kind == "encode_pkcs8":
                v, e = _try(lambda: keycodec.seed_to_pkcs8_pem(_unhex(case["key"])).decode("ascii"))
            elif kind == "encode_spki":
                v, e = _try(lambda: keycodec.pubkey_to_spki_pem(_unhex(case["key"])).decode("ascii"))
            elif kind == "decode_pkcs8":
                v, e = _try(lambda: hexbytes.to_hex(keycodec.pkcs8_pem_to_seed(case["pem"].encode("utf-8"))))
            elif kind == "decode_spki":
                v, e = _try(lambda: hexbytes.to_hex(keycodec.spki_pem_to_pubkey(case["pem"].encode("utf-8"))))
            else:
                raise SystemExit(f"unknown keycodec kind: {kind}")
            out["result"] = _result_of(v, e)

        elif family == "signature_verify":
            out["valid"] = crypto.verify(
                _unhex(case["pubkey"]), _unhex(case["message"]), _unhex(case["sig"])
            )

        elif family == "hex_decode":
            kind = case["kind"]
            fn = {
                "seed": hexbytes.seed_from_hex,
                "pubkey": hexbytes.pubkey_from_hex,
                "signature": hexbytes.signature_from_hex,
            }.get(kind)
            if fn is None:
                raise SystemExit(f"unknown hex_decode kind: {kind}")
            v, e = _try(lambda: hexbytes.to_hex(fn(case["hex"])))
            out["result"] = _result_of(v, e)

        elif family == "domain_sign":
            v, e = _try(
                lambda: hexbytes.to_hex(
                    crypto.sign_in_domain(
                        _unhex(case["seed"]), case["domain"], _unhex(case["message"])
                    )
                )
            )
            out["result"] = _result_of(v, e)

        elif family == "domain_verify":
            out["valid"] = crypto.verify_in_domain(
                _unhex(case["pubkey"]),
                case["domain"],
                _unhex(case["message"]),
                _unhex(case["sig"]),
            )

        else:
            print(f"conformance: unhandled family: {family}", file=sys.stderr)
            return 1

        out_lines.append(json.dumps(out, separators=(",", ":"), sort_keys=True))

    sys.stdout.write("\n".join(out_lines) + ("\n" if out_lines else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
