// The Swift core's conformance v1 CLI.
//
//   archon-conformance <family>   reads the whole oracle document on stdin, selects that
//                                 family's cases, RECOMPUTES each one from its inputs, and
//                                 writes one NDJSON line per case.
//
// It never reads a case's expected value. A CLI that echoed the oracle's `result` would agree
// with it by construction and prove nothing; the harness asserts what this computed.
//
// Foundation is imported here, for JSON, and nowhere in the library: ArchonCore has no
// dependency beyond the standard library and its two C libraries.
import ArchonCore
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("conformance: \(message)\n".utf8))
    exit(1)
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: archon-conformance <family>\n".utf8))
    exit(2)
}
let family = CommandLine.arguments[1]

let input = FileHandle.standardInput.readDataToEndOfFile()
guard let document = try? JSONSerialization.jsonObject(with: input) as? [String: Any] else {
    fail("stdin is not a JSON object")
}
guard let cases = document[family] as? [[String: Any]] else {
    fail("no such family: \(family)")
}

/// Hex in the ORACLE's inputs is always well-formed; this is transport, not the API under test.
func unhex(_ text: String) -> [UInt8] {
    let chars = Array(text.utf8)
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 2)
    var i = 0
    while i + 1 < chars.count {
        let pair = String(decoding: chars[i...(i + 1)], as: UTF8.self)
        out.append(UInt8(pair, radix: 16) ?? 0)
        i += 2
    }
    return out
}

func quote(_ s: String) -> String {
    var out = "\""
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04x", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    return out + "\""
}

/// The oracle's two-shape result: {"ok": …} or {"error": true}.
func result(_ value: String?) -> String {
    value.map { "{\"ok\":\(quote($0))}" } ?? "{\"error\":true}"
}

func string(_ c: [String: Any], _ key: String) -> String {
    guard let value = c[key] as? String else { fail("case is missing string field '\(key)'") }
    return value
}

var output = ""
for c in cases {
    guard let name = c["name"] as? String else { continue }  // a leading note object
    var line = "{\"name\":\(quote(name))"

    switch family {
    case "pubkey_from_seed":
        let pub = Crypto.publicKeyFromSeed(unhex(string(c, "seed")))
        line += ",\"pubkey\":\(quote(pub.map(HexBytes.toHex) ?? ""))"

    case "key_encode":
        line += ",\"text\":\(quote(KeyText.encodeKey(unhex(string(c, "pubkey")))))"

    case "keycodec":
        let value: String?
        switch string(c, "kind") {
        case "encode_pkcs8": value = KeyCodec.seedToPKCS8PEM(unhex(string(c, "key")))
        case "encode_spki": value = KeyCodec.pubkeyToSPKIPEM(unhex(string(c, "key")))
        case "decode_pkcs8": value = KeyCodec.pkcs8PEMToSeed(string(c, "pem")).map(HexBytes.toHex)
        case "decode_spki": value = KeyCodec.spkiPEMToPubkey(string(c, "pem")).map(HexBytes.toHex)
        case let kind: fail("unknown keycodec kind: \(kind)")
        }
        line += ",\"result\":\(result(value))"

    case "signature_verify":
        let ok = Crypto.verify(publicKey: unhex(string(c, "pubkey")),
                               message: unhex(string(c, "message")),
                               signature: unhex(string(c, "sig")))
        line += ",\"valid\":\(ok)"

    case "hex_decode":
        let text = string(c, "hex")
        let decoded: [UInt8]?
        switch string(c, "kind") {
        case "seed": decoded = HexBytes.seedFromHex(text)
        case "pubkey": decoded = HexBytes.pubkeyFromHex(text)
        case "signature": decoded = HexBytes.signatureFromHex(text)
        case let kind: fail("unknown hex_decode kind: \(kind)")
        }
        line += ",\"result\":\(result(decoded.map(HexBytes.toHex)))"

    case "domain_sign":
        let sig = Crypto.signInDomain(seed: unhex(string(c, "seed")),
                                      domain: string(c, "domain"),
                                      message: unhex(string(c, "message")))
        line += ",\"result\":\(result(sig.map(HexBytes.toHex)))"

    case "domain_verify":
        let ok = Crypto.verifyInDomain(publicKey: unhex(string(c, "pubkey")),
                                       domain: string(c, "domain"),
                                       message: unhex(string(c, "message")),
                                       signature: unhex(string(c, "sig")))
        line += ",\"valid\":\(ok)"

    default:
        fail("unhandled family: \(family)")
    }

    output += line + "}\n"
}
FileHandle.standardOutput.write(Data(output.utf8))
