/// SPKI (RFC 5280) and PKCS #8 v1 (RFC 5958) PEM for Ed25519 keys, as fixed DER templates.
///
/// Both formats have exactly one valid shape for an Ed25519 key, so they are handled as a fixed
/// prefix followed by the 32 key bytes — not with a general ASN.1 parser, which would accept
/// encodings the other cores refuse. Anything that does not match the template byte for byte is
/// refused: a v2 PKCS #8 with an embedded public key, a wrong OID, a short key, trailing bytes.
///
/// PEM parsing follows the Go reference exactly: CRLF is accepted, trailing newlines are
/// ignored, the BEGIN and END lines must be the first and last, and the body is standard base64
/// with padding only at its end.
public enum KeyCodec {
    static let spkiPrefix: [UInt8] = [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]
    static let pkcs8Prefix: [UInt8] = [
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]

    public static func pubkeyToSPKIPEM(_ publicKey: [UInt8]) -> String? {
        encode(publicKey, spkiPrefix, "PUBLIC KEY")
    }

    public static func seedToPKCS8PEM(_ seed: [UInt8]) -> String? {
        encode(seed, pkcs8Prefix, "PRIVATE KEY")
    }

    public static func spkiPEMToPubkey(_ pem: String) -> [UInt8]? {
        decode(pem, spkiPrefix, "PUBLIC KEY")
    }

    public static func pkcs8PEMToSeed(_ pem: String) -> [UInt8]? {
        decode(pem, pkcs8Prefix, "PRIVATE KEY")
    }

    private static func encode(_ key: [UInt8], _ prefix: [UInt8], _ type: String) -> String? {
        guard key.count == Crypto.publicKeySize else { return nil }
        let body = Base64.encode(prefix + key)
        return "-----BEGIN \(type)-----\n\(body)\n-----END \(type)-----\n"
    }

    private static func decode(_ pem: String, _ prefix: [UInt8], _ type: String) -> [UInt8]? {
        // CRLF -> LF, then drop trailing newlines — the Go reference's two normalisations, and no
        // others. A lone CR survives into the body and is skipped by the base64 decoder, as Go's is.
        var text = Array(pem.utf8)
        var normalised = [UInt8]()
        normalised.reserveCapacity(text.count)
        var i = 0
        while i < text.count {
            if text[i] == 0x0D, i + 1 < text.count, text[i + 1] == 0x0A { i += 1; continue }
            normalised.append(text[i])
            i += 1
        }
        while normalised.last == 0x0A { normalised.removeLast() }
        text = normalised

        let lines = text.split(separator: 0x0A, omittingEmptySubsequences: false).map(Array.init)
        let begin = Array("-----BEGIN \(type)-----".utf8)
        let end = Array("-----END \(type)-----".utf8)
        guard lines.count >= 3, lines.first == begin, lines.last == end else { return nil }

        let body = lines[1..<(lines.count - 1)].flatMap { $0 }
        guard let der = Base64.decode(body),
              der.count == prefix.count + Crypto.publicKeySize,
              Array(der[..<prefix.count]) == prefix
        else { return nil }
        return Array(der[prefix.count...])
    }
}

/// Standard base64 (RFC 4648 §4), matching Go's `base64.StdEncoding`: padding is required and
/// may appear only as one or two `=` at the very end; `\r` and `\n` are skipped; any other
/// character outside the alphabet is a refusal rather than something to ignore.
enum Base64 {
    private static let alphabet: [UInt8] =
        Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

    static func encode(_ data: [UInt8]) -> String {
        var out = [UInt8]()
        out.reserveCapacity((data.count + 2) / 3 * 4)
        var i = 0
        while i < data.count {
            let b0 = UInt32(data[i])
            let b1 = i + 1 < data.count ? UInt32(data[i + 1]) : 0
            let b2 = i + 2 < data.count ? UInt32(data[i + 2]) : 0
            let chunk = b0 << 16 | b1 << 8 | b2
            out.append(alphabet[Int(chunk >> 18 & 0x3F)])
            out.append(alphabet[Int(chunk >> 12 & 0x3F)])
            out.append(i + 1 < data.count ? alphabet[Int(chunk >> 6 & 0x3F)] : UInt8(ascii: "="))
            out.append(i + 2 < data.count ? alphabet[Int(chunk & 0x3F)] : UInt8(ascii: "="))
            i += 3
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func decode(_ input: [UInt8]) -> [UInt8]? {
        let text = input.filter { $0 != 0x0D && $0 != 0x0A }
        guard text.count % 4 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(text.count / 4 * 3)
        var quad = 0
        while quad < text.count {
            let isLast = quad + 4 == text.count
            var values = [UInt32](repeating: 0, count: 4)
            var padding = 0
            for j in 0..<4 {
                let c = text[quad + j]
                if c == UInt8(ascii: "=") {
                    // Padding belongs only to the final quad, only in its last two positions,
                    // and once it starts nothing else may follow it.
                    guard isLast, j >= 2 else { return nil }
                    padding += 1
                    continue
                }
                guard padding == 0, let v = value(c) else { return nil }
                values[j] = v
            }
            let chunk = values[0] << 18 | values[1] << 12 | values[2] << 6 | values[3]
            out.append(UInt8(chunk >> 16 & 0xFF))
            if padding < 2 { out.append(UInt8(chunk >> 8 & 0xFF)) }
            if padding < 1 { out.append(UInt8(chunk & 0xFF)) }
            quad += 4
        }
        return out
    }

    private static func value(_ c: UInt8) -> UInt32? {
        switch c {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): return UInt32(c - UInt8(ascii: "A"))
        case UInt8(ascii: "a")...UInt8(ascii: "z"): return UInt32(c - UInt8(ascii: "a") + 26)
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return UInt32(c - UInt8(ascii: "0") + 52)
        case UInt8(ascii: "+"): return 62
        case UInt8(ascii: "/"): return 63
        default: return nil
        }
    }
}
