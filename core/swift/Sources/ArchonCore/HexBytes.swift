/// Lowercase hex out, case-insensitive hex in, at exactly the length a value must have.
///
/// Decoding is fixed-size on purpose: a seed is 64 digits and a signature 128, and a string of
/// the wrong length is refused rather than truncated or padded. No `0x` prefix, no whitespace.
public enum HexBytes {
    private static let digits: [UInt8] = Array("0123456789abcdef".utf8)

    public static func toHex(_ data: [UInt8]) -> String {
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func seedFromHex(_ text: String) -> [UInt8]? { fixed(text, Crypto.seedSize) }
    public static func pubkeyFromHex(_ text: String) -> [UInt8]? { fixed(text, Crypto.publicKeySize) }
    public static func signatureFromHex(_ text: String) -> [UInt8]? { fixed(text, Crypto.signatureSize) }

    static func fixed(_ text: String, _ size: Int) -> [UInt8]? {
        let chars = Array(text.utf8)
        guard chars.count == size * 2 else { return nil }
        var out = [UInt8](repeating: 0, count: size)
        for i in 0..<size {
            guard let hi = value(chars[2 * i]), let lo = value(chars[2 * i + 1]) else { return nil }
            out[i] = hi << 4 | lo
        }
        return out
    }

    private static func value(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}
