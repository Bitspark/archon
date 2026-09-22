/// The canonical spelling of a public key: `ed25519:` followed by 64 lowercase hex digits.
///
/// Encoding always produces lowercase. Decoding accepts either case in the digits, as the Go
/// reference does (`hex.DecodeString`), but the prefix is exact: `ED25519:` is not archon's
/// spelling. Note the oracle pins only ENCODING here — decoding is held to the Go reference by
/// reading it, not by a vector.
public enum KeyText {
    public static let prefix = "ed25519:"

    public static func encodeKey(_ publicKey: [UInt8]) -> String {
        prefix + HexBytes.toHex(publicKey)
    }

    public static func decodeKey(_ text: String) -> [UInt8]? {
        let bytes = Array(text.utf8)
        let head = Array(prefix.utf8)
        guard bytes.count >= head.count, Array(bytes[..<head.count]) == head else { return nil }
        let body = String(decoding: bytes[head.count...], as: UTF8.self)
        return HexBytes.fixed(body, Crypto.publicKeySize)
    }
}
