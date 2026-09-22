// swift-tools-version: 6.0
//
// archon's Swift core. This manifest sits at the repository ROOT because SwiftPM consumers
// depend on a git URL and a tag, and SwiftPM reads Package.swift from the root of that
// repository -- there is no way to point it at a subdirectory. Everything else lives under
// core/swift/.
//
// Two system libraries, and the split is the point (docs/languages.md, ADR 0008 §8):
//   OpenSSL >= 3.2        signs. It is the only library here that reaches Ed25519ph with a
//                         context string. CryptoKit and swift-crypto ship pure Ed25519 only.
//   libsodium >= 1.0.21   decides what is acceptable. OpenSSL validates no points for Ed25519.
//
// SwiftPM cannot express a system library's version, so the floors are enforced by #error in
// the shim (core/swift/Sources/CArchonCrypto) and again at runtime against the libraries the
// process actually loaded.
import PackageDescription

let package = Package(
    name: "Archon",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ArchonCore", targets: ["ArchonCore"]),
    ],
    targets: [
        .systemLibrary(
            name: "COpenSSL",
            path: "core/swift/Sources/COpenSSL",
            pkgConfig: "libcrypto",
            providers: [.apt(["libssl-dev"]), .brew(["openssl@3"])]
        ),
        .systemLibrary(
            name: "CSodium",
            path: "core/swift/Sources/CSodium",
            pkgConfig: "libsodium",
            providers: [.apt(["libsodium-dev"]), .brew(["libsodium"])]
        ),
        .target(
            name: "CArchonCrypto",
            dependencies: ["COpenSSL", "CSodium"],
            path: "core/swift/Sources/CArchonCrypto"
        ),
        .target(
            name: "ArchonCore",
            dependencies: ["CArchonCrypto"],
            path: "core/swift/Sources/ArchonCore"
        ),
        // The conformance CLI is a dev artifact. A consumer depending on the ArchonCore product
        // never builds it: SwiftPM builds only the targets a product needs.
        .executableTarget(
            name: "ArchonConformance",
            dependencies: ["ArchonCore"],
            path: "core/swift/Sources/ArchonConformance"
        ),
        .testTarget(
            name: "ArchonCoreTests",
            dependencies: ["ArchonCore"],
            path: "core/swift/Tests/ArchonCoreTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
