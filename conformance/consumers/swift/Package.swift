// swift-tools-version: 6.0
//
// A consumer that knows nothing but the package. It is NOT part of archon's own manifest: it
// depends on archon the way a stranger does, so it exercises the root Package.swift, the two
// system-library targets and the shim's floors from the outside.
//
// Two ways to point it at archon:
//   ARCHON_VERSION=0.8.0   resolve the TAG from the public git URL, exactly as a consumer does
//   ARCHON_PATH=/x/archon  a local checkout; the directory MUST be named `archon`, because
//                          SwiftPM names a path dependency after its directory and the product
//                          below is looked up in the package called "archon"
import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment
let archon: Package.Dependency
if let path = environment["ARCHON_PATH"] {
    archon = .package(path: path)
} else if let version = environment["ARCHON_VERSION"] {
    archon = .package(url: "https://github.com/Bitspark/archon.git", exact: Version(stringLiteral: version))
} else {
    fatalError("set ARCHON_VERSION (a released tag) or ARCHON_PATH (a checkout named archon)")
}

let package = Package(
    name: "ArchonConsumer",
    platforms: [.macOS(.v13)],
    dependencies: [archon],
    targets: [
        .executableTarget(
            name: "Consumer",
            dependencies: [.product(name: "ArchonCore", package: "archon")],
            path: "Sources/Consumer"
        ),
    ]
)
