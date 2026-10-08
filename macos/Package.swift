// swift-tools-version: 6.0
import PackageDescription
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().path
let package = Package(
    name: "iSafety",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "iSafety", targets: ["iSafety"])],
    targets: [
        .target(name: "CIsafety", publicHeadersPath: "include"),
        .executableTarget(
            name: "iSafety", dependencies: ["CIsafety"],
            linkerSettings: [.unsafeFlags(["-L", root + "/target/release"]), .linkedLibrary("isafety_core"), .linkedLibrary("iconv")]
        ),
        .testTarget(name: "iSafetyTests", dependencies: ["iSafety"])
    ]
)
