// swift-tools-version: 6.0
import PackageDescription

// No Xcode project: the .app bundle is assembled by `scripts/build-app.sh`
// from this binary. It builds with the Command Line Tools alone, so in CI just
// as on a development machine, without depending on an installed Xcode
// version.
let package = Package(
    name: "mcpwall",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "mcpwall",
            path: "Sources/mcpwall",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)
