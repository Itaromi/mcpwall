// swift-tools-version: 6.0
import PackageDescription

// Pas de projet Xcode : le bundle .app est assemblé par `scripts/build-app.sh`
// à partir de ce binaire. Ça se construit avec les seuls Command Line Tools,
// donc en CI comme sur une machine de développement, sans dépendre d'une
// version d'Xcode installée.
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
