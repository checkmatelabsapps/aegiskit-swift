// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisKit",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "AegisKit", targets: ["AegisKit"])
    ],
    dependencies: [
        // libsodium: ristretto255 group operations for the VOPRF ticket client.
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1")
    ],
    targets: [
        .target(
            name: "AegisKit",
            dependencies: [.product(name: "Clibsodium", package: "swift-sodium")],
            // Apple's privacy manifest: what the SDK collects (a device-bound
            // pseudonym), that it doesn't track, and that it uses no
            // required-reason APIs. Xcode folds it into the app's privacy report.
            resources: [.process("PrivacyInfo.xcprivacy")]
        ),
        .testTarget(
            name: "AegisKitTests",
            dependencies: ["AegisKit"],
            resources: [.copy("Resources/voprf-vectors.json"), .copy("Resources/refusal-explanations.json")]
        )
    ]
)
