// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "FountainAuthKit",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "FountainAuthKit", targets: ["FountainAuthKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
        .package(url: "https://github.com/Fountain-Coach/swift-secretstore.git", exact: "0.2.1")
    ],
    targets: [
        .target(name: "FountainAuthKit", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "SecretStore", package: "swift-secretstore")
        ]),
        .testTarget(name: "FountainAuthKitTests", dependencies: ["FountainAuthKit"])
    ])
