
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwWidevine",
    platforms: [
        .macOS(.v10_13), .macCatalyst(.v13), .iOS(.v11), .tvOS(.v11), .watchOS(.v5), .visionOS(.v1)
    ],
    products: [
        .library(
            name: "SwWidevine",
            targets: ["SwWidevine"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.27.1"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.3"),
        .package(url: "https://github.com/mIwr/SwPSSH.git", from: "1.2.1"),
        .package(url: "https://github.com/mIwr/SwiftRSA.git", from: "2.5.2"),
    ],
    targets: [
        .target(name: "SwWidevine", dependencies: [
            .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            .product(name: "CryptoSwift", package: "CryptoSwift"),
            .product(name: "SwPSSH", package: "SwPSSH"),
            .product(name: "SwiftRSA", package: "SwiftRSA"),
        ], resources: [.copy("PrivacyInfo.xcprivacy")]),
        .testTarget(name: "SwWidevineTests", dependencies: ["SwWidevine"], exclude: ["TestConstantsXCodeEnvExt.swift"], resources: [
            .process("appCrt.protobuf"),
            .process("deviceClID.protobuf"),
            .process("licRequest.protobuf"),
            .process("licResponse.protobuf"),
            .process("licReqSelfGenerated.protobuf"),
            .process("licRespBySelfGenerated.protobuf"),
        ]),
    ],
    swiftLanguageVersions: [.v5]
)
