
// swift-tools-version: 5.9
import PackageDescription

let protobufMinVersion: Version = "1.29.0"
let psshMinVersion: Version = "1.2.2"
let rsaMinVersion: Version = "2.6.1"

#if targetEnvironment(simulator) || targetEnvironment(macCatalyst) || os(macOS) || os(iOS) || os(watchOS) || os(tvOS) || os(visionOS)
//Exclude CryptoSwift package (used built-in CommonCrypto)
let dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-protobuf.git", from: protobufMinVersion),
    .package(url: "https://github.com/mIwr/SwPSSH.git", from: psshMinVersion),
    .package(url: "https://github.com/mIwr/SwiftRSA.git", from: rsaMinVersion)
]
let mainTargetDependencies: [Target.Dependency] = [
    .product(name: "SwiftProtobuf", package: "swift-protobuf"),
    .product(name: "SwPSSH", package: "SwPSSH"),
    .product(name: "SwiftRSA", package: "SwiftRSA")
]
#else
let dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-protobuf.git", from: protobufMinVersion),
    .package(url: "https://github.com/mIwr/SwPSSH.git", from: psshMinVersion),
    .package(url: "https://github.com/mIwr/SwiftRSA.git", from: rsaMinVersion),
    .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.4")
]
let mainTargetDependencies: [Target.Dependency] = [
    .product(name: "SwiftProtobuf", package: "swift-protobuf"),
    .product(name: "SwPSSH", package: "SwPSSH"),
    .product(name: "SwiftRSA", package: "SwiftRSA"),
    .product(name: "CryptoSwift", package: "CryptoSwift")
]
#endif

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
    dependencies: dependencies,
    targets: [
        .target(name: "SwWidevine", dependencies: mainTargetDependencies, resources: [.copy("PrivacyInfo.xcprivacy")]),
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
