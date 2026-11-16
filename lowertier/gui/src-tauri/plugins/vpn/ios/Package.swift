// swift-tools-version:5.7

import PackageDescription

let package = Package(
    name: "tauri-plugin-lowertier-vpn",
    platforms: [
        .macOS(.v11),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "tauri-plugin-lowertier-vpn",
            type: .static,
            targets: ["tauri-plugin-lowertier-vpn"]),
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-lowertier-vpn",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources")
    ]
)
