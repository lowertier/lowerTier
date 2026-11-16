"""Add the VPN extension to a generated Tauri iOS project."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
TAURI = ROOT / "lowertier/gui/src-tauri"
APPLE = TAURI / "gen/apple"
project = APPLE / "project.yml"
if not project.is_file():
    raise SystemExit("Run pnpm ios:init in lowertier/gui first.")
spec = json.loads(subprocess.check_output(
    ["ruby", "-rjson", "-ryaml", "-e", "puts JSON.generate(YAML.load_file(ARGV[0]))", str(project)],
    cwd=ROOT, text=True,
))
bundle = json.loads((TAURI / "tauri.conf.json").read_text())["identifier"]
app_name = next(name for name, target in spec["targets"].items() if target["type"] == "application" and target["platform"] == "iOS")
app = spec["targets"][app_name]
base = app["settings"]["base"]
base["LOWTIER_BUNDLE_ID"] = bundle
base["PRODUCT_BUNDLE_IDENTIFIER"] = bundle
properties = {
    "LowTierKeychainGroup": "$(AppIdentifierPrefix)$(LOWTIER_BUNDLE_ID).shared",
    "LowTierAppGroup": "group.$(LOWTIER_BUNDLE_ID)",
    "NSLocalNetworkUsageDescription": "LowTier connects this device to members of your private network.",
}
capabilities = {
    "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
    "com.apple.security.application-groups": ["group.$(LOWTIER_BUNDLE_ID)"],
    "keychain-access-groups": ["$(AppIdentifierPrefix)$(LOWTIER_BUNDLE_ID).shared"],
}
app["info"]["properties"].update(properties)
app["entitlements"] = {"path": "../../ios/App.entitlements", "properties": capabilities}
dependencies = app["dependencies"]
for dependency in [{"target": "LowTierPacketTunnel", "embed": True}, {"sdk": "NetworkExtension.framework"}]:
    if dependency not in dependencies:
        dependencies.append(dependency)
spec["targets"]["LowTierPacketTunnel"] = {
    "type": "app-extension", "platform": "iOS", "deploymentTarget": "16.0",
    "sources": [
        {"path": "../../ios/PacketTunnel", "excludes": ["*.h", "*.entitlements"]},
        {"path": "../../plugins/vpn/ios/Sources/Shared.swift"},
    ],
    "info": {
        "path": "../../ios/PacketTunnel/Info.plist",
        "properties": {
            **properties,
            "CFBundleDisplayName": "LowTier VPN",
            "CFBundleShortVersionString": "0.0.3",
            "CFBundleVersion": "0.0.3",
            "NSExtension": {
                "NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel",
                "NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).PacketTunnelProvider",
            },
        },
    },
    "entitlements": {"path": "../../ios/PacketTunnel/PacketTunnel.entitlements", "properties": capabilities},
    "settings": {"base": {
        "PRODUCT_BUNDLE_IDENTIFIER": bundle + ".PacketTunnel",
        "LOWTIER_BUNDLE_ID": bundle,
        "SWIFT_VERSION": "5.0",
        "SWIFT_OBJC_BRIDGING_HEADER": "$(SRCROOT)/../../ios/PacketTunnel/LowTierFFI.h",
        "APPLICATION_EXTENSION_API_ONLY": True,
        "SKIP_INSTALL": True,
        "ENABLE_BITCODE": False,
        "ARCHS": ["arm64"],
        "LOWTIER_ROOT": "$(SRCROOT)/../../../../..",
        "LOWTIER_RUST_TARGET[sdk=iphoneos*]": "aarch64-apple-ios",
        "LOWTIER_RUST_TARGET[sdk=iphonesimulator*]": "aarch64-apple-ios-sim",
        "OTHER_LDFLAGS": '$(inherited) "$(LOWTIER_ROOT)/target/$(LOWTIER_RUST_TARGET)/release/liblowertier_ffi.a"',
    }},
    "dependencies": [
        {"sdk": name} for name in [
            "NetworkExtension.framework", "Security.framework", "SystemConfiguration.framework",
            "Network.framework", "libresolv.tbd", "libiconv.tbd",
        ]
    ],
    "preBuildScripts": [{
        "name": "Build LowTier VPN core",
        "script": 'python3 "${LOWTIER_ROOT}/script/ios/build-core.py" "${LOWTIER_RUST_TARGET}"',
        "basedOnDependencyAnalysis": False,
    }],
}
yaml = subprocess.check_output(
    ["ruby", "-rjson", "-ryaml", "-e", "puts YAML.dump(JSON.parse(STDIN.read))"],
    cwd=ROOT, input=json.dumps(spec), text=True,
)
project.write_text(yaml)
subprocess.run(["xcodegen", "generate", "--spec", str(project)], cwd=APPLE, check=True)
print(f"Configured {app_name} and LowTierPacketTunnel for {bundle}.")
