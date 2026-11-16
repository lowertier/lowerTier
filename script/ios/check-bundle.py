"""Check the app, embedded extension, and runtime library paths."""

import json
from pathlib import Path
import plistlib
import subprocess
import sys

app = Path(sys.argv[1]).resolve()
extension = app / "PlugIns/LowTierPacketTunnel.appex"
app_info = plistlib.loads((app / "Info.plist").read_bytes())
extension_info = plistlib.loads((extension / "Info.plist").read_bytes())
assert extension_info["CFBundleIdentifier"] == app_info["CFBundleIdentifier"] + ".PacketTunnel"
assert extension_info["NSExtension"]["NSExtensionPointIdentifier"] == "com.apple.networkextension.packet-tunnel"
assert extension_info["LowTierAppGroup"] == app_info["LowTierAppGroup"]
assert extension_info["LowTierKeychainGroup"] == app_info["LowTierKeychainGroup"]

for folder, info in [(app, app_info), (extension, extension_info)]:
    binary = folder / info["CFBundleExecutable"]
    architectures = subprocess.check_output(["xcrun", "lipo", "-archs", str(binary)], text=True).split()
    assert architectures == ["arm64"], f"Unexpected architectures: {architectures}"
    output = subprocess.check_output(["xcrun", "otool", "-L", str(binary)], text=True)
    dependencies = [line.strip().split(" (", 1)[0] for line in output.splitlines()[1:]]
    for library in dependencies:
        assert library.startswith(("/System/Library/", "/usr/lib/", "@rpath/", "@loader_path/", "@executable_path/")), \
            f"The bundle references an external build path: {library}"
        assert "lowertier_ffi" not in library, "The VPN core must link from its static archive."
    print(json.dumps({
        "bundle": info["CFBundleIdentifier"], "architectures": architectures,
        "binary_bytes": binary.stat().st_size, "libraries": dependencies,
    }))
