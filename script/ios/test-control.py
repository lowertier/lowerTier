"""Run the production Swift control plugin with host VPN and IPC fixtures."""

import datetime
import json
from pathlib import Path
import plistlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "benchmark-results/.work/ios-control-test"
BUNDLE = OUT / "VpnControlTest.app/Contents"
EXECUTABLE = BUNDLE / "MacOS/VpnControlTest"
EXECUTABLE.parent.mkdir(parents=True, exist_ok=True)
with (BUNDLE / "Info.plist").open("wb") as output:
    plistlib.dump({
        "CFBundleIdentifier": "com.lowertier.fixture",
        "CFBundleExecutable": "VpnControlTest",
        "CFBundlePackageType": "APPL",
    }, output)


def record(value):
    with (OUT / "audit.jsonl").open("a") as output:
        output.write(json.dumps(value) + "\n")
    print(json.dumps(value), flush=True)


def run(command, timeout):
    process = subprocess.Popen(command, cwd=ROOT)
    details = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": [str(part) for part in command], "cwd": str(ROOT), "pid": process.pid,
        "timeout_seconds": timeout,
    }
    record(dict(details, event="start"))
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        code = -9
    record(dict(details, event="finish", exit_code=code, output="Inherited by the enclosing command log.",
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    if code:
        raise SystemExit(code)


run([
    "xcrun", "swiftc", "-swift-version", "5", "-emit-library", "-emit-module", "-module-name", "Tauri",
    "-emit-module-path", OUT / "Tauri.swiftmodule", ROOT / "script/ios/ControlPluginStub.swift",
    "-o", OUT / "libTauri.dylib", "-Xlinker", "-install_name", "-Xlinker", "@rpath/libTauri.dylib",
], 120)
run([
    "xcrun", "swiftc", "-swift-version", "5", "-I", OUT, "-L", OUT, "-lTauri",
    "-Xlinker", "-rpath", "-Xlinker", OUT,
    ROOT / "lowertier/gui/src-tauri/plugins/vpn/ios/Sources/VpnPlugin.swift",
    ROOT / "script/ios/VpnControlTest.swift", "-o", EXECUTABLE,
], 120)
run([EXECUTABLE], 30)
