"""Build the native VPN archive with the repository toolchain and cache."""

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
target = sys.argv[1] if len(sys.argv) > 1 else "aarch64-apple-ios"
if target not in {"aarch64-apple-ios", "aarch64-apple-ios-sim"}:
    raise SystemExit("Select aarch64-apple-ios or aarch64-apple-ios-sim.")
environment = os.environ.copy()
# Xcode passes its deployment target to all build phases.
environment["IPHONEOS_DEPLOYMENT_TARGET"] = "16.0"
subprocess.run(
    ["cargo", "build", "--locked", "--release", "--target", target, "-p", "lowertier-ffi",
     "--no-default-features", "--features", "c-abi,packet-tunnel"],
    cwd=ROOT, env=environment, check=True,
)
