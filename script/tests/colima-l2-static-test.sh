#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
harness="$repo_root/script/colima-l2/e2e.sh"
dockerfile="$repo_root/script/colima-l2/Dockerfile"
probe="$repo_root/script/colima-l2/frame_probe.py"

test -f "$harness"
test -f "$dockerfile"
test -f "$probe"

grep -q '^set -euo pipefail$' "$harness"
grep -q 'trap cleanup EXIT INT TERM' "$harness"
grep -q 'frame_probe.py' "$harness"
grep -q -- '--secure-mode' "$harness"
grep -q 'SKIP_IMAGE_BUILD' "$harness"
grep -q 'LOWTIER_L2_TEST_SCOPE' "$harness"
grep -q 'did not create' "$harness"
grep -q 'result}' "$harness"
grep -q 'unknown-ethertype' "$harness"
grep -q 'vlan-8021q' "$harness"
grep -q 'qinq-8021ad' "$harness"
grep -q 'lldp-multicast' "$harness"
grep -q 'broadcast' "$harness"
grep -q 'known-unicast' "$harness"
grep -q 'unknown-unicast' "$harness"
grep -q 'mac-move' "$harness"
grep -q 'mtu-boundary' "$harness"
grep -q 'oversized-frame' "$harness"
grep -q '/sys/class/net/et0/mtu' "$harness"
grep -q 'python3' "$dockerfile"
grep -q 'traffic_signature_scan.py' "$dockerfile"

python3 -m py_compile "$probe"
python3 "$repo_root/script/tests/frame_probe_test.py"
python3 "$repo_root/script/tests/traffic_signature_scan_test.py"
bash -n "$harness"

echo "Colima L2 static tests passed"
