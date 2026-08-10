#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
benchmark="$repo_root/script/colima-l2/benchmark.sh"

test -f "$benchmark"
grep -q '^set -euo pipefail$' "$benchmark"
grep -q 'LOWTIER_L2_SECURE_MODE' "$benchmark"
grep -q 'direct-underlay' "$benchmark"
grep -q 'overlay-tap' "$benchmark"
grep -q 'summary.tsv' "$benchmark"
grep -q 'resources.tsv' "$benchmark"
grep -q 'VmRSS' "$benchmark"
grep -q 'Threads' "$benchmark"
grep -q 'steady-state-signature.json' "$benchmark"
grep -q 'traffic_signature_scan.py' "$benchmark"
grep -q -- '--secure-mode' "$benchmark"
bash -n "$benchmark"

echo "Colima L2 benchmark static tests passed"
