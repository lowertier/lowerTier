#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
benchmark="$repo_root/script/colima-l2/benchmark.sh"
report="$repo_root/script/colima-l2/benchmark_report.py"

test -f "$benchmark"
test -f "$report"
grep -q '^set -euo pipefail$' "$benchmark"
! grep -q 'LOWTIER_L2_SECURE_MODE' "$benchmark"
grep -q 'direct-underlay' "$benchmark"
grep -q 'automatic-compact-l3' "$benchmark"
grep -q 'authorized-full-ethernet' "$benchmark"
grep -q 'relay-compact-l3' "$benchmark"
grep -q 'LOWTIER_L2_QUEUE_MATRIX' "$benchmark"
grep -q 'LOWTIER_TUN_QUEUES' "$benchmark"
grep -q 'LOWTIER_L2_UDP_RATE' "$benchmark"
grep -q 'for streams in 1 8' "$benchmark"
grep -q 'for direction in forward reverse' "$benchmark"
grep -q 'results.tsv' "$report"
grep -q 'results.json' "$report"
grep -q 'summary.tsv' "$report"
grep -q 'VmRSS' "$benchmark"
grep -q 'Threads' "$benchmark"
grep -q 'rx_packets' "$benchmark"
grep -q 'tx_bytes' "$benchmark"
grep -q 'endpoint_a_cpu_pct' "$report"
grep -q 'endpoint_a_peak_rss_kib' "$report"
grep -q 'endpoint_a_peak_threads' "$report"
grep -q 'endpoint_a_packets' "$report"
grep -q 'endpoint_a_bytes' "$report"
! grep -q -- '--secure-mode' "$benchmark"
bash -n "$benchmark"
python3 - "$report" <<'PY'
import ast
import pathlib
import sys

ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY

echo "Colima L2 benchmark static tests passed"
