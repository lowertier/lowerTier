#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
benchmark="$repo_root/script/colima-l2/benchmark.sh"
report="$repo_root/script/colima-l2/benchmark_report.py"

test -f "$benchmark"
test -f "$report"
grep -q '^set -euo pipefail$' "$benchmark"
grep -Fq "printf '%b\\n'" "$benchmark"
! grep -q 'LOWTIER_L2_SECURE_MODE' "$benchmark"
grep -q 'direct-underlay' "$benchmark"
grep -q 'automatic-compact-l3' "$benchmark"
grep -q 'authorized-bridge-compact-l3' "$benchmark"
grep -q 'relay-compact-l3' "$benchmark"
grep -q 'LOWTIER_L2_QUEUE_MATRIX' "$benchmark"
grep -q 'LOWTIER_TUN_QUEUES' "$benchmark"
grep -q 'LOWTIER_L2_UDP_RATE' "$benchmark"
grep -q 'LOWTIER_L2_REPEAT_COUNT' "$benchmark"
grep -q 'LOWTIER_L2_MEMORY_CEILING_KIB' "$benchmark"
grep -q 'for streams in 1 8' "$benchmark"
grep -q 'for direction in forward reverse' "$benchmark"
grep -q 'results.tsv' "$report"
grep -q 'results.json' "$report"
grep -q 'summary.tsv' "$report"
grep -q 'VmRSS' "$benchmark"
grep -q 'VmHWM' "$benchmark"
grep -q 'pidof lowertier-core' "$benchmark"
grep -q '/proc/\$process_pid/status' "$benchmark"
! grep -Fq '/proc/[0-9]*/status' "$benchmark"
grep -q 'Threads' "$benchmark"
grep -q 'rx_packets' "$benchmark"
grep -q 'tx_bytes' "$benchmark"
grep -q '"cpu_pct"' "$report"
grep -q '"peak_rss_kib"' "$report"
grep -q '"process_lifetime_hwm_kib"' "$report"
grep -q 'memory_ceiling_status' "$report"
grep -q 'load_latency_p95_ms' "$report"
grep -q '"peak_threads"' "$report"
grep -q '"rx_packets"' "$report"
grep -q '"tx_packets"' "$report"
grep -q '"rx_bytes"' "$report"
grep -q '"tx_bytes"' "$report"
! grep -q -- '--secure-mode' "$benchmark"
bash -n "$benchmark"
python3 - "$report" <<'PY'
import ast
import pathlib
import sys

ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY

fixture_dir=$(mktemp -d -t lowertier-benchmark-report.XXXXXX)
trap 'rm -rf "$fixture_dir"' EXIT
printf '%b\n' \
    'case_id\tscenario\tmode\tqueue_count\trepeat\tprotocol\tdirection\tstreams\toffered_rate\twindow_start_ms\twindow_end_ms\twall_time_ms\tiperf_json\tidle_latency\tload_latency\tidle_expected\tload_expected\tresource_a\tresource_b\tresource_relay\tmode_stats_a_before\tmode_stats_a_after\tmode_stats_b_before\tmode_stats_b_after\troute_proof' \
    'case-1\tautomatic-compact-l3\tauto\t1\t1\ttcp\tforward\t1\t0\t1050\t1250\t200\tiperf.json\tidle.txt\tload.txt\t3\t3\ta.tsv\tb.tsv\trelay.tsv\ta-before.prom\ta-after.prom\tb-before.prom\tb-after.prom\troute.json' \
    >"$fixture_dir/cases.tsv"
printf '%s\n' \
    '{"scenario":"automatic-compact-l3","forward":{"ipv4":"10.88.0.2/24","path_len":1},"reverse":{"ipv4":"10.88.0.1/24","path_len":1}}' \
    >"$fixture_dir/route.json"
printf '%s\n' '{"end":{"sum_received":{"bits_per_second":1000000}}}' \
    >"$fixture_dir/iperf.json"
printf '%b\n' \
    'sample\tepoch_ms\tprocess_pid\tprocess_start_ticks\tcpu_pct\trss_kib\thwm_kib\trss_anon_kib\trss_file_kib\trss_shmem_kib\tpss_kib\tprivate_clean_kib\tprivate_dirty_kib\tthreads\trx_bytes\ttx_bytes\trx_packets\ttx_packets' \
    '0\t1000\t42\t100\t1\t10000\t10000\t3000\t7000\t0\t5000\t1000\t3000\t2\t0\t0\t0\t0' \
    '1\t1100\t42\t100\t20\t18000\t21000\t4000\t14000\t0\t9000\t1000\t5000\t3\t100\t200\t1\t2' \
    '2\t1200\t42\t100\t40\t19000\t21000\t5000\t14000\t0\t10000\t1000\t6000\t3\t300\t500\t3\t5' \
    >"$fixture_dir/a.tsv"
printf '%b\n' \
    'sample\tepoch_ms\tprocess_pid\tprocess_start_ticks\tcpu_pct\trss_kib\thwm_kib\trss_anon_kib\trss_file_kib\trss_shmem_kib\tpss_kib\tprivate_clean_kib\tprivate_dirty_kib\tthreads\trx_bytes\ttx_bytes\trx_packets\ttx_packets' \
    '0\t1100\t43\t200\t10\t17000\t19000\t4000\t13000\t0\t9000\t1000\t5000\t2\t100\t100\t1\t1' \
    '1\t1200\t43\t200\t20\t18000\t19000\t5000\t13000\t0\t10000\t1000\t6000\t2\t200\t300\t2\t3' \
    >"$fixture_dir/b.tsv"
printf '%b\n' \
    'sample\tepoch_ms\tprocess_pid\tprocess_start_ticks\tcpu_pct\trss_kib\thwm_kib\trss_anon_kib\trss_file_kib\trss_shmem_kib\tpss_kib\tprivate_clean_kib\tprivate_dirty_kib\tthreads\trx_bytes\ttx_bytes\trx_packets\ttx_packets' \
    >"$fixture_dir/relay.tsv"
printf '%s\n' \
    'hybrid_compact_l3_packets_tx 10' \
    'hybrid_full_ethernet_packets_tx 4' \
    >"$fixture_dir/a-before.prom"
printf '%s\n' \
    'hybrid_compact_l3_packets_tx 30' \
    'hybrid_full_ethernet_packets_tx 4' \
    >"$fixture_dir/a-after.prom"
printf '%s\n' \
    'hybrid_compact_l3_packets_tx 5' \
    'hybrid_full_ethernet_packets_tx 2' \
    >"$fixture_dir/b-before.prom"
printf '%s\n' \
    'hybrid_compact_l3_packets_tx 15' \
    'hybrid_full_ethernet_packets_tx 2' \
    >"$fixture_dir/b-after.prom"
printf '%s\n' \
    '[1.000000] 64 bytes from 10.0.0.2: time=1.0 ms' \
    '[1.100000] 64 bytes from 10.0.0.2: time=1.1 ms' \
    '[1.200000] 64 bytes from 10.0.0.2: time=1.2 ms' \
    '3 packets transmitted, 3 received, 0% packet loss' \
    >"$fixture_dir/idle.txt"
printf '%s\n' \
    '[1.000000] 64 bytes from 10.0.0.2: time=9.0 ms' \
    '[1.100000] 64 bytes from 10.0.0.2: time=1.2 ms' \
    '[1.150000] 64 bytes from 10.0.0.2: time=1.8 ms' \
    '[1.200000] 64 bytes from 10.0.0.2: time=2.4 ms' \
    '3 packets transmitted, 3 received, 0% packet loss' \
    >"$fixture_dir/load.txt"

if python3 "$report" "$fixture_dir" 18000 >/dev/null 2>&1; then
    echo "benchmark report did not enforce the memory ceiling" >&2
    exit 1
fi
if python3 "$report" "$fixture_dir" 20000 >/dev/null 2>&1; then
    echo "benchmark report did not enforce process high-water memory" >&2
    exit 1
fi
python3 "$report" "$fixture_dir" 22000 >/dev/null
python3 - "$fixture_dir/results.json" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
case = result["cases"][0]
assert case["memory_ceiling_status"] == "pass"
assert case["route_valid"]
assert case["total_peak_rss_kib"] == 37000
assert case["total_hwm_sum_kib"] == 40000
assert case["endpoint_a_process_lifetime_hwm_kib"] == 21000
assert case["endpoint_a_complete"]
assert case["endpoint_a_rx_packets"] == 2
assert case["endpoint_a_tx_packets"] == 3
assert case["compact_l3_packets"] == 30
assert case["hybrid_full_ethernet_packets"] == 0
assert case["mode_valid"]
assert case["throughput_valid"]
assert case["load_latency_samples"] == 3
assert case["load_latency_p95_ms"] == 2.4
assert not case["relay_sampled"]
assert result["summary"][0]["repeats"] == 1
assert result["summary"][0]["process_lifetime_hwm_max_kib"] == 21000
PY

printf '%s\n' \
    '{"end":{"sum":{"packets":100,"lost_packets":1,"lost_percent":1.0,"jitter_ms":0.2}}}' \
    >"$fixture_dir/udp-valid.json"
printf '%s\n' '{"end":{"sum":{"bits_per_second":1000000}}}' \
    >"$fixture_dir/udp-incomplete.json"
python3 - "$report" "$fixture_dir" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("benchmark_report", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
fixture = pathlib.Path(sys.argv[2])
valid = module.iperf_udp_metrics(fixture / "udp-valid.json")
assert valid["received_packets"] == 99
assert valid["loss_percent"] == 1.0
incomplete = module.iperf_udp_metrics(fixture / "udp-incomplete.json")
assert incomplete["loss_percent"] is None
PY

printf '%s\n' 'ping failed' >"$fixture_dir/load.txt"
if python3 "$report" "$fixture_dir" 20000 >/dev/null 2>&1; then
    echo "benchmark report accepted a failed latency probe" >&2
    exit 1
fi

echo "Colima L2 benchmark static tests passed"
