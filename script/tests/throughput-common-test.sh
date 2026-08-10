#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$repo_root/script/throughput-common.sh"

test_dir=$(mktemp -d -t lowertier-throughput-common.XXXXXX)
trap 'rm -rf "$test_dir"' EXIT

cat >"$test_dir/tcp.json" <<'JSON'
{
  "start": {"test_start": {"protocol": "TCP", "num_streams": 8}},
  "end": {
    "sum_sent": {"bits_per_second": 5100000000, "retransmits": 12},
    "sum_received": {"bits_per_second": 5000000000},
    "cpu_utilization_percent": {"host_total": 240.0, "remote_total": 75.0}
  }
}
JSON

cat >"$test_dir/udp.json" <<'JSON'
{
  "start": {"test_start": {"protocol": "UDP", "num_streams": 1, "target_bitrate": 10000000000}},
  "end": {
    "sum_sent": {"bits_per_second": 9990000000},
    "sum_received": {"bits_per_second": 9850000000, "lost_percent": 0.08},
    "cpu_utilization_percent": {"host_total": 120.0, "remote_total": 64.0}
  }
}
JSON

tcp=$(perf_parse_iperf_json forward 1 "$test_dir/tcp.json")
[[ "$tcp" == $'forward\t1\ttcp\t8\t0\t5000000000\t12\t0\t240\t75' ]]

udp=$(perf_parse_iperf_json reverse 2 "$test_dir/udp.json")
[[ "$udp" == $'reverse\t2\tudp\t1\t10000000000\t9850000000\t0\t0.08\t120\t64' ]]

[[ "$(perf_cpu_cores_per_gbit 250 5000000000)" == "0.500000" ]]
[[ "$(perf_cpu_cores_per_gbit 0 5000000000)" == "0.000000" ]]
[[ "$(perf_cpu_cores_per_gbit 100 0)" == "nan" ]]

netstat_counters=$(printf '%s\n' \
    'Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll' \
    'utun70     1360  <Link#42>                          123     0       4567      890     0      12345     0' \
    | perf_parse_netstat_link_counters utun70)
[[ "$netstat_counters" == $'123\t4567\t890\t12345' ]]

printf '{"end": {}}\n' >"$test_dir/bad.json"
if perf_parse_iperf_json forward 3 "$test_dir/bad.json" >/dev/null 2>&1; then
    echo "malformed iperf JSON unexpectedly parsed" >&2
    exit 1
fi

metadata_dir="$test_dir/metadata"
perf_write_metadata "$metadata_dir" "test-context"
test -s "$metadata_dir/environment.txt"
grep -q '^context=test-context$' "$metadata_dir/environment.txt"

echo "throughput common tests passed"
