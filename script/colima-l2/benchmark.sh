#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
docker_context=${COLIMA_DOCKER_CONTEXT:-colima-easytier-l2}
image_name=${EASYTIER_L2_IMAGE:-easytier-l2-qemu-test:local}
secure_mode=${EASYTIER_L2_SECURE_MODE:-1}
ping_count=${EASYTIER_L2_PING_COUNT:-1000}
duration=${EASYTIER_L2_IPERF_DURATION:-10}
result_dir=${EASYTIER_L2_RESULT_DIR:-$(mktemp -d -t easytier-l2-benchmark.XXXXXX)}
network_name=easytier-l2-benchmark-net
node_a=easytier-l2-benchmark-a
node_b=easytier-l2-benchmark-b
docker_cmd=(docker --context "$docker_context")

cleanup() {
    "${docker_cmd[@]}" rm -f "$node_a" "$node_b" >/dev/null 2>&1 || true
    "${docker_cmd[@]}" network rm "$network_name" >/dev/null 2>&1 || true
}

wait_for_interface() {
    local node=$1
    local attempt
    for attempt in $(seq 1 60); do
        if "${docker_cmd[@]}" exec "$node" ip link show et0 >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    "${docker_cmd[@]}" exec "$node" cat /tmp/easytier.log >&2 || true
    return 1
}

wait_for_ping() {
    local destination=$1
    local attempt
    for attempt in $(seq 1 30); do
        if "${docker_cmd[@]}" exec "$node_a" ping -n -c 1 -W 1 "$destination" \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

start_resource_sampler() {
    local node=$1
    local sample_count=$((duration + 1))
    "${docker_cmd[@]}" exec -d "$node" sh -c '
output=$1
done_file=$2
sample_count=$3
node_name=$4
pid=$(pidof easytier-core | cut -d " " -f 1)
: >"$output"
rm -f "$done_file"
for sample in $(seq 1 "$sample_count"); do
    rss=$(sed -n "s/^VmRSS:[[:space:]]*\\([0-9]*\\).*/\\1/p" "/proc/$pid/status")
    threads=$(sed -n "s/^Threads:[[:space:]]*\\([0-9]*\\).*/\\1/p" "/proc/$pid/status")
    if [ -n "$rss" ] && [ -n "$threads" ]; then
        printf "%s\t%s\t%s\t%s\n" "$sample" "$node_name" "$rss" "$threads" >>"$output"
    fi
    sleep 1
done
touch "$done_file"
' sh /tmp/easytier-resource-samples.tsv /tmp/easytier-resource-done \
        "$sample_count" "$node"
}

collect_resource_samples() {
    local output=$1
    local node
    local attempt

    printf 'sample\tnode\trss_kib\tthreads\n' >"$output"
    for node in "$node_a" "$node_b"; do
        for attempt in $(seq 1 $((duration + 20))); do
            if "${docker_cmd[@]}" exec "$node" \
                test -f /tmp/easytier-resource-done; then
                break
            fi
            sleep 1
        done
        "${docker_cmd[@]}" exec "$node" \
            cat /tmp/easytier-resource-samples.tsv >>"$output"
    done
}

start_core() {
    local node=$1
    local overlay_ip=$2
    local peer_url=${3:-}
    local args=(
        easytier-core
        --network-name l2-benchmark
        --network-secret l2-benchmark-secret
        --port-mode tap
        --dev-name et0
        --ipv4 "$overlay_ip/24"
        --listeners udp://0.0.0.0:11010
        --disable-upnp true
    )
    if [[ "$secure_mode" == 1 ]]; then
        args+=(--secure-mode)
    fi
    if [[ -n "$peer_url" ]]; then
        args+=(--peers "$peer_url")
    fi
    "${docker_cmd[@]}" exec -d "$node" \
        sh -c 'exec "$@" >/tmp/easytier.log 2>&1' sh "${args[@]}"
}

trap cleanup EXIT INT TERM
mkdir -p "$result_dir"
cleanup
"${docker_cmd[@]}" network create --driver bridge --subnet 172.31.77.0/24 \
    "$network_name" >/dev/null

"${docker_cmd[@]}" run -d --name "$node_a" --network "$network_name" \
    --ip 172.31.77.2 --cap-add NET_ADMIN --device /dev/net/tun \
    "$image_name" sleep infinity >/dev/null
"${docker_cmd[@]}" run -d --name "$node_b" --network "$network_name" \
    --ip 172.31.77.3 --cap-add NET_ADMIN --device /dev/net/tun \
    "$image_name" sleep infinity >/dev/null

start_core "$node_a" 10.88.0.1
start_core "$node_b" 10.88.0.2 "udp://$node_a:11010"
wait_for_interface "$node_a"
wait_for_interface "$node_b"
wait_for_ping 10.88.0.2

"${docker_cmd[@]}" exec "$node_a" ping -n -c "$ping_count" -i 0.01 172.31.77.3 \
    >"$result_dir/direct-underlay-ping.txt"
"${docker_cmd[@]}" exec -d "$node_b" python3 /usr/local/bin/traffic_signature_scan.py \
    capture --interface eth0 --udp-port 11010 --count 128 --timeout 20 \
    --output /tmp/steady-state-traffic.hex
sleep 0.2
"${docker_cmd[@]}" exec "$node_a" ping -n -c "$ping_count" -i 0.01 10.88.0.2 \
    >"$result_dir/overlay-tap-ping.txt"

for attempt in $(seq 1 100); do
    if "${docker_cmd[@]}" exec "$node_b" test -f /tmp/steady-state-traffic.hex; then
        break
    fi
    sleep 0.1
done
"${docker_cmd[@]}" cp "$node_b:/tmp/steady-state-traffic.hex" \
    "$result_dir/steady-state-traffic.hex"
python3 "$repo_root/script/traffic_signature_scan.py" scan \
    --input "$result_dir/steady-state-traffic.hex" \
    --output "$result_dir/steady-state-signature.json" \
    --strip-bytes 8 \
    --forbid easytier \
    --forbid l2-benchmark \
    --forbid l2-benchmark-secret \
    --forbid ETL1 \
    --max-common-edge 0

"${docker_cmd[@]}" exec "$node_b" iperf3 -s -D -p 5201
"${docker_cmd[@]}" exec "$node_a" iperf3 -c 172.31.77.3 -p 5201 \
    -t "$duration" -O 1 -P 4 -J >"$result_dir/direct-underlay-iperf.json"
start_resource_sampler "$node_a"
start_resource_sampler "$node_b"
"${docker_cmd[@]}" exec "$node_a" iperf3 -c 10.88.0.2 -p 5201 \
    -t "$duration" -O 1 -P 4 -J >"$result_dir/overlay-tap-iperf.json"
collect_resource_samples "$result_dir/resource-samples.tsv"

python3 - "$result_dir" "$secure_mode" <<'PY'
from __future__ import annotations

import json
import math
import re
import statistics
import sys
from pathlib import Path


result_dir = Path(sys.argv[1])
secure_mode = sys.argv[2]


def ping_samples(path: Path) -> list[float]:
    samples = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.search(r"time[=<]([0-9.]+) ms", line)
        if match:
            samples.append(float(match.group(1)))
    if not samples:
        raise RuntimeError(f"no ping samples in {path}")
    return sorted(samples)


def percentile(samples: list[float], value: float) -> float:
    index = max(0, math.ceil(len(samples) * value) - 1)
    return samples[index]


def throughput(path: Path) -> float:
    data = json.loads(path.read_text(encoding="utf-8"))
    return float(data["end"]["sum_received"]["bits_per_second"])


direct = ping_samples(result_dir / "direct-underlay-ping.txt")
overlay = ping_samples(result_dir / "overlay-tap-ping.txt")
direct_bps = throughput(result_dir / "direct-underlay-iperf.json")
overlay_bps = throughput(result_dir / "overlay-tap-iperf.json")

rows = [("sample_count", len(direct), len(overlay), len(overlay) - len(direct))]
for name, function in (
    ("median_rtt_ms", statistics.median),
    ("p95_rtt_ms", lambda values: percentile(values, 0.95)),
    ("p99_rtt_ms", lambda values: percentile(values, 0.99)),
    ("maximum_rtt_ms", max),
):
    direct_value = function(direct)
    overlay_value = function(overlay)
    rows.append((name, direct_value, overlay_value, overlay_value - direct_value))
rows.append(("throughput_bps", direct_bps, overlay_bps, overlay_bps - direct_bps))
rows.append(("throughput_ratio", 1.0, overlay_bps / direct_bps, overlay_bps / direct_bps - 1.0))

with (result_dir / "summary.tsv").open("w", encoding="utf-8") as output:
    output.write("metric\tdirect-underlay\toverlay-tap\toverlay-difference\n")
    for row in rows:
        output.write("\t".join(str(value) for value in row) + "\n")

(result_dir / "environment.txt").write_text(
    f"secure_mode={secure_mode}\n", encoding="utf-8"
)

resource_rows = []
for line in (result_dir / "resource-samples.tsv").read_text(encoding="utf-8").splitlines()[1:]:
    sample, node, rss_kib, threads = line.split("\t")
    resource_rows.append((int(sample), node, int(rss_kib), int(threads)))

with (result_dir / "resources.tsv").open("w", encoding="utf-8") as output:
    output.write("node\tsample_count\tmean_rss_kib\tpeak_rss_kib\tmean_threads\tpeak_threads\n")
    for node in sorted({row[1] for row in resource_rows}):
        node_rows = [row for row in resource_rows if row[1] == node]
        rss_values = [row[2] for row in node_rows]
        thread_values = [row[3] for row in node_rows]
        output.write(
            f"{node}\t{len(node_rows)}\t{statistics.mean(rss_values):.2f}\t{max(rss_values)}\t"
            f"{statistics.mean(thread_values):.2f}\t{max(thread_values)}\n"
        )
PY

cat "$result_dir/summary.tsv"
cat "$result_dir/resources.tsv"
echo "Results: $result_dir"
