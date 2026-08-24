#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$repo_root/script/throughput-common.sh"

colima_profile=${COLIMA_PROFILE:-easytier-l2}
docker_context=${DOCKER_CONTEXT:-colima-easytier-l2}
image=${WIREGUARD_TEST_IMAGE:-lowertier-kernel-wireguard-bench:tmp}
network=${LOWTIER_KERNEL_WG_NETWORK:-lowertier-kernel-wireguard-net}
node_a=${LOWTIER_KERNEL_WG_NODE_A:-lowertier-kernel-wireguard-a}
node_b=${LOWTIER_KERNEL_WG_NODE_B:-lowertier-kernel-wireguard-b}
result_dir=${RESULT_DIR:-$(mktemp -d -t lowertier-kernel-wireguard-bench.XXXXXX)}
duration=${DURATION:-10}
omit=${OMIT:-2}
runs=${RUNS:-3}
cpu_duration=${CPU_DURATION:-10}
stream_counts_text=${STREAM_COUNTS:-"1 4"}
mtu=${MTU:-1360}
raw_gate_bps=${RAW_GATE_BPS:-12000000000}
build_image=${BUILD_IMAGE:-1}
run_cpu_probe=${RUN_CPU_PROBE:-1}
iperf_timeout_seconds=${IPERF_TIMEOUT_SECONDS:-$((duration + omit + 15))}
dockerfile="$repo_root/script/wireguard-macos-bench/Dockerfile"
docker_cmd=(docker --context "$docker_context")
containers=("$node_a" "$node_b")

cleanup() {
    local node
    mkdir -p "$result_dir/logs"
    for node in "${containers[@]}"; do
        "${docker_cmd[@]}" logs "$node" >"$result_dir/logs/${node}.log" 2>&1 || true
    done
    "${docker_cmd[@]}" rm -f "${containers[@]}" >/dev/null 2>&1 || true
    "${docker_cmd[@]}" network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

start_iperf_server() {
    local port=$1
    "${docker_cmd[@]}" exec "$node_b" sh -lc \
        "pkill iperf3 2>/dev/null || true; iperf3 -s -D -p $port"
}

run_iperf() {
    local mode=$1
    local direction=$2
    local streams=$3
    local destination=$4
    local port=$5
    local run=$6
    local output=$7
    local reverse_flag=
    local parsed
    local error

    if [[ "$direction" == reverse ]]; then
        reverse_flag=-R
    fi
    start_iperf_server "$port"
    "${docker_cmd[@]}" exec "$node_a" timeout "$iperf_timeout_seconds" \
        iperf3 -c "$destination" -p "$port" -t "$duration" -O "$omit" \
        -P "$streams" $reverse_flag -J >"$output" || true
    if parsed=$(perf_parse_iperf_json "$direction" "$run" "$output"); then
        printf '%s\t%s\n' "$mode" "$parsed" >>"$result_dir/throughput.tsv"
        return 0
    fi
    error=$(jq -r '.error // "iperf result was incomplete"' "$output" 2>/dev/null \
        || printf 'iperf result was not valid JSON')
    printf '%s\t%s\t%s\ttcp\t%s\t%s\n' \
        "$mode" "$direction" "$run" "$streams" "$error" \
        >>"$result_dir/workload-errors.tsv"
    return 1
}

vm_cpu_snapshot() {
    colima -p "$colima_profile" ssh -- sh -lc \
        "awk 'NR == 1 { total = 0; for (field = 2; field <= NF; field++) total += \$field; idle = \$5 + \$6; print total, idle }' /proc/stat"
}

record_vm_cpu_probe() {
    local direction=$1
    local streams=$2
    local reverse_flag=
    local output="$result_dir/cpu/${direction}-p${streams}.json"
    local total_before idle_before total_after idle_after
    local iperf_pid received total_delta idle_delta busy_cores cores_per_gbit

    if [[ "$direction" == reverse ]]; then
        reverse_flag=-R
    fi
    start_iperf_server 5201
    "${docker_cmd[@]}" exec "$node_a" timeout "$iperf_timeout_seconds" \
        iperf3 -c 10.202.1.2 -p 5201 -t "$cpu_duration" -O "$omit" \
        -P "$streams" $reverse_flag -J >"$output" &
    iperf_pid=$!
    sleep "$omit"
    read -r total_before idle_before < <(vm_cpu_snapshot)
    wait "$iperf_pid"
    read -r total_after idle_after < <(vm_cpu_snapshot)

    received=$(jq -er '.end.sum_received.bits_per_second | numbers' "$output")
    total_delta=$((total_after - total_before))
    idle_delta=$((idle_after - idle_before))
    busy_cores=$(awk -v total="$total_delta" -v idle="$idle_delta" -v cpus="$vm_vcpus" \
        'BEGIN { if (total <= 0) print "nan"; else printf "%.6f", cpus * (total - idle) / total }')
    cores_per_gbit=$(awk -v cores="$busy_cores" -v bps="$received" \
        'BEGIN { if (bps <= 0) print "nan"; else printf "%.6f", cores / (bps / 1000000000) }')
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$direction" "$streams" "$received" "$busy_cores" "$cores_per_gbit" \
        >>"$result_dir/vm-cpu-cores-per-gbit.tsv"
}

read -r -a stream_counts <<<"$stream_counts_text"
if ((${#stream_counts[@]} == 0)); then
    echo "STREAM_COUNTS must contain at least one positive integer" >&2
    exit 64
fi
max_streams=0
for streams in "${stream_counts[@]}"; do
    if ! [[ "$streams" =~ ^[1-9][0-9]*$ ]]; then
        echo "STREAM_COUNTS must contain positive integers" >&2
        exit 64
    fi
    if ((streams > max_streams)); then
        max_streams=$streams
    fi
done

mkdir -p "$result_dir/raw" "$result_dir/wireguard" "$result_dir/cpu" "$result_dir/logs"
perf_write_metadata "$result_dir" "kernel-wireguard:$docker_context"
printf 'colima_profile=%s\ndocker_context=%s\nimage=%s\nstream_counts=%s\nmtu=%s\nraw_gate_bps=%s\n' \
    "$colima_profile" "$docker_context" "$image" "$stream_counts_text" "$mtu" "$raw_gate_bps" \
    >>"$result_dir/environment.txt"

colima -p "$colima_profile" status
"${docker_cmd[@]}" info >/dev/null
if [[ "$build_image" == 1 ]]; then
    "${docker_cmd[@]}" build -q -f "$dockerfile" -t "$image" \
        "$repo_root/script/wireguard-macos-bench" >/dev/null
fi

cleanup
"${docker_cmd[@]}" network create --driver bridge --subnet 172.30.12.0/24 \
    --opt com.docker.network.driver.mtu=9000 "$network" >/dev/null
"${docker_cmd[@]}" run -d --name "$node_a" --network "$network" --ip 172.30.12.2 \
    --privileged "$image" >/dev/null
"${docker_cmd[@]}" run -d --name "$node_b" --network "$network" --ip 172.30.12.3 \
    --privileged "$image" >/dev/null

perf_result_header | awk '{print "mode\t" $0}' >"$result_dir/throughput.tsv"
printf 'mode\tdirection\trun\tprotocol\tstreams\terror\n' >"$result_dir/workload-errors.tsv"
printf 'direction\tstreams\treceived_bps\tvm_busy_cores\tvm_cores_per_gbit\n' \
    >"$result_dir/vm-cpu-cores-per-gbit.tsv"

start_iperf_server 5200
for streams in "${stream_counts[@]}"; do
    run_iperf raw forward "$streams" 172.30.12.3 5200 1 \
        "$result_dir/raw/forward-p${streams}.json" || true
done
raw_bps=$(jq -er '.end.sum_received.bits_per_second | numbers' \
    "$result_dir/raw/forward-p${max_streams}.json")
if awk -v actual="$raw_bps" -v required="$raw_gate_bps" \
    'BEGIN { exit !(actual >= required) }'; then
    printf 'valid\n' >"$result_dir/substrate-status.txt"
else
    printf 'substrate-limited\n' >"$result_dir/substrate-status.txt"
fi

private_a=$("${docker_cmd[@]}" exec "$node_a" wg genkey)
public_a=$(printf '%s\n' "$private_a" | "${docker_cmd[@]}" exec -i "$node_a" wg pubkey)
private_b=$("${docker_cmd[@]}" exec "$node_b" wg genkey)
public_b=$(printf '%s\n' "$private_b" | "${docker_cmd[@]}" exec -i "$node_b" wg pubkey)
printf '%s\n' "$private_a" | "${docker_cmd[@]}" exec -i "$node_a" sh -lc \
    'umask 077; cat >/tmp/wireguard-private-key'
printf '%s\n' "$private_b" | "${docker_cmd[@]}" exec -i "$node_b" sh -lc \
    'umask 077; cat >/tmp/wireguard-private-key'

"${docker_cmd[@]}" exec "$node_a" ip link add wg0 type wireguard
"${docker_cmd[@]}" exec "$node_b" ip link add wg0 type wireguard
"${docker_cmd[@]}" exec "$node_a" wg set wg0 \
    private-key /tmp/wireguard-private-key listen-port 51820 \
    peer "$public_b" allowed-ips 10.202.1.2/32 endpoint 172.30.12.3:51820
"${docker_cmd[@]}" exec "$node_b" wg set wg0 \
    private-key /tmp/wireguard-private-key listen-port 51820 \
    peer "$public_a" allowed-ips 10.202.1.1/32 endpoint 172.30.12.2:51820
"${docker_cmd[@]}" exec "$node_a" rm -f /tmp/wireguard-private-key
"${docker_cmd[@]}" exec "$node_b" rm -f /tmp/wireguard-private-key
"${docker_cmd[@]}" exec "$node_a" ip address add 10.202.1.1/24 dev wg0
"${docker_cmd[@]}" exec "$node_b" ip address add 10.202.1.2/24 dev wg0
"${docker_cmd[@]}" exec "$node_a" ip link set mtu "$mtu" up dev wg0
"${docker_cmd[@]}" exec "$node_b" ip link set mtu "$mtu" up dev wg0

{
    colima -p "$colima_profile" ssh -- uname -a
    colima -p "$colima_profile" ssh -- sh -lc 'grep -w wireguard /proc/modules'
    colima -p "$colima_profile" ssh -- sh -lc 'modinfo wireguard 2>/dev/null || true'
    "${docker_cmd[@]}" exec "$node_a" ip -d link show wg0
    "${docker_cmd[@]}" exec "$node_a" wg show wg0
    "${docker_cmd[@]}" exec "$node_b" ip -d link show wg0
    "${docker_cmd[@]}" exec "$node_b" wg show wg0
} >"$result_dir/kernel-evidence.txt"

if "${docker_cmd[@]}" exec "$node_a" pgrep -f wireguard-go >/dev/null 2>&1 \
    || "${docker_cmd[@]}" exec "$node_b" pgrep -f wireguard-go >/dev/null 2>&1; then
    echo "wireguard-go must not run in the kernel WireGuard benchmark" >&2
    exit 1
fi

for _ in $(seq 1 30); do
    if "${docker_cmd[@]}" exec "$node_a" ping -q -c 1 -W 1 10.202.1.2 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
"${docker_cmd[@]}" exec "$node_a" ping -n -c 100 -i 0.02 10.202.1.2 \
    >"$result_dir/unloaded-latency.txt"

for direction in forward reverse; do
    for run in $(seq 1 "$runs"); do
        for streams in "${stream_counts[@]}"; do
            run_iperf wireguard "$direction" "$streams" 10.202.1.2 5201 "$run" \
                "$result_dir/wireguard/${direction}-p${streams}-r${run}.json" || true
        done
    done
done

vm_vcpus=$(colima -p "$colima_profile" ssh -- nproc)
if [[ "$run_cpu_probe" == 1 ]]; then
    record_vm_cpu_probe forward "$max_streams"
    record_vm_cpu_probe reverse "$max_streams"
fi

echo "results: $result_dir"
