#!/usr/bin/env bash
set -euo pipefail

# This harness measures work and traffic for each selected data-plane path.
# Build the image before this script and reuse the same image for every case.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
docker_context=${COLIMA_DOCKER_CONTEXT:-colima-lowertier-l2}
image_name=${LOWTIER_L2_IMAGE:-lowertier-l2-qemu-test:local}
duration=${LOWTIER_L2_IPERF_DURATION:-10}
udp_rate=${LOWTIER_L2_UDP_RATE:-500M}
queue_matrix=${LOWTIER_L2_QUEUE_MATRIX:-${LOWTIER_TUN_QUEUE_MATRIX:-1,2,4}}
scenario_matrix=${LOWTIER_L2_SCENARIOS:-direct-underlay,automatic-compact-l3,authorized-full-ethernet,relay-compact-l3}
result_dir=${LOWTIER_L2_RESULT_DIR:-$(mktemp -d -t lowertier-l2-benchmark.XXXXXX)}

network_name=lowertier-l2-benchmark-net
node_a=lowertier-l2-benchmark-a
node_b=lowertier-l2-benchmark-b
node_relay=lowertier-l2-benchmark-relay
underlay_a=172.31.77.2
underlay_b=172.31.77.3
overlay_a=10.88.0.1
overlay_b=10.88.0.2
docker_cmd=(docker --context "$docker_context")
cases_file="$result_dir/cases.tsv"

if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]]; then
    echo "LOWTIER_L2_IPERF_DURATION must be a positive integer" >&2
    exit 2
fi

mkdir -p "$result_dir"

IFS=',' read -r -a queue_counts <<< "$queue_matrix"
if [[ "${#queue_counts[@]}" -eq 0 ]]; then
    echo "LOWTIER_L2_QUEUE_MATRIX must contain at least one queue count" >&2
    exit 2
fi
for queue_count in "${queue_counts[@]}"; do
    if ! [[ "$queue_count" =~ ^[1-4]$ ]]; then
        echo "queue count must be one, two, three, or four: $queue_count" >&2
        exit 2
    fi
done

IFS=',' read -r -a scenarios <<< "$scenario_matrix"
for scenario in "${scenarios[@]}"; do
    case "$scenario" in
        direct-underlay|automatic-compact-l3|authorized-full-ethernet|relay-compact-l3)
            ;;
        *)
            echo "unsupported benchmark scenario: $scenario" >&2
            exit 2
            ;;
    esac
done

printf '%s\n' \
    'case_id\tscenario\tmode\tqueue_count\tprotocol\tdirection\tstreams\toffered_rate\twall_time_ms\tiperf_json\tresource_a\tresource_b' \
    >"$cases_file"

now_ms() {
    python3 -c 'import time; print(time.time_ns() // 1_000_000)'
}

cleanup() {
    "${docker_cmd[@]}" rm -f "$node_a" "$node_b" "$node_relay" >/dev/null 2>&1 || true
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
    "${docker_cmd[@]}" exec "$node" cat /tmp/lowertier.log >&2 || true
    return 1
}

wait_for_ping() {
    local node=$1
    local destination=$2
    local attempt
    for attempt in $(seq 1 30); do
        if "${docker_cmd[@]}" exec "$node" ping -n -c 1 -W 2 "$destination" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    "${docker_cmd[@]}" exec "$node" cat /tmp/lowertier.log >&2 || true
    return 1
}

start_container() {
    local node=$1
    local underlay_ip=$2
    "${docker_cmd[@]}" run -d --name "$node" --network "$network_name" \
        --ip "$underlay_ip" --cap-add NET_ADMIN --device /dev/net/tun \
        "$image_name" sleep infinity >/dev/null
}

start_core() {
    local node=$1
    local port_mode=$2
    local overlay_ip=${3:-}
    local peer_url=${4:-}
    local disable_p2p=${5:-false}
    local no_tun=${6:-false}
    local relay_node=${7:-false}
    local args=(
        lowertier-core
        --network-name l2-benchmark
        --network-secret l2-benchmark-secret
        --port-mode "$port_mode"
        --listeners udp://0.0.0.0:11010
        --disable-upnp true
        --disable-p2p "$disable_p2p"
    )
    if [[ -n "$overlay_ip" ]]; then
        args+=(--dev-name et0 --ipv4 "$overlay_ip/24")
    fi
    if [[ "$no_tun" == true ]]; then
        args+=(--no-tun true)
    fi
    if [[ "$relay_node" == true ]]; then
        args+=(--relay-network-whitelist l2-benchmark)
    fi
    if [[ -n "$peer_url" ]]; then
        args+=(--peers "$peer_url")
    fi
    "${docker_cmd[@]}" exec -d "$node" \
        sh -c 'export LOWTIER_TUN_QUEUES="$1"; shift; exec "$@" >/tmp/lowertier.log 2>&1' \
        sh "$queue_count" "${args[@]}"
}

start_resource_sampler() {
    local node=$1
    local case_id=$2
    local resource_file="/tmp/lowertier-${case_id}-resources.tsv"
    local done_file="/tmp/lowertier-${case_id}-resources.done"
    local stop_file="/tmp/lowertier-${case_id}-resources.stop"
    "${docker_cmd[@]}" exec "$node" rm -f "$resource_file" "$done_file" "$stop_file"
    "${docker_cmd[@]}" exec -d "$node" sh -c '
resource_file=$1
done_file=$2
stop_file=$3
sample=0
previous_cpu=0
previous_time=0

cgroup_cpu_usec() {
    if [ -r /sys/fs/cgroup/cpu.stat ]; then
        awk "\$1 == \"usage_usec\" {print \$2; exit}" /sys/fs/cgroup/cpu.stat
    elif [ -r /sys/fs/cgroup/cpuacct/cpuacct.usage ]; then
        awk "{print int(\$1 / 1000)}" /sys/fs/cgroup/cpuacct/cpuacct.usage
    else
        printf "0"
    fi
}

process_rss_kib() {
    awk "/^VmRSS:/ {rss += \$2} END {print rss + 0}" /proc/[0-9]*/status 2>/dev/null || printf "0"
}

process_threads() {
    awk "/^Threads:/ {threads += \$2} END {print threads + 0}" /proc/[0-9]*/status 2>/dev/null || printf "0"
}

interface_stats() {
    awk -v interface_name=eth0 "\$1 == interface_name \":\" {print \$2, \$3, \$10, \$11; exit}" /proc/net/dev
}

: >"$resource_file"
printf "sample\tepoch_ms\tcpu_pct\trss_kib\tthreads\trx_bytes\ttx_bytes\trx_packets\ttx_packets\n" >"$resource_file"
while [ ! -f "$stop_file" ]; do
    now=$(date +%s%3N)
    cpu=$(cgroup_cpu_usec)
    if [ "$previous_time" -gt 0 ] && [ "$cpu" -ge "$previous_cpu" ]; then
        elapsed=$((now - previous_time))
        cpu_delta=$((cpu - previous_cpu))
        if [ "$elapsed" -gt 0 ]; then
            cpu_pct=$(awk -v delta="$cpu_delta" -v elapsed="$elapsed" "BEGIN {printf \"%.6f\", delta / (elapsed * 1000.0) * 100.0}")
        else
            cpu_pct=0
        fi
    else
        cpu_pct=0
    fi
    read -r rx_bytes rx_packets tx_bytes tx_packets <<EOF
$(interface_stats)
EOF
    rx_bytes=${rx_bytes:-0}
    rx_packets=${rx_packets:-0}
    tx_bytes=${tx_bytes:-0}
    tx_packets=${tx_packets:-0}
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$sample" "$now" "$cpu_pct" "$(process_rss_kib)" "$(process_threads)" \
        "$rx_bytes" "$tx_bytes" "$rx_packets" "$tx_packets" >>"$resource_file"
    sample=$((sample + 1))
    previous_cpu=$cpu
    previous_time=$now
    sleep 0.2
done
touch "$done_file"
' sh "$resource_file" "$done_file" "$stop_file"
}

stop_resource_sampler() {
    local node=$1
    local case_id=$2
    local local_file=$3
    local resource_file="/tmp/lowertier-${case_id}-resources.tsv"
    local done_file="/tmp/lowertier-${case_id}-resources.done"
    local stop_file="/tmp/lowertier-${case_id}-resources.stop"
    local attempt

    "${docker_cmd[@]}" exec "$node" touch "$stop_file"
    for attempt in $(seq 1 100); do
        if "${docker_cmd[@]}" exec "$node" test -f "$done_file"; then
            break
        fi
        sleep 0.1
    done
    "${docker_cmd[@]}" cp "$node:$resource_file" "$local_file"
}

start_iperf_server() {
    "${docker_cmd[@]}" exec -d "$node_b" iperf3 -s -D -p 5201
    sleep 1
}

run_iperf_case() {
    local scenario=$1
    local mode=$2
    local queue_count=$3
    local target_ip=$4
    local protocol=$5
    local direction=$6
    local streams=$7
    local case_id="${scenario}-q${queue_count}-${protocol}-${direction}-s${streams}"
    local iperf_json="$result_dir/${case_id}.iperf.json"
    local iperf_stderr="$result_dir/${case_id}.iperf.stderr"
    local resource_a="$result_dir/${case_id}.a.resources.tsv"
    local resource_b="$result_dir/${case_id}.b.resources.tsv"
    local started_ms
    local finished_ms
    local wall_time_ms
    local offered_rate=0
    local -a iperf_args

    if [[ "$protocol" == tcp ]]; then
        iperf_args=(iperf3 -c "$target_ip" -p 5201 -t "$duration" -O 1 -P "$streams" -J)
    else
        iperf_args=(iperf3 -u -b "$udp_rate" -c "$target_ip" -p 5201 -t "$duration" -O 1 -P "$streams" -J)
        offered_rate="$udp_rate"
    fi
    if [[ "$direction" == reverse ]]; then
        iperf_args+=(-R)
    fi

    start_resource_sampler "$node_a" "$case_id"
    start_resource_sampler "$node_b" "$case_id"
    started_ms=$(now_ms)
    if ! "${docker_cmd[@]}" exec "$node_a" "${iperf_args[@]}" \
        >"$iperf_json" 2>"$iperf_stderr"; then
        stop_resource_sampler "$node_a" "$case_id" "$resource_a" || true
        stop_resource_sampler "$node_b" "$case_id" "$resource_b" || true
        echo "iperf3 failed for $case_id; see $iperf_stderr" >&2
        return 1
    fi
    finished_ms=$(now_ms)
    wall_time_ms=$((finished_ms - started_ms))
    stop_resource_sampler "$node_a" "$case_id" "$resource_a"
    stop_resource_sampler "$node_b" "$case_id" "$resource_b"

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$case_id" "$scenario" "$mode" "$queue_count" "$protocol" "$direction" \
        "$streams" "$offered_rate" "$wall_time_ms" "${iperf_json#$result_dir/}" \
        "${resource_a#$result_dir/}" "${resource_b#$result_dir/}" >>"$cases_file"
}

run_case_matrix() {
    local scenario=$1
    local mode=$2
    local queue_count=$3
    local target_ip=$4
    local streams
    local direction

    for streams in 1 8; do
        for direction in forward reverse; do
            run_iperf_case "$scenario" "$mode" "$queue_count" "$target_ip" \
                tcp "$direction" "$streams"
        done
    done
    for direction in forward reverse; do
        run_iperf_case "$scenario" "$mode" "$queue_count" "$target_ip" \
            udp "$direction" 1
    done
}

run_scenario() {
    local scenario=$1
    local queue_count=$2
    local mode
    local topology
    local target_ip

    case "$scenario" in
        direct-underlay)
            mode=underlay
            topology=direct
            target_ip="$underlay_b"
            ;;
        automatic-compact-l3)
            mode=auto
            topology=direct
            target_ip="$overlay_b"
            ;;
        authorized-full-ethernet)
            mode=ethernet
            topology=direct
            target_ip="$overlay_b"
            ;;
        relay-compact-l3)
            mode=auto
            topology=relay
            target_ip="$overlay_b"
            ;;
    esac

    echo "Benchmark scenario=$scenario queue_count=$queue_count"
    cleanup
    "${docker_cmd[@]}" network create --driver bridge --subnet 172.31.77.0/24 \
        "$network_name" >/dev/null
    start_container "$node_a" "$underlay_a"
    start_container "$node_b" "$underlay_b"

    if [[ "$topology" == relay ]]; then
        start_container "$node_relay" 172.31.77.4
        start_core "$node_relay" routed "" "" false true true
        start_core "$node_a" "$mode" "$overlay_a" "udp://$node_relay:11010" true
        start_core "$node_b" "$mode" "$overlay_b" "udp://$node_relay:11010" true
    elif [[ "$scenario" != direct-underlay ]]; then
        start_core "$node_a" "$mode" "$overlay_a"
        start_core "$node_b" "$mode" "$overlay_b" "udp://$node_a:11010"
    fi

    if [[ "$scenario" != direct-underlay ]]; then
        wait_for_interface "$node_a"
        wait_for_interface "$node_b"
        wait_for_ping "$node_a" "$overlay_b"
        wait_for_ping "$node_b" "$overlay_a"
        if [[ "$scenario" == authorized-full-ethernet ]]; then
            "${docker_cmd[@]}" exec "$node_a" ip -d link show et0 | grep -q tap
            "${docker_cmd[@]}" exec "$node_b" ip -d link show et0 | grep -q tap
        fi
    fi
    start_iperf_server
    run_case_matrix "$scenario" "$mode" "$queue_count" "$target_ip"
}

trap cleanup EXIT INT TERM

for queue_count in "${queue_counts[@]}"; do
    for scenario in "${scenarios[@]}"; do
        run_scenario "$scenario" "$queue_count"
    done
done

python3 "$repo_root/script/colima-l2/benchmark_report.py" "$result_dir"
cat "$result_dir/results.tsv"
printf "secure_mode=mandatory\ndocker_context=%s\nimage=%s\nduration_seconds=%s\nqueue_matrix=%s\n" \
    "$docker_context" "$image_name" "$duration" "$queue_matrix" >"$result_dir/environment.txt"
echo "Results: $result_dir"
