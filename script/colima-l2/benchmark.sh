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
scenario_matrix=${LOWTIER_L2_SCENARIOS:-direct-underlay,automatic-compact-l3,authorized-bridge-compact-l3,relay-compact-l3}
repeat_count=${LOWTIER_L2_REPEAT_COUNT:-3}
memory_ceiling_kib=${LOWTIER_L2_MEMORY_CEILING_KIB:-20480}
idle_latency_packets=${LOWTIER_L2_IDLE_LATENCY_PACKETS:-40}
result_dir=${LOWTIER_L2_RESULT_DIR:-$(mktemp -d -t lowertier-l2-benchmark.XXXXXX)}

network_a=lowertier-l2-benchmark-net-a
network_b=lowertier-l2-benchmark-net-b
node_a=lowertier-l2-benchmark-a
node_b=lowertier-l2-benchmark-b
node_relay=lowertier-l2-benchmark-relay
underlay_a=172.31.77.2
underlay_b=172.31.77.3
relay_underlay_a=172.31.77.4
relay_underlay_b=172.31.78.4
overlay_a=10.88.0.1
overlay_b=10.88.0.2
docker_cmd=(docker --context "$docker_context")
cases_file="$result_dir/cases.tsv"

if ! [[ "$duration" =~ ^[1-9][0-9]*$ ]]; then
    echo "LOWTIER_L2_IPERF_DURATION must be a positive integer" >&2
    exit 2
fi
if ! [[ "$repeat_count" =~ ^[1-9][0-9]*$ ]]; then
    echo "LOWTIER_L2_REPEAT_COUNT must be a positive integer" >&2
    exit 2
fi
if ! [[ "$memory_ceiling_kib" =~ ^[1-9][0-9]*$ ]]; then
    echo "LOWTIER_L2_MEMORY_CEILING_KIB must be a positive integer" >&2
    exit 2
fi
if ! [[ "$idle_latency_packets" =~ ^[1-9][0-9]*$ ]]; then
    echo "LOWTIER_L2_IDLE_LATENCY_PACKETS must be a positive integer" >&2
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
        direct-underlay|automatic-compact-l3|authorized-bridge-compact-l3|relay-compact-l3)
            ;;
        *)
            echo "unsupported benchmark scenario: $scenario" >&2
            exit 2
            ;;
    esac
done

printf '%b\n' \
    'case_id\tscenario\tmode\tqueue_count\trepeat\tprotocol\tdirection\tstreams\toffered_rate\twindow_start_ms\twindow_end_ms\twall_time_ms\tiperf_json\tidle_latency\tload_latency\tidle_expected\tload_expected\tresource_a\tresource_b\tresource_relay\tmode_stats_a_before\tmode_stats_a_after\tmode_stats_b_before\tmode_stats_b_after\troute_proof' \
    >"$cases_file"

now_ms() {
    python3 -c 'import time; print(time.time_ns() // 1_000_000)'
}

compute_source_digest() {
    python3 "$repo_root/script/colima-l2/source_digest.py" "$repo_root"
}

cleanup() {
    "${docker_cmd[@]}" rm -f "$node_a" "$node_b" "$node_relay" >/dev/null 2>&1 || true
    "${docker_cmd[@]}" network rm "$network_a" "$network_b" >/dev/null 2>&1 || true
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
    local network=$2
    local underlay_ip=$3
    if [[ -n "${LOWTIER_MALLOC_ARENA_MAX:-}" ]]; then
        "${docker_cmd[@]}" run -d --name "$node" --network "$network" \
            --hostname "$node" --ip "$underlay_ip" --cap-add NET_ADMIN --device /dev/net/tun \
            --env "MALLOC_ARENA_MAX=$LOWTIER_MALLOC_ARENA_MAX" \
            "$image_name" sleep infinity >/dev/null
        return
    fi
    "${docker_cmd[@]}" run -d --name "$node" --network "$network" \
        --hostname "$node" --ip "$underlay_ip" --cap-add NET_ADMIN --device /dev/net/tun \
        "$image_name" sleep infinity >/dev/null
}

start_core() {
    local node=$1
    local overlay_ip=${2:-}
    local peer_url=${3:-}
    local disable_p2p=${4:-false}
    local no_tun=${5:-false}
    local relay_node=${6:-false}
    local enable_bridge=${7:-false}
    local args=(
        lowertier-core
        --network-name l2-benchmark
        --network-secret l2-benchmark-secret
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
    if [[ "$enable_bridge" == true ]]; then
        args+=(--enable-bridge true)
    fi
    if [[ -n "$peer_url" ]]; then
        args+=(--peers "$peer_url")
    fi
    "${docker_cmd[@]}" exec -d "$node" \
        sh -c 'export LOWTIER_TUN_QUEUES="$1"; shift; printf "%s\n" "$@" >/tmp/lowertier.args; exec "$@" >/tmp/lowertier.log 2>&1' \
        sh "$queue_count" "${args[@]}"
}

capture_route_proof() {
    local scenario=$1
    local queue_count=$2
    local repeat=$3
    local target_ip=$4
    local proof_file=${5:-"$result_dir/${scenario}-q${queue_count}-r${repeat}.route.json"}
    if [[ "$scenario" == direct-underlay ]]; then
        printf '{"scenario":"direct-underlay","forward_target":"%s","reverse_target":"%s"}\n' \
            "$target_ip" "$underlay_a" \
            >"$proof_file"
        return
    fi

    local routes_a="$result_dir/${scenario}-q${queue_count}-r${repeat}.a.routes.json"
    local routes_b="$result_dir/${scenario}-q${queue_count}-r${repeat}.b.routes.json"
    "${docker_cmd[@]}" exec "$node_a" lowertier-cli -o json route list >"$routes_a"
    "${docker_cmd[@]}" exec "$node_b" lowertier-cli -o json route list >"$routes_b"
    "${docker_cmd[@]}" cp "$node_a:/tmp/lowertier.args" \
        "$result_dir/${scenario}-q${queue_count}-r${repeat}.a.args"
    "${docker_cmd[@]}" cp "$node_b:/tmp/lowertier.args" \
        "$result_dir/${scenario}-q${queue_count}-r${repeat}.b.args"
    if [[ "$scenario" == relay-compact-l3 ]]; then
        "${docker_cmd[@]}" cp "$node_relay:/tmp/lowertier.args" \
            "$result_dir/${scenario}-q${queue_count}-r${repeat}.relay.args"
    fi
    python3 - "$routes_a" "$routes_b" "$proof_file" "$target_ip" "$overlay_a" \
        "$scenario" "$node_relay" <<'PY'
import json
import pathlib
import sys

routes_a = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
routes_b = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
proof_path = pathlib.Path(sys.argv[3])
forward_target = sys.argv[4]
reverse_target = sys.argv[5]
scenario = sys.argv[6]
relay_hostname = sys.argv[7]

def select(rows, target, direction):
    matches = [row for row in rows if row.get("ipv4", "").split("/", 1)[0] == target]
    if len(matches) != 1:
        raise SystemExit(f"{direction} route proof has {len(matches)} rows for {target}")
    route = matches[0]
    path_len = int(route.get("path_len", 0))
    if scenario == "relay-compact-l3":
        if path_len != 2:
            raise SystemExit(f"{direction} relay route has path length {path_len}")
        if route.get("next_hop_hostname") != relay_hostname:
            raise SystemExit(
                f"{direction} relay route uses {route.get('next_hop_hostname')!r}"
            )
    elif path_len != 1:
        raise SystemExit(f"{direction} direct route has path length {path_len}")
    return route

proof = {
    "scenario": scenario,
    "forward": select(routes_a, forward_target, "forward"),
    "reverse": select(routes_b, reverse_target, "reverse"),
}
proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

start_resource_sampler() {
    local node=$1
    local case_id=$2
    local interfaces=${3:-eth0}
    local resource_file="/tmp/lowertier-${case_id}-resources.tsv"
    local done_file="/tmp/lowertier-${case_id}-resources.done"
    local stop_file="/tmp/lowertier-${case_id}-resources.stop"
    local attempt
    "${docker_cmd[@]}" exec "$node" rm -f "$resource_file" "$done_file" "$stop_file"
    "${docker_cmd[@]}" exec -d "$node" sh -c '
resource_file=$1
done_file=$2
stop_file=$3
interfaces=$4
sample=0
previous_cpu=0
previous_time=0
clock_ticks=$(getconf CLK_TCK)
process_pid=$(pidof lowertier-core)
set -- $process_pid
if [ "$#" -ne 1 ]; then
    printf "expected one lowertier-core process, found %s\n" "$#" >&2
    exit 1
fi
process_start_ticks=$(awk "{print \$22}" "/proc/$process_pid/stat")

process_cpu_ticks() {
    awk "{print \$14 + \$15}" "/proc/$process_pid/stat"
}

current_process_start_ticks() {
    awk "{print \$22}" "/proc/$process_pid/stat"
}

process_status() {
    awk "
        /^VmRSS:/ {rss = \$2}
        /^VmHWM:/ {hwm = \$2}
        /^RssAnon:/ {anon = \$2}
        /^RssFile:/ {file = \$2}
        /^RssShmem:/ {shmem = \$2}
        /^Threads:/ {threads = \$2}
        END {print rss + 0, hwm + 0, anon + 0, file + 0, shmem + 0, threads + 0}
    " "/proc/$process_pid/status"
}

process_smaps() {
    awk "
        /^Pss:/ {pss = \$2}
        /^Private_Clean:/ {clean = \$2}
        /^Private_Dirty:/ {dirty = \$2}
        END {print pss + 0, clean + 0, dirty + 0}
    " "/proc/$process_pid/smaps_rollup"
}

interface_stats() {
    awk -v interfaces="$interfaces" "
        BEGIN {count = split(interfaces, names, /[[:space:]]+/); for (i = 1; i <= count; i++) wanted[names[i]] = 1}
        {name = \$1; sub(/:$/, \"\", name)}
        name in wanted {rx_bytes += \$2; rx_packets += \$3; tx_bytes += \$10; tx_packets += \$11}
        END {print rx_bytes + 0, rx_packets + 0, tx_bytes + 0, tx_packets + 0}
    " /proc/net/dev
}

: >"$resource_file"
printf "sample\tepoch_ms\tprocess_pid\tprocess_start_ticks\tcpu_pct\trss_kib\thwm_kib\trss_anon_kib\trss_file_kib\trss_shmem_kib\tpss_kib\tprivate_clean_kib\tprivate_dirty_kib\tthreads\trx_bytes\ttx_bytes\trx_packets\ttx_packets\n" >"$resource_file"
while [ ! -f "$stop_file" ]; do
    now=$(date +%s%3N)
    cpu=$(process_cpu_ticks)
    current_start_ticks=$(current_process_start_ticks)
    if [ "$previous_time" -gt 0 ] && [ "$cpu" -ge "$previous_cpu" ]; then
        elapsed=$((now - previous_time))
        cpu_delta=$((cpu - previous_cpu))
        if [ "$elapsed" -gt 0 ]; then
            cpu_pct=$(awk -v delta="$cpu_delta" -v ticks="$clock_ticks" -v elapsed="$elapsed" "BEGIN {printf \"%.6f\", delta * 100000.0 / (ticks * elapsed)}")
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
    read -r rss_kib hwm_kib rss_anon_kib rss_file_kib rss_shmem_kib threads <<EOF
$(process_status)
EOF
    read -r pss_kib private_clean_kib private_dirty_kib <<EOF
$(process_smaps)
EOF
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$sample" "$now" "$process_pid" "$current_start_ticks" "$cpu_pct" \
        "$rss_kib" "$hwm_kib" "$rss_anon_kib" \
        "$rss_file_kib" "$rss_shmem_kib" "$pss_kib" "$private_clean_kib" \
        "$private_dirty_kib" "$threads" \
        "$rx_bytes" "$tx_bytes" "$rx_packets" "$tx_packets" >>"$resource_file"
    sample=$((sample + 1))
    previous_cpu=$cpu
    previous_time=$now
    sleep 0.2
done
touch "$done_file"
' sh "$resource_file" "$done_file" "$stop_file" "$interfaces"
    for attempt in $(seq 1 50); do
        if "${docker_cmd[@]}" exec "$node" test -s "$resource_file"; then
            return 0
        fi
        sleep 0.1
    done
    echo "resource sampler did not start for $node" >&2
    return 1
}

write_empty_resource_file() {
    local local_file=$1
    printf '%b\n' \
        'sample\tepoch_ms\tprocess_pid\tprocess_start_ticks\tcpu_pct\trss_kib\thwm_kib\trss_anon_kib\trss_file_kib\trss_shmem_kib\tpss_kib\tprivate_clean_kib\tprivate_dirty_kib\tthreads\trx_bytes\ttx_bytes\trx_packets\ttx_packets' \
        >"$local_file"
}

capture_mode_stats() {
    local node=$1
    local local_file=$2
    "${docker_cmd[@]}" exec "$node" lowertier-cli stats prometheus >"$local_file"
}

write_empty_mode_stats() {
    local local_file=$1
    : >"$local_file"
}

run_idle_latency_probe() {
    local node=$1
    local target_ip=$2
    local local_file=$3
    "${docker_cmd[@]}" exec "$node" \
        ping -D -n -c "$idle_latency_packets" -i 0.05 -W 1 "$target_ip" \
        >"$local_file" 2>&1 || true
}

start_load_latency_probe() {
    local node=$1
    local target_ip=$2
    local case_id=$3
    local packet_count=$(((duration + 2) * 20))
    local latency_file="/tmp/lowertier-${case_id}-latency.txt"
    local done_file="/tmp/lowertier-${case_id}-latency.done"
    "${docker_cmd[@]}" exec "$node" rm -f "$latency_file" "$done_file"
    "${docker_cmd[@]}" exec -d "$node" sh -c \
        'ping -D -n -c "$1" -i 0.05 -W 1 "$2" >"$3" 2>&1 || true; touch "$4"' \
        sh "$packet_count" "$target_ip" "$latency_file" "$done_file"
}

finish_load_latency_probe() {
    local node=$1
    local case_id=$2
    local local_file=$3
    local latency_file="/tmp/lowertier-${case_id}-latency.txt"
    local done_file="/tmp/lowertier-${case_id}-latency.done"
    local attempt
    for attempt in $(seq 1 50); do
        if "${docker_cmd[@]}" exec "$node" test -f "$done_file"; then
            "${docker_cmd[@]}" cp "$node:$latency_file" "$local_file"
            return 0
        fi
        sleep 0.1
    done
    echo "latency probe did not complete for $case_id" >&2
    return 1
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
    local repeat=$8
    local sample_core=$9
    local sample_relay=${10}
    local case_id="${scenario}-q${queue_count}-r${repeat}-${protocol}-${direction}-s${streams}"
    local iperf_json="$result_dir/${case_id}.iperf.json"
    local iperf_stderr="$result_dir/${case_id}.iperf.stderr"
    local idle_latency="$result_dir/${case_id}.idle-latency.txt"
    local load_latency="$result_dir/${case_id}.load-latency.txt"
    local resource_a="$result_dir/${case_id}.a.resources.tsv"
    local resource_b="$result_dir/${case_id}.b.resources.tsv"
    local resource_relay="$result_dir/${case_id}.relay.resources.tsv"
    local mode_stats_a_before="$result_dir/${case_id}.a.mode.before.prom"
    local mode_stats_a_after="$result_dir/${case_id}.a.mode.after.prom"
    local mode_stats_b_before="$result_dir/${case_id}.b.mode.before.prom"
    local mode_stats_b_after="$result_dir/${case_id}.b.mode.after.prom"
    local route_proof="$result_dir/${case_id}.route.json"
    local started_ms
    local finished_ms
    local wall_time_ms
    local offered_rate=0
    local latency_node="$node_a"
    local latency_target="$target_ip"
    local load_latency_packets=$(((duration + 2) * 20))
    local -a iperf_args

    if [[ "$protocol" == tcp ]]; then
        iperf_args=(iperf3 -c "$target_ip" -p 5201 -t "$duration" -O 1 -P "$streams" -J)
    else
        iperf_args=(iperf3 -u -b "$udp_rate" -c "$target_ip" -p 5201 -t "$duration" -O 1 -P "$streams" -J)
        offered_rate="$udp_rate"
    fi
    if [[ "$direction" == reverse ]]; then
        iperf_args+=(-R)
        latency_node="$node_b"
        if [[ "$scenario" == direct-underlay ]]; then
            latency_target="$underlay_a"
        else
            latency_target="$overlay_a"
        fi
    fi

    capture_route_proof "$scenario" "$queue_count" "$repeat" "$target_ip" "$route_proof"
    run_idle_latency_probe "$latency_node" "$latency_target" "$idle_latency"
    if [[ "$sample_core" == true ]]; then
        capture_mode_stats "$node_a" "$mode_stats_a_before"
        capture_mode_stats "$node_b" "$mode_stats_b_before"
        start_resource_sampler "$node_a" "$case_id"
        start_resource_sampler "$node_b" "$case_id"
    else
        write_empty_resource_file "$resource_a"
        write_empty_resource_file "$resource_b"
        write_empty_mode_stats "$mode_stats_a_before"
        write_empty_mode_stats "$mode_stats_b_before"
    fi
    if [[ "$sample_relay" == true ]]; then
        start_resource_sampler "$node_relay" "$case_id" "eth0 eth1"
    else
        write_empty_resource_file "$resource_relay"
    fi
    sleep 0.25
    start_load_latency_probe "$latency_node" "$latency_target" "$case_id"
    started_ms=$(now_ms)
    if ! "${docker_cmd[@]}" exec "$node_a" "${iperf_args[@]}" \
        >"$iperf_json" 2>"$iperf_stderr"; then
        if [[ "$sample_core" == true ]]; then
            stop_resource_sampler "$node_a" "$case_id" "$resource_a" || true
            stop_resource_sampler "$node_b" "$case_id" "$resource_b" || true
        fi
        if [[ "$sample_relay" == true ]]; then
            stop_resource_sampler "$node_relay" "$case_id" "$resource_relay" || true
        fi
        finish_load_latency_probe "$latency_node" "$case_id" "$load_latency" || true
        echo "iperf3 failed for $case_id; see $iperf_stderr" >&2
        return 1
    fi
    finished_ms=$(now_ms)
    wall_time_ms=$((finished_ms - started_ms))
    load_latency_packets=$((wall_time_ms / 50))
    finish_load_latency_probe "$latency_node" "$case_id" "$load_latency"
    sleep 0.25
    if [[ "$sample_core" == true ]]; then
        capture_mode_stats "$node_a" "$mode_stats_a_after"
        capture_mode_stats "$node_b" "$mode_stats_b_after"
        stop_resource_sampler "$node_a" "$case_id" "$resource_a"
        stop_resource_sampler "$node_b" "$case_id" "$resource_b"
    else
        write_empty_mode_stats "$mode_stats_a_after"
        write_empty_mode_stats "$mode_stats_b_after"
    fi
    if [[ "$sample_relay" == true ]]; then
        stop_resource_sampler "$node_relay" "$case_id" "$resource_relay"
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$case_id" "$scenario" "$mode" "$queue_count" "$repeat" "$protocol" "$direction" \
        "$streams" "$offered_rate" "$started_ms" "$finished_ms" "$wall_time_ms" \
        "${iperf_json#$result_dir/}" "${idle_latency#$result_dir/}" \
        "${load_latency#$result_dir/}" "$idle_latency_packets" "$load_latency_packets" \
        "${resource_a#$result_dir/}" \
        "${resource_b#$result_dir/}" "${resource_relay#$result_dir/}" \
        "${mode_stats_a_before#$result_dir/}" "${mode_stats_a_after#$result_dir/}" \
        "${mode_stats_b_before#$result_dir/}" "${mode_stats_b_after#$result_dir/}" \
        "${route_proof#$result_dir/}" >>"$cases_file"
}

run_case_matrix() {
    local scenario=$1
    local mode=$2
    local queue_count=$3
    local target_ip=$4
    local repeat=$5
    local sample_core=$6
    local sample_relay=$7
    local streams
    local direction

    if ((repeat % 2 == 1)); then
        for streams in 1 8; do
            for direction in forward reverse; do
                run_iperf_case "$scenario" "$mode" "$queue_count" "$target_ip" \
                    tcp "$direction" "$streams" "$repeat" "$sample_core" "$sample_relay"
            done
        done
        for direction in forward reverse; do
            run_iperf_case "$scenario" "$mode" "$queue_count" "$target_ip" \
                udp "$direction" 1 "$repeat" "$sample_core" "$sample_relay"
        done
    else
        for direction in reverse forward; do
            run_iperf_case "$scenario" "$mode" "$queue_count" "$target_ip" \
                udp "$direction" 1 "$repeat" "$sample_core" "$sample_relay"
        done
        for streams in 8 1; do
            for direction in reverse forward; do
                run_iperf_case "$scenario" "$mode" "$queue_count" "$target_ip" \
                    tcp "$direction" "$streams" "$repeat" "$sample_core" "$sample_relay"
            done
        done
    fi
}

run_scenario() {
    local scenario=$1
    local queue_count=$2
    local repeat=$3
    local mode
    local topology
    local target_ip
    local sample_core=true
    local sample_relay=false

    case "$scenario" in
        direct-underlay)
            mode=underlay
            topology=direct
            target_ip="$underlay_b"
            sample_core=false
            ;;
        automatic-compact-l3)
            mode=automatic
            topology=direct
            target_ip="$overlay_b"
            ;;
        authorized-bridge-compact-l3)
            mode=automatic
            topology=direct
            target_ip="$overlay_b"
            ;;
        relay-compact-l3)
            mode=automatic
            topology=relay
            target_ip="$overlay_b"
            sample_relay=true
            ;;
    esac

    echo "Benchmark scenario=$scenario queue_count=$queue_count repeat=$repeat"
    cleanup
    "${docker_cmd[@]}" network create --driver bridge --subnet 172.31.77.0/24 \
        "$network_a" >/dev/null

    if [[ "$topology" == relay ]]; then
        "${docker_cmd[@]}" network create --driver bridge --subnet 172.31.78.0/24 \
            "$network_b" >/dev/null
        start_container "$node_a" "$network_a" "$underlay_a"
        start_container "$node_b" "$network_b" 172.31.78.3
        start_container "$node_relay" "$network_a" "$relay_underlay_a"
        "${docker_cmd[@]}" network connect --ip "$relay_underlay_b" \
            "$network_b" "$node_relay"
        start_core "$node_relay" "" "" false true true
        start_core "$node_a" "$overlay_a" "udp://$node_relay:11010" true
        start_core "$node_b" "$overlay_b" "udp://$node_relay:11010" true
    elif [[ "$scenario" == authorized-bridge-compact-l3 ]]; then
        start_container "$node_a" "$network_a" "$underlay_a"
        start_container "$node_b" "$network_a" "$underlay_b"
        start_core "$node_a" "$overlay_a" "" false false false true
        start_core "$node_b" "$overlay_b" "udp://$node_a:11010" false false false true
    elif [[ "$scenario" != direct-underlay ]]; then
        start_container "$node_a" "$network_a" "$underlay_a"
        start_container "$node_b" "$network_a" "$underlay_b"
        start_core "$node_a" "$overlay_a"
        start_core "$node_b" "$overlay_b" "udp://$node_a:11010"
    else
        start_container "$node_a" "$network_a" "$underlay_a"
        start_container "$node_b" "$network_a" "$underlay_b"
    fi

    if [[ "$scenario" != direct-underlay ]]; then
        wait_for_interface "$node_a"
        wait_for_interface "$node_b"
        wait_for_ping "$node_a" "$overlay_b"
        wait_for_ping "$node_b" "$overlay_a"
        if [[ "$scenario" == authorized-bridge-compact-l3 ]]; then
            "${docker_cmd[@]}" exec "$node_a" ip -d link show et0 | grep -q tap
            "${docker_cmd[@]}" exec "$node_b" ip -d link show et0 | grep -q tap
        fi
    fi
    start_iperf_server
    run_case_matrix "$scenario" "$mode" "$queue_count" "$target_ip" \
        "$repeat" "$sample_core" "$sample_relay"
    cleanup
}

trap cleanup EXIT INT TERM

source_revision=$(git -C "$repo_root" rev-parse HEAD)
source_digest=$(compute_source_digest)
image_revision=$("${docker_cmd[@]}" image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image_name")
image_source_digest=$("${docker_cmd[@]}" image inspect \
    --format '{{ index .Config.Labels "dev.lowertier.source-digest" }}' "$image_name")
image_build_features=$("${docker_cmd[@]}" image inspect \
    --format '{{ index .Config.Labels "dev.lowertier.build-features" }}' "$image_name")
if [[ "$image_revision" != "$source_revision" ]]; then
    echo "benchmark image revision does not match the source tree" >&2
    exit 1
fi
if [[ "$image_source_digest" != "$source_digest" ]]; then
    echo "benchmark image digest does not match the source tree" >&2
    exit 1
fi
if [[ -z "$image_build_features" || "$image_build_features" == unknown ]]; then
    echo "benchmark image does not identify its build features" >&2
    exit 1
fi

printf "secure_mode=mandatory\ndocker_context=%s\nimage=%s\nduration_seconds=%s\nqueue_matrix=%s\n" \
    "$docker_context" "$image_name" "$duration" "$queue_matrix" >"$result_dir/environment.txt"
printf "malloc_arena_max=%s\n" "${LOWTIER_MALLOC_ARENA_MAX:-default}" >>"$result_dir/environment.txt"
printf "scenario_matrix=%s\nrepeat_count=%s\nmemory_ceiling_kib=%s\nudp_rate=%s\nidle_latency_packets=%s\n" \
    "$scenario_matrix" "$repeat_count" "$memory_ceiling_kib" "$udp_rate" \
    "$idle_latency_packets" >>"$result_dir/environment.txt"
printf "git_commit=%s\ngit_dirty=%s\nrun_started_utc=%s\n" \
    "$source_revision" \
    "$(test -n "$(git -C "$repo_root" status --short)" && echo true || echo false)" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$result_dir/environment.txt"
printf "source_digest=%s\nimage_revision=%s\nimage_source_digest=%s\nbuild_features=%s\n" \
    "$source_digest" "$image_revision" "$image_source_digest" "$image_build_features" \
    >>"$result_dir/environment.txt"
git -C "$repo_root" status --short >"$result_dir/git-status.txt"
git -C "$repo_root" diff --binary HEAD >"$result_dir/source.patch"
git -C "$repo_root" ls-files --others --exclude-standard -z \
    >"$result_dir/untracked-files.list"
if [[ -s "$result_dir/untracked-files.list" ]]; then
    tar -C "$repo_root" --null --files-from "$result_dir/untracked-files.list" \
        -czf "$result_dir/untracked-source.tar.gz"
fi
"${docker_cmd[@]}" image inspect "$image_name" >"$result_dir/image-inspect.json"
"${docker_cmd[@]}" info >"$result_dir/docker-info.txt"
uname -a >"$result_dir/system.txt"
runtime_arch=$("${docker_cmd[@]}" run --rm "$image_name" uname -m)
core_elf_machine=$("${docker_cmd[@]}" run --rm "$image_name" python3 -c \
    'import struct; print(struct.unpack("<H", open("/usr/local/bin/lowertier-core", "rb").read()[18:20])[0])')
printf "runtime_uname_m=%s\ncore_elf_machine=%s\n" \
    "$runtime_arch" "$core_elf_machine" >"$result_dir/runtime-architecture.txt"
printf "runtime_uname_m=%s\ncore_elf_machine=%s\n" \
    "$runtime_arch" "$core_elf_machine" >>"$result_dir/environment.txt"
shasum -a 256 "$repo_root/script/colima-l2/benchmark.sh" \
    "$repo_root/script/colima-l2/benchmark_report.py" \
    "$repo_root/script/colima-l2/source_digest.py" \
    "$repo_root/script/colima-l2/Dockerfile" >"$result_dir/harness-sha256.txt"

for scenario in "${scenarios[@]}"; do
    if [[ "$scenario" == direct-underlay ]]; then
        for repeat in $(seq 1 "$repeat_count"); do
            run_scenario "$scenario" 0 "$repeat"
        done
        continue
    fi
    for queue_count in "${queue_counts[@]}"; do
        for repeat in $(seq 1 "$repeat_count"); do
            run_scenario "$scenario" "$queue_count" "$repeat"
        done
    done
done

printf "run_finished_utc=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >>"$result_dir/environment.txt"

report_status=0
python3 "$repo_root/script/colima-l2/benchmark_report.py" \
    "$result_dir" "$memory_ceiling_kib" || report_status=$?
cat "$result_dir/results.tsv"
echo "Results: $result_dir"
exit "$report_status"
