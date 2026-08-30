#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$repo_root/script/throughput-common.sh"

docker_context=${DOCKER_CONTEXT:-colima}
image=${LOWTIER_BENCH_IMAGE:-lowertier-throughput:local}
network=${LOWTIER_BENCH_NETWORK:-lowertier-throughput-net}
node_a=${LOWTIER_BENCH_NODE_A:-lowertier-throughput-a}
node_b=${LOWTIER_BENCH_NODE_B:-lowertier-throughput-b}
result_dir=${RESULT_DIR:-$(mktemp -d -t lowertier-colima-throughput.XXXXXX)}
duration=${DURATION:-10}
omit=${OMIT:-2}
iperf_timeout_seconds=${IPERF_TIMEOUT_SECONDS:-$((duration + omit + 15))}
runs=${RUNS:-1}
parallel_streams=${PARALLEL_STREAMS:-8}
tcp_streams_text=${TCP_STREAMS:-"1 $parallel_streams"}
encryption_algorithm=${ENCRYPTION_ALGORITHM:-chacha20-poly1305}
runtime_env=${LOWTIER_RUNTIME_ENV:-}
underlay_protocol=${UNDERLAY_PROTOCOL:-udp}
core_args=${LOWTIER_CORE_ARGS:-}
core_binary=${LOWTIER_CORE_BINARY:-}
tcp_congestion_control=${TCP_CONGESTION_CONTROL:-}
netem_delay=${NETEM_DELAY:-}
netem_jitter=${NETEM_JITTER:-0ms}
netem_loss=${NETEM_LOSS:-0%}
netem_loss_correlation=${NETEM_LOSS_CORRELATION:-0%}
netem_limit=${NETEM_LIMIT:-250000}
udp_rates_text=${UDP_RATES:-"2500M 5000M 7500M 10000M 12000M"}
raw_gate_bps=${RAW_GATE_BPS:-12000000000}
require_raw_gate=${REQUIRE_RAW_GATE:-0}
build_image=${BUILD_IMAGE:-1}
quick=${QUICK:-0}
cpu_duration=${CPU_DURATION:-$duration}
iperf_busy_retries=${IPERF_BUSY_RETRIES:-3}
run_tcp=${RUN_TCP:-1}
run_udp=${RUN_UDP:-1}
run_cpu_probe=${RUN_CPU_PROBE:-1}
cpu_protocol=${CPU_PROTOCOL:-tcp}
cpu_udp_rate=${CPU_UDP_RATE:-10000M}
cpu_udp_length=${CPU_UDP_LENGTH:-1352}
capture_dataplane_stats=${CAPTURE_DATAPLANE_STATS:-1}
directions_text=${DIRECTIONS:-"forward reverse"}
run_raw_gate=${RUN_RAW_GATE:-1}

docker_cmd=(docker --context "$docker_context")
containers=("$node_a" "$node_b")

cleanup_nodes() {
    "${docker_cmd[@]}" rm -f "${containers[@]}" >/dev/null 2>&1 || true
}

capture_active_logs() {
    if [[ ! -d "$result_dir/logs" ]]; then
        return
    fi
    local node
    for node in "${containers[@]}"; do
        "${docker_cmd[@]}" cp "$node:/tmp/lowertier.log" \
            "$result_dir/logs/failure-${node}.log" >/dev/null 2>&1 || true
    done
}

cleanup() {
    capture_active_logs
    cleanup_nodes
    "${docker_cmd[@]}" network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ "$quick" == 1 ]]; then
    duration=${DURATION:-3}
    cpu_duration=${CPU_DURATION:-3}
    runs=${RUNS:-1}
    udp_rates_text=${UDP_RATES:-10000M}
fi

read -r -a udp_rates <<<"$udp_rates_text"
read -r -a directions <<<"$directions_text"
if ! [[ "$parallel_streams" =~ ^[1-9][0-9]*$ ]]; then
    echo "PARALLEL_STREAMS must be a positive integer" >&2
    exit 64
fi
raw_tcp_streams=(1)
if [[ "$parallel_streams" != 1 ]]; then
    raw_tcp_streams+=("$parallel_streams")
fi
read -r -a requested_tcp_streams <<<"$tcp_streams_text"
tcp_streams=()
for streams in "${requested_tcp_streams[@]}"; do
    if ! [[ "$streams" =~ ^[1-9][0-9]*$ ]]; then
        echo "TCP_STREAMS must contain positive integers" >&2
        exit 64
    fi
    duplicate=0
    for existing in ${tcp_streams[*]-}; do
        if [[ "$existing" == "$streams" ]]; then
            duplicate=1
            break
        fi
    done
    if [[ "$duplicate" == 0 ]]; then
        tcp_streams+=("$streams")
    fi
done
if [[ "${#tcp_streams[@]}" == 0 ]]; then
    echo "TCP_STREAMS must contain at least one stream count" >&2
    exit 64
fi

mkdir -p "$result_dir/raw" "$result_dir/overlay" "$result_dir/cpu" "$result_dir/latency" "$result_dir/logs"
perf_write_metadata "$result_dir" "colima-throughput:$docker_context"
printf 'docker_context=%s\nraw_gate_bps=%s\nadapter=automatic\nudp_rates=%s\nencryption_algorithm=%s\n' \
    "$docker_context" "$raw_gate_bps" "$udp_rates_text" "$encryption_algorithm" \
    >>"$result_dir/environment.txt"
printf 'runtime_env=%s\n' "$runtime_env" >>"$result_dir/environment.txt"
printf 'run_tcp=%s\nrun_udp=%s\nrun_cpu_probe=%s\n' \
    "$run_tcp" "$run_udp" "$run_cpu_probe" >>"$result_dir/environment.txt"
printf 'cpu_protocol=%s\ncpu_udp_rate=%s\ncpu_udp_length=%s\ncapture_dataplane_stats=%s\n' \
    "$cpu_protocol" "$cpu_udp_rate" "$cpu_udp_length" "$capture_dataplane_stats" \
    >>"$result_dir/environment.txt"
printf 'directions=%s\nrun_raw_gate=%s\n' "$directions_text" "$run_raw_gate" \
    >>"$result_dir/environment.txt"
printf 'tcp_streams=%s\n' "$tcp_streams_text" >>"$result_dir/environment.txt"
printf 'underlay_protocol=%s\ncore_args=%s\nnetem_delay=%s\nnetem_jitter=%s\nnetem_loss=%s\nnetem_loss_correlation=%s\nnetem_limit=%s\n' \
    "$underlay_protocol" "$core_args" "$netem_delay" "$netem_jitter" "$netem_loss" \
    "$netem_loss_correlation" "$netem_limit" \
    >>"$result_dir/environment.txt"
printf 'tcp_congestion_control=%s\n' "$tcp_congestion_control" \
    >>"$result_dir/environment.txt"
if [[ -n "$core_binary" ]]; then
    if [[ ! -f "$core_binary" || ! -x "$core_binary" ]]; then
        echo "LOWTIER_CORE_BINARY must name an executable file" >&2
        exit 64
    fi
    core_binary=$(cd "$(dirname "$core_binary")" && pwd -P)/$(basename "$core_binary")
    printf 'core_binary_name=%s\n' "$(basename "$core_binary")" >>"$result_dir/environment.txt"
    shasum -a 256 "$core_binary" >>"$result_dir/core-binary-sha256.txt"
fi

case "$underlay_protocol" in
    udp|quic) ;;
    *) echo "unsupported underlay protocol: $underlay_protocol" >&2; exit 64 ;;
esac
case "$cpu_protocol" in
    tcp|udp) ;;
    *) echo "unsupported CPU probe protocol: $cpu_protocol" >&2; exit 64 ;;
esac
if [[ "$cpu_protocol" == udp ]]; then
    if ! [[ "$cpu_udp_length" =~ ^[0-9]+$ ]] || (( cpu_udp_length < 1 )); then
        echo "CPU_UDP_LENGTH must be a positive integer" >&2
        exit 64
    fi
fi

"${docker_cmd[@]}" info >/dev/null
if [[ "$build_image" == 1 ]]; then
    "${docker_cmd[@]}" build \
        -f "$repo_root/script/colima-throughput/Dockerfile" \
        -t "$image" "$repo_root"
fi

"${docker_cmd[@]}" network rm "$network" >/dev/null 2>&1 || true
"${docker_cmd[@]}" network create \
    --driver bridge --subnet 172.30.10.0/24 --opt com.docker.network.driver.mtu=9000 \
    "$network" >/dev/null

start_containers() {
    cleanup_nodes
    local run_args=(--pull never -d --network "$network" --cap-add NET_ADMIN --device /dev/net/tun)
    if [[ -n "$core_binary" ]]; then
        run_args+=(-v "$core_binary:/usr/local/bin/lowertier-core:ro")
    fi
    if [[ -n "$tcp_congestion_control" ]]; then
        run_args+=(--sysctl "net.ipv4.tcp_congestion_control=$tcp_congestion_control")
    fi
    "${docker_cmd[@]}" run "${run_args[@]}" --name "$node_a" --ip 172.30.10.2 \
        "$image" sleep infinity >/dev/null
    "${docker_cmd[@]}" run "${run_args[@]}" --name "$node_b" --ip 172.30.10.3 \
        "$image" sleep infinity >/dev/null
}

apply_network_noise() {
    if [[ -z "$netem_delay" && "$netem_loss" == 0% ]]; then
        return
    fi
    local node
    for node in "${containers[@]}"; do
        local netem_args=(tc qdisc replace dev eth0 root netem)
        if [[ -n "$netem_delay" ]]; then
            netem_args+=(delay "$netem_delay" "$netem_jitter")
        fi
        if [[ "$netem_loss" != 0% ]]; then
            netem_args+=(loss random "$netem_loss")
            if [[ "$netem_loss_correlation" != 0% ]]; then
                netem_args+=("$netem_loss_correlation")
            fi
        fi
        netem_args+=(limit "$netem_limit")
        "${docker_cmd[@]}" exec "$node" "${netem_args[@]}"
    done
}

start_iperf_server() {
    local port=$1
    "${docker_cmd[@]}" exec "$node_b" sh -lc "pkill iperf3 2>/dev/null || true; iperf3 -s -D -p $port"
}

wait_for_ping() {
    local destination=$1
    local attempt
    for attempt in $(seq 1 30); do
        if "${docker_cmd[@]}" exec "$node_a" ping -q -c 1 -W 1 "$destination" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "could not reach $destination from $node_a" >&2
    return 1
}

run_iperf() {
    local mode=$1
    local direction=$2
    local protocol=$3
    local streams=$4
    local rate=$5
    local destination=$6
    local port=$7
    local run=$8
    local output=$9
    local iperf_args=(-c "$destination" -p "$port" -t "$duration" -O "$omit" -P "$streams" -J)
    local parsed error attempt

    if [[ "$direction" == reverse ]]; then
        iperf_args+=(-R)
    fi
    if [[ "$protocol" == udp ]]; then
        iperf_args+=(-u -b "$rate")
    fi

    for attempt in $(seq 0 "$iperf_busy_retries"); do
        "${docker_cmd[@]}" exec "$node_a" \
            timeout "$iperf_timeout_seconds" iperf3 "${iperf_args[@]}" >"$output" || true
        if parsed=$(perf_parse_iperf_json "$direction" "$run" "$output"); then
            printf '%s\t%s\n' "$mode" "$parsed" >>"$result_dir/throughput.tsv"
            return
        fi
        error=$(jq -r '.error // "iperf result was incomplete"' "$output" 2>/dev/null \
            || printf 'iperf result was not valid JSON')
        if [[ "$error" != *"the server is busy running a test"* || "$attempt" -eq "$iperf_busy_retries" ]]; then
            break
        fi
        start_iperf_server "$port"
        sleep 1
    done

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$mode" "$direction" "$run" "$protocol" "$streams" "$rate" "$error" \
        >>"$result_dir/workload-errors.tsv"
}

sample_cpu() {
    local node=$1
    local output=$2
    local samples=$3
    "${docker_cmd[@]}" exec "$node" sh -lc \
        "i=0; while [ \"\$i\" -lt $samples ]; do ps -C lowertier-core -o %cpu=,rss= | awk '{cpu+=\$1; rss+=\$2} END {print cpu+0, rss+0}'; i=\$((i+1)); sleep 1; done" \
        >"$output"
}

capture_dataplane_snapshot() {
    local node=$1
    local portal=$2
    local output=$3
    if [[ "$capture_dataplane_stats" != 1 ]]; then
        : >"$output"
        return
    fi
    local temporary="${output}.tmp"
    if ! "${docker_cmd[@]}" exec "$node" \
        lowertier-cli --rpc-portal "127.0.0.1:$portal" stats prometheus \
        >"$temporary" 2>"${output}.stderr"; then
        cat "$temporary" >"$output" 2>/dev/null || true
        rm -f "$temporary"
        echo "failed to capture dataplane Prometheus metrics from $node" >&2
        return 1
    fi
    if ! grep -q '^lowertier_dataplane_' "$temporary"; then
        cat "$temporary" >"$output"
        rm -f "$temporary"
        echo "dataplane Prometheus metrics were absent for $node" >&2
        return 1
    fi
    mv "$temporary" "$output"
}

record_cpu_probe() {
    local mode=$1
    local direction=$2
    local destination=$3
    local port=$4
    local json="$result_dir/cpu/${mode}-${direction}.json"
    local cpu_a="$result_dir/cpu/${mode}-${direction}-${node_a}.txt"
    local cpu_b="$result_dir/cpu/${mode}-${direction}-${node_b}.txt"
    local ping_file="$result_dir/latency/${mode}-${direction}-loaded.txt"
    local iperf_args=(-c "$destination" -p "$port" -t "$cpu_duration" -O "$omit" -P "$parallel_streams" -J)
    local samples=$((cpu_duration + 1))
    local ping_count=$((cpu_duration * 20))
    local inner_packet_length=0
    local offered_rate=0
    local pid_a pid_b ping_pid received cpu_avg cpu_max cores rss_avg rss_max

    if [[ "$cpu_protocol" == udp ]]; then
        iperf_args+=(-u -b "$cpu_udp_rate" -l "$cpu_udp_length")
        inner_packet_length=$((cpu_udp_length + 28))
        offered_rate="$cpu_udp_rate"
    fi

    # A heavily delayed UDP test can leave iperf's single-test server occupied
    # after the client has returned. Start a fresh server so the CPU probe is
    # independent of the preceding workload's control-flow tail.
    start_iperf_server "$port"

    if [[ "$direction" == reverse ]]; then
        iperf_args+=(-R)
    fi

    capture_dataplane_snapshot "$node_a" 15991 \
        "$result_dir/cpu/${mode}-${direction}-${node_a}-prometheus-before.txt"
    capture_dataplane_snapshot "$node_b" 15992 \
        "$result_dir/cpu/${mode}-${direction}-${node_b}-prometheus-before.txt"

    sample_cpu "$node_a" "$cpu_a" "$samples" &
    pid_a=$!
    sample_cpu "$node_b" "$cpu_b" "$samples" &
    pid_b=$!
    "${docker_cmd[@]}" exec "$node_a" ping -n -i 0.05 -c "$ping_count" "$destination" \
        >"$ping_file" 2>&1 &
    ping_pid=$!

    "${docker_cmd[@]}" exec "$node_a" \
        timeout "$iperf_timeout_seconds" iperf3 "${iperf_args[@]}" >"$json"
    wait "$pid_a" "$pid_b" "$ping_pid"

    capture_dataplane_snapshot "$node_a" 15991 \
        "$result_dir/cpu/${mode}-${direction}-${node_a}-prometheus-after.txt"
    capture_dataplane_snapshot "$node_b" 15992 \
        "$result_dir/cpu/${mode}-${direction}-${node_b}-prometheus-after.txt"

    received=$(jq -er '.end.sum_received.bits_per_second | numbers' "$json")
    if ! awk -v received="$received" 'BEGIN { exit !(received > 0) }'; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$mode" "$direction" 0 "$cpu_protocol" "$parallel_streams" "$offered_rate" \
            'CPU probe delivered zero payload bytes' \
            >>"$result_dir/workload-errors.tsv"
        echo "CPU probe delivered zero payload bytes for $mode/$direction" >&2
        return 1
    fi
    for node in "$node_a" "$node_b"; do
        local cpu_file="$result_dir/cpu/${mode}-${direction}-${node}.txt"
        cpu_avg=$(awk 'NF {sum += $1; count++} END {if (count) printf "%.6f", sum/count; else print "0.000000"}' "$cpu_file")
        cpu_max=$(awk 'NF && $1 > max {max=$1} END {printf "%.6f", max+0}' "$cpu_file")
        rss_avg=$(awk 'NF {sum += $2; count++} END {if (count) printf "%.0f", sum/count; else print "0"}' "$cpu_file")
        rss_max=$(awk 'NF && $2 > max {max=$2} END {printf "%.0f", max+0}' "$cpu_file")
        cores=$(perf_cpu_cores_per_gbit "$cpu_avg" "$received")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$mode" "$direction" "$node" "$received" "$cpu_avg" "$cpu_max" "$cores" \
            >>"$result_dir/cpu-cores-per-gbit.tsv"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$mode" "$direction" "$cpu_protocol" "$parallel_streams" \
            "$cpu_udp_length" "$inner_packet_length" "$node" "$received" "$cpu_avg" "$cores" \
            >>"$result_dir/work-model.tsv"
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$mode" "$direction" "$node" "$rss_avg" "$rss_max" \
            >>"$result_dir/memory.tsv"
    done
}

perf_result_header | awk '{print "mode\t" $0}' >"$result_dir/throughput.tsv"
printf 'mode\tdirection\trun\tprotocol\tstreams\toffered_bps\terror\n' \
    >"$result_dir/workload-errors.tsv"
printf 'mode\tdirection\tnode\treceived_bps\taverage_cpu_percent\tmax_cpu_percent\tcpu_cores_per_gbit\n' \
    >"$result_dir/cpu-cores-per-gbit.tsv"
printf 'mode\tdirection\tnode\taverage_rss_kib\tpeak_rss_kib\n' >"$result_dir/memory.tsv"
printf 'mode\tdirection\tprotocol\tflows\tudp_payload_bytes\tinner_packet_bytes\tnode\treceived_bps\taverage_cpu_percent\tcpu_cores_per_gbit\n' \
    >"$result_dir/work-model.tsv"
if [[ "$run_raw_gate" == 1 ]]; then
    start_containers
    apply_network_noise
    "${docker_cmd[@]}" exec "$node_a" ethtool -k eth0 >"$result_dir/raw/${node_a}-offloads.txt" || true
    "${docker_cmd[@]}" exec "$node_b" ethtool -k eth0 >"$result_dir/raw/${node_b}-offloads.txt" || true
    start_iperf_server 5200
    for streams in "${raw_tcp_streams[@]}"; do
        raw_json="$result_dir/raw/tcp-p${streams}.json"
        run_iperf raw forward tcp "$streams" 0 172.30.10.3 5200 1 "$raw_json"
    done

    raw_bps=$(jq -er '.end.sum_received.bits_per_second | numbers' "$result_dir/raw/tcp-p${parallel_streams}.json")
    if jq -ne --argjson actual "$raw_bps" --argjson required "$raw_gate_bps" '$actual >= $required'; then
        printf 'valid\n' >"$result_dir/substrate-status.txt"
    else
        printf 'substrate-limited\n' >"$result_dir/substrate-status.txt"
        if [[ "$require_raw_gate" == 1 ]]; then
            echo "raw substrate ${raw_bps} bps did not meet ${raw_gate_bps} bps gate" >&2
            exit 2
        fi
    fi
else
    printf 'not-run\n' >"$result_dir/substrate-status.txt"
fi

profile=automatic
subnet=10.201.4

start_containers
apply_network_noise
"${docker_cmd[@]}" exec -d "$node_a" sh -lc \
    "exec env $runtime_env lowertier-core --network-name throughput-$profile --network-secret throughput-secret --encryption-algorithm $encryption_algorithm --dev-name et0 --ipv4 $subnet.1/24 --listeners ${underlay_protocol}://0.0.0.0:11010 --default-protocol $underlay_protocol --disable-upnp true --rpc-portal 127.0.0.1:15991 $core_args >/tmp/lowertier.log 2>&1"
"${docker_cmd[@]}" exec -d "$node_b" sh -lc \
    "exec env $runtime_env lowertier-core --network-name throughput-$profile --network-secret throughput-secret --encryption-algorithm $encryption_algorithm --dev-name et0 --ipv4 $subnet.2/24 --listeners ${underlay_protocol}://0.0.0.0:11010 --peers ${underlay_protocol}://$node_a:11010 --default-protocol $underlay_protocol --disable-upnp true --rpc-portal 127.0.0.1:15992 $core_args >/tmp/lowertier.log 2>&1"
wait_for_ping "$subnet.2"
"${docker_cmd[@]}" exec "$node_a" ping -n -c 100 -i 0.02 "$subnet.2" \
    >"$result_dir/latency/${profile}-unloaded.txt"
start_iperf_server 5201

for direction in "${directions[@]}"; do
    for run in $(seq 1 "$runs"); do
        if [[ "$run_tcp" == 1 ]]; then
            for streams in "${tcp_streams[@]}"; do
                output="$result_dir/overlay/${profile}-${direction}-tcp-p${streams}-r${run}.json"
                run_iperf "$profile" "$direction" tcp "$streams" 0 "$subnet.2" 5201 "$run" "$output"
            done
        fi
        if [[ "$run_udp" == 1 ]]; then
            for rate in "${udp_rates[@]}"; do
                output="$result_dir/overlay/${profile}-${direction}-udp-${rate}-r${run}.json"
                run_iperf "$profile" "$direction" udp 1 "$rate" "$subnet.2" 5201 "$run" "$output"
            done
        fi
    done
    if [[ "$run_cpu_probe" == 1 ]]; then
        record_cpu_probe "$profile" "$direction" "$subnet.2" 5201
    fi
done
"${docker_cmd[@]}" exec "$node_a" pkill -TERM lowertier-core 2>/dev/null || true
"${docker_cmd[@]}" exec "$node_b" pkill -TERM lowertier-core 2>/dev/null || true
sleep 1
for node in "$node_a" "$node_b"; do
    log_file="$result_dir/logs/${profile}-${node}.log"
    "${docker_cmd[@]}" cp "$node:/tmp/lowertier.log" "$log_file" 2>/dev/null || true
done

echo "results: $result_dir"
