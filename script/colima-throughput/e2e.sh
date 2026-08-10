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
runs=${RUNS:-1}
parallel_streams=${PARALLEL_STREAMS:-8}
encryption_algorithm=${ENCRYPTION_ALGORITHM:-chacha20-poly1305}
runtime_env=${LOWTIER_RUNTIME_ENV:-}
underlay_protocol=${UNDERLAY_PROTOCOL:-udp}
core_args=${LOWTIER_CORE_ARGS:-}
netem_delay=${NETEM_DELAY:-}
netem_jitter=${NETEM_JITTER:-0ms}
netem_loss=${NETEM_LOSS:-0%}
netem_loss_correlation=${NETEM_LOSS_CORRELATION:-0%}
netem_limit=${NETEM_LIMIT:-250000}
quic_fec_profiles_text=${QUIC_FEC_PROFILES:-2}
modes_text=${MODES:-"l3 l2-tun tap"}
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

docker_cmd=(docker --context "$docker_context")
containers=("$node_a" "$node_b")

cleanup_nodes() {
    "${docker_cmd[@]}" rm -f "${containers[@]}" >/dev/null 2>&1 || true
}

cleanup() {
    cleanup_nodes
    "${docker_cmd[@]}" network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ "$quick" == 1 ]]; then
    duration=${DURATION:-3}
    cpu_duration=${CPU_DURATION:-3}
    runs=${RUNS:-1}
    modes_text=${MODES:-l3}
    udp_rates_text=${UDP_RATES:-10000M}
fi

read -r -a modes <<<"$modes_text"
read -r -a udp_rates <<<"$udp_rates_text"
read -r -a quic_fec_profiles <<<"$quic_fec_profiles_text"

mkdir -p "$result_dir/raw" "$result_dir/overlay" "$result_dir/cpu" "$result_dir/latency" "$result_dir/logs"
perf_write_metadata "$result_dir" "colima-throughput:$docker_context"
printf 'docker_context=%s\nraw_gate_bps=%s\nmodes=%s\nudp_rates=%s\nencryption_algorithm=%s\n' \
    "$docker_context" "$raw_gate_bps" "$modes_text" "$udp_rates_text" "$encryption_algorithm" \
    >>"$result_dir/environment.txt"
printf 'runtime_env=%s\n' "$runtime_env" >>"$result_dir/environment.txt"
printf 'run_tcp=%s\nrun_udp=%s\nrun_cpu_probe=%s\n' \
    "$run_tcp" "$run_udp" "$run_cpu_probe" >>"$result_dir/environment.txt"
printf 'underlay_protocol=%s\ncore_args=%s\nnetem_delay=%s\nnetem_jitter=%s\nnetem_loss=%s\nnetem_loss_correlation=%s\nnetem_limit=%s\nquic_fec_profiles=%s\n' \
    "$underlay_protocol" "$core_args" "$netem_delay" "$netem_jitter" "$netem_loss" \
    "$netem_loss_correlation" "$netem_limit" "$quic_fec_profiles_text" \
    >>"$result_dir/environment.txt"

case "$underlay_protocol" in
    udp|quic) ;;
    *) echo "unsupported underlay protocol: $underlay_protocol" >&2; exit 64 ;;
esac

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
    "${docker_cmd[@]}" run -d --name "$node_a" --network "$network" --ip 172.30.10.2 \
        --cap-add NET_ADMIN --device /dev/net/tun "$image" sleep infinity >/dev/null
    "${docker_cmd[@]}" run -d --name "$node_b" --network "$network" --ip 172.30.10.3 \
        --cap-add NET_ADMIN --device /dev/net/tun "$image" sleep infinity >/dev/null
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

extract_quic_metrics() {
    local profile=$1
    local node=$2
    local log_file=$3
    [[ -f "$log_file" ]] || return 0
    awk -v profile="$profile" -v node="$node" '
        index($0, "ETQ4_METRICS_TSV\t") {
            line = substr($0, index($0, "ETQ4_METRICS_TSV\t") + length("ETQ4_METRICS_TSV\t"));
            count = split(line, field, "\t");
            if (count < 32) next;
            sub(/ .*/, "", field[32]);
            printf "%s\t%s", profile, node;
            for (i = 1; i <= 32; i++) printf "\t%s", field[i];
            printf "\n";
        }
    ' "$log_file" >>"$result_dir/quic-datagram-metrics.tsv"
}

extract_alternate_fec_metrics() {
    local profile=$1
    local node=$2
    local log_file=$3
    [[ -f "$log_file" ]] || return 0
    awk -v profile="$profile" -v node="$node" '
        index($0, "EAP1_METRICS_TSV\t") {
            line = substr($0, index($0, "EAP1_METRICS_TSV\t") + length("EAP1_METRICS_TSV\t"));
            count = split(line, field, "\t");
            if (count < 8) next;
            sub(/ .*/, "", field[8]);
            printf "%s\t%s", profile, node;
            for (i = 1; i <= 8; i++) printf "\t%s", field[i];
            printf "\n";
        }
    ' "$log_file" >>"$result_dir/alternate-fec-metrics.tsv"
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
        "${docker_cmd[@]}" exec "$node_a" iperf3 "${iperf_args[@]}" >"$output" || true
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
        "i=0; while [ \"\$i\" -lt $samples ]; do ps -C lowertier-core -o %cpu= | awk '{s+=\$1} END {print s+0}'; i=\$((i+1)); sleep 1; done" \
        >"$output"
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
    local pid_a pid_b ping_pid received cpu_avg cpu_max cores

    # A heavily delayed UDP test can leave iperf's single-test server occupied
    # after the client has returned. Start a fresh server so the CPU probe is
    # independent of the preceding workload's control-flow tail.
    start_iperf_server "$port"

    if [[ "$direction" == reverse ]]; then
        iperf_args+=(-R)
    fi

    sample_cpu "$node_a" "$cpu_a" "$samples" &
    pid_a=$!
    sample_cpu "$node_b" "$cpu_b" "$samples" &
    pid_b=$!
    "${docker_cmd[@]}" exec "$node_a" ping -n -i 0.05 -c "$ping_count" "$destination" \
        >"$ping_file" 2>&1 &
    ping_pid=$!

    "${docker_cmd[@]}" exec "$node_a" iperf3 "${iperf_args[@]}" >"$json"
    wait "$pid_a" "$pid_b" "$ping_pid"

    received=$(jq -er '.end.sum_received.bits_per_second | numbers' "$json")
    for node in "$node_a" "$node_b"; do
        local cpu_file="$result_dir/cpu/${mode}-${direction}-${node}.txt"
        cpu_avg=$(awk 'NF {sum += $1; count++} END {if (count) printf "%.6f", sum/count; else print "0.000000"}' "$cpu_file")
        cpu_max=$(awk 'NF && $1 > max {max=$1} END {printf "%.6f", max+0}' "$cpu_file")
        cores=$(perf_cpu_cores_per_gbit "$cpu_avg" "$received")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$mode" "$direction" "$node" "$received" "$cpu_avg" "$cpu_max" "$cores" \
            >>"$result_dir/cpu-cores-per-gbit.tsv"
    done
}

perf_result_header | awk '{print "mode\t" $0}' >"$result_dir/throughput.tsv"
printf 'mode\tdirection\trun\tprotocol\tstreams\toffered_bps\terror\n' \
    >"$result_dir/workload-errors.tsv"
printf 'mode\tdirection\tnode\treceived_bps\taverage_cpu_percent\tmax_cpu_percent\tcpu_cores_per_gbit\n' \
    >"$result_dir/cpu-cores-per-gbit.tsv"
printf 'profile\tnode\treason\tsource_frames\tsource_fragments\tsource_bytes\tfragmented_source_fragments\tqueue_drops_pending\tqueue_drops_quinn\tack_ranges_sent\tack_ranges_received\tnacks_sent\tnacks_received\tselective_fragments_retransmitted\trecovery_exhausted\tcritical_duplicates_sent\tcritical_duplicates_suppressed\tfec_blocks\tfec_source_symbols\tfec_parity_symbols\tfec_source_bytes\tfec_parity_bytes\tfec_recovered_symbols\tfec_unrecoverable_blocks\tpartial_frames_expired\tpath_mtu\tqueue_high_water_bytes\trtt_us\tcwnd_bytes\tlost_packets\tlost_bytes\tsent_packets\tcurrent_mtu\tdatagram_queue_bytes\n' \
    >"$result_dir/quic-datagram-metrics.tsv"
printf 'profile\tnode\treason\tsource_records\tsource_bytes\tparity_blocks_sent\tparity_records_sent\tparity_bytes_sent\tparity_send_failures\tparity_blocks_skipped_no_path\n' \
    >"$result_dir/alternate-fec-metrics.tsv"

start_containers
apply_network_noise
"${docker_cmd[@]}" exec "$node_a" ethtool -k eth0 >"$result_dir/raw/${node_a}-offloads.txt" || true
"${docker_cmd[@]}" exec "$node_b" ethtool -k eth0 >"$result_dir/raw/${node_b}-offloads.txt" || true
start_iperf_server 5200
for streams in 1 "$parallel_streams"; do
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

for fec_parity in "${quic_fec_profiles[@]}"; do
for mode in "${modes[@]}"; do
    case "$mode" in
        l3) subnet=10.201.1 ;;
        l2-tun) subnet=10.201.2 ;;
        tap) subnet=10.201.3 ;;
        *) echo "unsupported mode: $mode" >&2; exit 64 ;;
    esac

    profile=$mode
    fec_args=""
    if [[ "$underlay_protocol" == quic ]]; then
        profile="${mode}-fec${fec_parity}"
        fec_args="--quic-datagram-fec-parity $fec_parity"
    fi

    start_containers
    apply_network_noise
    "${docker_cmd[@]}" exec -d "$node_a" sh -lc \
        "exec env $runtime_env lowertier-core --network-name throughput-$profile --network-secret throughput-secret --encryption-algorithm $encryption_algorithm --port-mode $mode --dev-name et0 --ipv4 $subnet.1/24 --listeners ${underlay_protocol}://0.0.0.0:11010 --default-protocol $underlay_protocol --disable-upnp true --rpc-portal 0.0.0.0:15991 $fec_args $core_args >/tmp/lowertier.log 2>&1"
    "${docker_cmd[@]}" exec -d "$node_b" sh -lc \
        "exec env $runtime_env lowertier-core --network-name throughput-$profile --network-secret throughput-secret --encryption-algorithm $encryption_algorithm --port-mode $mode --dev-name et0 --ipv4 $subnet.2/24 --listeners ${underlay_protocol}://0.0.0.0:11010 --peers ${underlay_protocol}://$node_a:11010 --default-protocol $underlay_protocol --disable-upnp true --rpc-portal 0.0.0.0:15992 $fec_args $core_args >/tmp/lowertier.log 2>&1"
    wait_for_ping "$subnet.2"
    "${docker_cmd[@]}" exec "$node_a" ping -n -c 100 -i 0.02 "$subnet.2" \
        >"$result_dir/latency/${profile}-unloaded.txt"
    start_iperf_server 5201

    for direction in forward reverse; do
        for run in $(seq 1 "$runs"); do
            if [[ "$run_tcp" == 1 ]]; then
                for streams in 1 "$parallel_streams"; do
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
        extract_quic_metrics "$profile" "$node" "$log_file"
        extract_alternate_fec_metrics "$profile" "$node" "$log_file"
    done
done
done

echo "results: $result_dir"
