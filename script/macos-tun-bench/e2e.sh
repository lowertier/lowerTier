#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$repo_root/script/throughput-common.sh"

binary=${1:-target/release/lowertier-core}
binary=$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")
runs=${RUNS:-3}
duration=${DURATION:-10}
cpu_duration=${CPU_DURATION:-15}
profile_duration=${PROFILE_DURATION:-0}
parallel_streams=${PARALLEL_STREAMS:-8}
encryption_algorithm=${ENCRYPTION_ALGORITHM:-chacha20-poly1305}
mtu=${MTU:-1360}
colima_profile=${COLIMA_PROFILE:-lowertier-l2}
docker_context=${DOCKER_CONTEXT:-colima-lowertier-l2}
image=${LOWTIER_TEST_IMAGE:-lowertier-l2-qemu-test:local}
runtime_env=${LOWTIER_RUNTIME_ENV:-}
container_name=lowertier-macos-tun-bench
host_udp_port=${HOST_UDP_PORT:-12010}
result_dir=${RESULT_DIR:-$(mktemp -d -t lowertier-macos-tun-bench.XXXXXX)}
client_pid=
client_core_pid=
loaded_ping_pid=
resource_sampler_pid=
sc_usage_pid=
client_ifname=

cleanup() {
    if [[ -n "$client_core_pid" ]]; then
        sudo -n kill "$client_core_pid" 2>/dev/null || true
    fi
    if [[ -n "$client_pid" ]]; then
        kill "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
    fi
    if [[ -n "$loaded_ping_pid" ]]; then
        kill "$loaded_ping_pid" 2>/dev/null || true
        wait "$loaded_ping_pid" 2>/dev/null || true
    fi
    if [[ -n "$resource_sampler_pid" ]]; then
        kill "$resource_sampler_pid" 2>/dev/null || true
        wait "$resource_sampler_pid" 2>/dev/null || true
    fi
    if [[ -n "$sc_usage_pid" ]]; then
        sudo -n kill "$sc_usage_pid" 2>/dev/null || true
        wait "$sc_usage_pid" 2>/dev/null || true
    fi
    if docker --context "$docker_context" inspect "$container_name" >/dev/null 2>&1; then
        docker --context "$docker_context" logs "$container_name" \
            >"$result_dir/server.log" 2>&1 || true
        docker --context "$docker_context" rm -f "$container_name" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

sample_resources() {
    local pid=$1
    local samples=$2
    local output=$3
    local index
    local rss
    local threads
    : >"$output"
    for index in $(seq 1 "$samples"); do
        rss=$(ps -o rss= -p "$pid" | awk 'NF == 1 {print $1}')
        threads=$(ps -M -p "$pid" | awk 'NR > 1 { count += 1 } END { print count + 0 }')
        if [[ -n "$rss" ]] && ((threads > 0)); then
            printf '%s\t%s\t%s\n' "$index" "$rss" "$threads" >>"$output"
        fi
        sleep 1
    done
}

capture_interface_counters() {
    local interface=$1
    local direction=$2
    local phase=$3
    local output=$4
    local counters
    counters=$(perf_read_interface_counters "$interface")
    printf '%s\t%s\t%s\n' "$direction" "$phase" "$counters" >>"$output"
}

mkdir -p "$result_dir"
mkdir -p "$result_dir/iperf" "$result_dir/loaded-latency" "$result_dir/profiles" "$result_dir/resources"
perf_write_metadata "$result_dir" "native-macos-tun"
printf 'colima_profile=%s\ndocker_context=%s\nparallel_streams=%s\nencryption_algorithm=%s\nmtu=%s\nruntime_env=%s\nprofile_duration=%s\n' \
    "$colima_profile" "$docker_context" "$parallel_streams" "$encryption_algorithm" "$mtu" "$runtime_env" "$profile_duration" \
    >>"$result_dir/environment.txt"
colima -p "$colima_profile" status
sudo -n true
test -x "$binary"

docker --context "$docker_context" rm -f "$container_name" >/dev/null 2>&1 || true
docker --context "$docker_context" run -d \
    --name "$container_name" \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    "$image" \
    env $runtime_env /usr/local/bin/lowertier-core \
    --network-name macos-tun-bench \
    --network-secret macos-tun-bench-secret \
    --encryption-algorithm "$encryption_algorithm" \
    --mtu "$mtu" \
    --interface-adapter tun \
    --ipv4 10.91.0.2/24 \
    --no-listener \
    --peers "udp://host.docker.internal:${host_udp_port}" \
    --default-protocol udp \
    --disable-upnp true \
    --rpc-portal 127.0.0.1:15992 >/dev/null

sleep 1
if [[ $(docker --context "$docker_context" inspect -f '{{.State.Running}}' "$container_name") != true ]]; then
    docker --context "$docker_context" logs "$container_name" >"$result_dir/server.log" 2>&1 || true
    echo "the Linux benchmark node stopped before the macOS client started" >&2
    exit 1
fi

(
    cd "$result_dir"
    exec sudo -n env $runtime_env "$binary" \
        --network-name macos-tun-bench \
        --network-secret macos-tun-bench-secret \
        --encryption-algorithm "$encryption_algorithm" \
        --mtu "$mtu" \
        --interface-adapter tun \
        --ipv4 10.91.0.1/24 \
        --listeners "udp://0.0.0.0:${host_udp_port}" \
        --default-protocol udp \
        --disable-upnp true \
        --rpc-portal 127.0.0.1:15991
) >"$result_dir/client.log" 2>&1 &
client_pid=$!

for _ in {1..30}; do
    if ping -q -c 1 -W 1000 10.91.0.2 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
client_core_pid=$(pgrep -n -x lowertier-core)
client_ifname=$(sed -n 's/.*tun device ready dev="\([^"]*\)".*/\1/p' "$result_dir/client.log" | tail -1)
test -n "$client_ifname"
ping -q -c 20 -i 0.1 -W 1000 10.91.0.2 | tee "$result_dir/ping.txt"

docker --context "$docker_context" exec "$container_name" sh -lc \
    'pkill iperf3 2>/dev/null || true; iperf3 -s -D'

results="$result_dir/throughput.tsv"
perf_result_header | awk '{print "mode\t" $0}' | tee "$results"
for direction in forward reverse; do
    for run in $(seq 1 "$runs"); do
        reverse_flag=
        if [[ "$direction" == reverse ]]; then
            reverse_flag=-R
        fi
        iperf_json="$result_dir/iperf/${direction}-r${run}.json"
        iperf3 -c 10.91.0.2 --connect-timeout 3000 -t "$duration" -O 2 \
            -P "$parallel_streams" $reverse_flag -J >"$iperf_json"
        printf 'tun\t%s\n' "$(perf_parse_iperf_json "$direction" "$run" "$iperf_json")" \
            | tee -a "$results"
    done
done

cpu_results="$result_dir/lowertier-cpu.tsv"
resources="$result_dir/resources.tsv"
printf 'direction\tbits_per_second\tretransmits\taverage_lowertier_cpu\tmax_lowertier_cpu\tcpu_cores_per_gbit\n' \
    | tee "$cpu_results"
printf 'direction\taverage_rss_kib\tmax_rss_kib\taverage_threads\tmax_threads\n' \
    | tee "$resources"
for direction in forward reverse; do
    reverse_flag=
    if [[ "$direction" == reverse ]]; then
        reverse_flag=-R
    fi
    iperf_json="$result_dir/cpu-${direction}-iperf.json"
    top_output="$result_dir/cpu-${direction}-top.txt"
    resource_output="$result_dir/resources/${direction}.tsv"
    loaded_ping="$result_dir/loaded-latency/${direction}.txt"
    ping_count=$((cpu_duration * 20))
    ping -n -i 0.05 -c "$ping_count" 10.91.0.2 >"$loaded_ping" 2>&1 &
    loaded_ping_pid=$!
    sample_resources "$client_core_pid" "$cpu_duration" "$resource_output" &
    resource_sampler_pid=$!
    iperf3 -c 10.91.0.2 --connect-timeout 3000 -t "$cpu_duration" -O 2 \
        -P "$parallel_streams" $reverse_flag -J >"$iperf_json" &
    iperf_pid=$!
    top -l "$((cpu_duration + 1))" -s 1 -pid "$client_core_pid" \
        -stats pid,cpu,command >"$top_output"
    wait "$iperf_pid"
    wait "$loaded_ping_pid" || true
    loaded_ping_pid=
    wait "$resource_sampler_pid"
    resource_sampler_pid=
    cpu_row=$(jq -r --arg direction "$direction" --arg pid "$client_core_pid" \
        --rawfile top "$top_output" '
            ($top | split("\n") | map(select(test("^" + $pid + "\\s"))) | map(split(" ") | map(select(length > 0)) | .[1] | tonumber)) as $cpu
            | [$direction, .end.sum_received.bits_per_second, (.end.sum_sent.retransmits // 0), ($cpu | add / length), ($cpu | max)]
            | @tsv
        ' "$iperf_json")
    cpu_bps=$(cut -f2 <<<"$cpu_row")
    cpu_average=$(cut -f4 <<<"$cpu_row")
    cpu_cores_per_gbit=$(perf_cpu_cores_per_gbit "$cpu_average" "$cpu_bps")
    printf '%s\t%s\n' "$cpu_row" "$cpu_cores_per_gbit" | tee -a "$cpu_results"
    awk -v direction="$direction" '
        NF == 3 { rss += $2; threads += $3; count += 1; if ($2 > max_rss) max_rss = $2; if ($3 > max_threads) max_threads = $3 }
        END { if (count > 0) printf "%s\t%.2f\t%d\t%.2f\t%d\n", direction, rss / count, max_rss, threads / count, max_threads }
    ' "$resource_output" | tee -a "$resources"
done

interface_counters="$result_dir/interface-counters.tsv"
printf 'direction\tphase\tinput_packets\tinput_bytes\toutput_packets\toutput_bytes\n' \
    >"$interface_counters"
if ((profile_duration > 0)); then
    for direction in forward reverse; do
        reverse_flag=
        if [[ "$direction" == reverse ]]; then
            reverse_flag=-R
        fi
        capture_interface_counters "$client_ifname" "$direction" before "$interface_counters"
        profile_iperf="$result_dir/profiles/${direction}-sample-iperf.json"
        iperf3 -c 10.91.0.2 --connect-timeout 3000 -t "$profile_duration" -O 1 \
            -P "$parallel_streams" $reverse_flag -J >"$profile_iperf" &
        profile_iperf_pid=$!
        sudo -n sample "$client_core_pid" "$profile_duration" 5 \
            -file "$result_dir/profiles/${direction}.sample.txt" >/dev/null
        wait "$profile_iperf_pid"
        capture_interface_counters "$client_ifname" "$direction" after "$interface_counters"

        sc_usage_output="$result_dir/profiles/${direction}.sc-usage.txt"
        sudo -n sc_usage -l -s1 "$client_core_pid" >"$sc_usage_output" 2>&1 &
        sc_usage_pid=$!
        iperf3 -c 10.91.0.2 --connect-timeout 3000 -t "$profile_duration" -O 1 \
            -P "$parallel_streams" $reverse_flag -J \
            >"$result_dir/profiles/${direction}-sc-usage-iperf.json"
        sudo -n kill "$sc_usage_pid" 2>/dev/null || true
        wait "$sc_usage_pid" 2>/dev/null || true
        sc_usage_pid=
    done
fi

sudo -n vmmap -summary "$client_core_pid" >"$result_dir/profiles/vmmap-summary.txt"
echo "results: $result_dir"
