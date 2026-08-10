#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$repo_root/script/throughput-common.sh"

runs=${RUNS:-3}
duration=${DURATION:-10}
cpu_duration=${CPU_DURATION:-15}
profile_duration=${PROFILE_DURATION:-0}
parallel_streams=${PARALLEL_STREAMS:-8}
mtu=${MTU:-1360}
colima_profile=${COLIMA_PROFILE:-easytier-l2}
docker_context=${DOCKER_CONTEXT:-colima-easytier-l2}
image=${WIREGUARD_TEST_IMAGE:-easytier-wireguard-bench:local}
build_image=${BUILD_IMAGE:-1}
host_udp_port=${HOST_UDP_PORT:-12020}
container_name=easytier-wireguard-macos-bench
result_dir=${RESULT_DIR:-$(mktemp -d -t easytier-wireguard-macos-bench.XXXXXX)}
wireguard_go_revision=2e01ba5b00f0
go_path=$(go env GOPATH)
wireguard_go_source=${WIREGUARD_GO_SOURCE:-$go_path/pkg/mod/github.com/tailscale/wireguard-go@v0.0.0-20260715223240-2e01ba5b00f0}
wireguard_go_binary=${WIREGUARD_GO_BINARY:-/tmp/easytier-wireguard-go-$wireguard_go_revision}

utun_name=
uapi_socket=
wg_launcher_pid=
wg_pid=
resource_sampler_pid=
loaded_ping_pid=
sc_usage_pid=

cleanup() {
    if [[ -n "$resource_sampler_pid" ]]; then
        kill "$resource_sampler_pid" 2>/dev/null || true
        wait "$resource_sampler_pid" 2>/dev/null || true
    fi
    if [[ -n "$loaded_ping_pid" ]]; then
        kill "$loaded_ping_pid" 2>/dev/null || true
        wait "$loaded_ping_pid" 2>/dev/null || true
    fi
    if [[ -n "$sc_usage_pid" ]]; then
        sudo -n kill "$sc_usage_pid" 2>/dev/null || true
        wait "$sc_usage_pid" 2>/dev/null || true
    fi
    if [[ -n "$utun_name" ]]; then
        sudo -n route -n delete -host 10.92.0.2 -interface "$utun_name" >/dev/null 2>&1 || true
    fi
    if [[ -n "$wg_pid" ]]; then
        sudo -n kill "$wg_pid" 2>/dev/null || true
    fi
    if [[ -n "$wg_launcher_pid" ]]; then
        kill "$wg_launcher_pid" 2>/dev/null || true
        wait "$wg_launcher_pid" 2>/dev/null || true
    fi
    if [[ -n "$uapi_socket" ]]; then
        sudo -n rm -f "$uapi_socket" 2>/dev/null || true
    fi
    docker --context "$docker_context" rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

base64_to_hex() {
    python3 -c 'import base64,sys; sys.stdout.write(base64.b64decode(sys.stdin.buffer.read()).hex())'
}

select_utun() {
    local unit
    for unit in $(seq 70 99); do
        if ! ifconfig "utun$unit" >/dev/null 2>&1 \
            && [[ ! -e "/var/run/wireguard/utun$unit.sock" ]]; then
            printf 'utun%s\n' "$unit"
            return 0
        fi
    done
    return 1
}

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

test -d "$wireguard_go_source"
sudo -n true
command -v go >/dev/null
command -v iperf3 >/dev/null
command -v jq >/dev/null

mkdir -p "$result_dir/iperf" "$result_dir/loaded-latency" "$result_dir/profiles" "$result_dir/resources"
perf_write_metadata "$result_dir" "native-macos-wireguard"
printf 'colima_profile=%s\ndocker_context=%s\nparallel_streams=%s\nmtu=%s\nwireguard_go_revision=%s\nprofile_duration=%s\n' \
    "$colima_profile" "$docker_context" "$parallel_streams" "$mtu" "$wireguard_go_revision" "$profile_duration" \
    >>"$result_dir/environment.txt"

if [[ ! -x "$wireguard_go_binary" ]]; then
    (
        cd "$wireguard_go_source"
        go build -trimpath -o "$wireguard_go_binary" .
    )
fi

colima -p "$colima_profile" status
if [[ "$build_image" == 1 ]]; then
    docker --context "$docker_context" build -q \
        -f "$repo_root/script/wireguard-macos-bench/Dockerfile" \
        -t "$image" "$repo_root/script/wireguard-macos-bench" >/dev/null
fi

docker --context "$docker_context" rm -f "$container_name" >/dev/null 2>&1 || true
docker --context "$docker_context" run -d \
    --name "$container_name" \
    --privileged \
    -p "${host_udp_port}:51820/udp" \
    "$image" >/dev/null

mac_private=$(docker --context "$docker_context" exec "$container_name" wg genkey)
mac_public=$(printf '%s\n' "$mac_private" \
    | docker --context "$docker_context" exec -i "$container_name" wg pubkey)
linux_private=$(docker --context "$docker_context" exec "$container_name" wg genkey)
linux_public=$(printf '%s\n' "$linux_private" \
    | docker --context "$docker_context" exec -i "$container_name" wg pubkey)
mac_private_hex=$(printf '%s' "$mac_private" | base64_to_hex)
linux_public_hex=$(printf '%s' "$linux_public" | base64_to_hex)

printf '%s\n' "$linux_private" \
    | docker --context "$docker_context" exec -i "$container_name" sh -c \
        'umask 077; cat >/tmp/wireguard-private-key'
docker --context "$docker_context" exec "$container_name" ip link add wg0 type wireguard
docker --context "$docker_context" exec "$container_name" wg set wg0 \
    private-key /tmp/wireguard-private-key \
    listen-port 51820 \
    peer "$mac_public" \
    allowed-ips 10.92.0.1/32
docker --context "$docker_context" exec "$container_name" rm -f /tmp/wireguard-private-key
docker --context "$docker_context" exec "$container_name" ip address add 10.92.0.2/24 dev wg0
docker --context "$docker_context" exec "$container_name" ip link set mtu "$mtu" up dev wg0

utun_name=$(select_utun)
uapi_socket="/var/run/wireguard/$utun_name.sock"
(
    exec sudo -n env LOG_LEVEL=error "$wireguard_go_binary" -f "$utun_name"
) >"$result_dir/wireguard-go.log" 2>&1 &
wg_launcher_pid=$!

for _ in $(seq 1 100); do
    if sudo -n test -S "$uapi_socket" && ifconfig "$utun_name" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
sudo -n test -S "$uapi_socket"
wg_pid=$(pgrep -n -f "$wireguard_go_binary.*-f $utun_name")

uapi_response=$(
    {
        printf 'set=1\n'
        printf 'private_key=%s\n' "$mac_private_hex"
        printf 'listen_port=0\n'
        printf 'public_key=%s\n' "$linux_public_hex"
        printf 'endpoint=127.0.0.1:%s\n' "$host_udp_port"
        printf 'allowed_ip=10.92.0.2/32\n'
        printf 'persistent_keepalive_interval=5\n\n'
    } | sudo -n nc -U -w 2 "$uapi_socket"
)
grep -q 'errno=0' <<<"$uapi_response"

sudo -n ifconfig "$utun_name" inet 10.92.0.1 10.92.0.1 mtu "$mtu" up
sudo -n route -n add -host 10.92.0.2 -interface "$utun_name" >/dev/null

for _ in $(seq 1 30); do
    if ping -q -c 1 -W 1000 10.92.0.2 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
ping -q -c 20 -i 0.1 -W 1000 10.92.0.2 | tee "$result_dir/ping.txt"

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
        iperf3 -c 10.92.0.2 --connect-timeout 3000 -t "$duration" -O 2 \
            -P "$parallel_streams" $reverse_flag -J >"$iperf_json"
        printf 'wireguard\t%s\n' "$(perf_parse_iperf_json "$direction" "$run" "$iperf_json")" \
            | tee -a "$results"
    done
done

cpu_results="$result_dir/wireguard-cpu.tsv"
resources="$result_dir/resources.tsv"
printf 'direction\tbits_per_second\tretransmits\taverage_wireguard_cpu\tmax_wireguard_cpu\tcpu_cores_per_gbit\n' \
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
    ping -n -i 0.05 -c "$ping_count" 10.92.0.2 >"$loaded_ping" 2>&1 &
    loaded_ping_pid=$!
    sample_resources "$wg_pid" "$cpu_duration" "$resource_output" &
    resource_sampler_pid=$!
    iperf3 -c 10.92.0.2 --connect-timeout 3000 -t "$cpu_duration" -O 2 \
        -P "$parallel_streams" $reverse_flag -J >"$iperf_json" &
    iperf_pid=$!
    top -l "$((cpu_duration + 1))" -s 1 -pid "$wg_pid" \
        -stats pid,cpu,command >"$top_output"
    wait "$iperf_pid"
    wait "$loaded_ping_pid" || true
    loaded_ping_pid=
    wait "$resource_sampler_pid"
    resource_sampler_pid=

    cpu_row=$(jq -r --arg direction "$direction" --arg pid "$wg_pid" \
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
        capture_interface_counters "$utun_name" "$direction" before "$interface_counters"
        profile_iperf="$result_dir/profiles/${direction}-sample-iperf.json"
        iperf3 -c 10.92.0.2 --connect-timeout 3000 -t "$profile_duration" -O 1 \
            -P "$parallel_streams" $reverse_flag -J >"$profile_iperf" &
        profile_iperf_pid=$!
        sudo -n sample "$wg_pid" "$profile_duration" 5 \
            -file "$result_dir/profiles/${direction}.sample.txt" >/dev/null
        wait "$profile_iperf_pid"
        capture_interface_counters "$utun_name" "$direction" after "$interface_counters"

        sc_usage_output="$result_dir/profiles/${direction}.sc-usage.txt"
        sudo -n sc_usage -l -s1 "$wg_pid" >"$sc_usage_output" 2>&1 &
        sc_usage_pid=$!
        iperf3 -c 10.92.0.2 --connect-timeout 3000 -t "$profile_duration" -O 1 \
            -P "$parallel_streams" $reverse_flag -J \
            >"$result_dir/profiles/${direction}-sc-usage-iperf.json"
        sudo -n kill "$sc_usage_pid" 2>/dev/null || true
        wait "$sc_usage_pid" 2>/dev/null || true
        sc_usage_pid=
    done
fi

docker --context "$docker_context" exec "$container_name" wg show >"$result_dir/wireguard-peer.txt"
sudo -n vmmap -summary "$wg_pid" >"$result_dir/profiles/vmmap-summary.txt"
echo "results: $result_dir"
