#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
probe="$repo_root/script/tests/userspace_proxy_probe.py"
core=${LOWTIER_CORE:-"$repo_root/target/debug/lowertier-core"}
benchmark_bytes=${USERSPACE_BENCHMARK_BYTES:-67108864}
benchmark_runs=${USERSPACE_BENCHMARK_RUNS:-5}
rtt_runs=${USERSPACE_RTT_RUNS:-101}
setup_runs=${USERSPACE_SETUP_RUNS:-11}
result_file=${USERSPACE_RESULT_FILE:-}
run_dir=$(mktemp -d -t lowertier-userspace-proxy.XXXXXX)

server_pid=
client_pid=
probe_pid=
service_pid=

cleanup() {
    for pid in "$probe_pid" "$client_pid" "$server_pid" "$service_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    rm -rf "$run_dir"
}
trap cleanup EXIT INT TERM

if [[ ! -f "$probe" ]]; then
    echo "The userspace proxy probe is missing: $probe" >&2
    exit 1
fi

if [[ ! -x "$core" ]]; then
    cargo build \
        --manifest-path "$repo_root/Cargo.toml" \
        --locked \
        -p lowertier \
        --bin lowertier-core \
        --no-default-features \
        --features socks5,quic
fi

read -r underlay_port proxy_port tcp_port udp_port http_port server_rpc_port client_rpc_port < <(
    python3 "$probe" ports
)

list_interfaces() {
    if [[ -d /sys/class/net ]]; then
        find /sys/class/net -mindepth 1 -maxdepth 1 -exec basename {} \; | sort
    else
        ifconfig -l | tr ' ' '\n' | sed '/^$/d' | sort
    fi
}

sample_rss_kib() {
    local pid=$1
    ps -o rss= -p "$pid" | tr -d ' '
}

median_values() {
    sort -n | awk '{ values[NR] = $1 } END {
        if (NR == 0) {
            print 0
        } else if (NR % 2 == 1) {
            print values[(NR + 1) / 2]
        } else {
            print int((values[NR / 2] + values[NR / 2 + 1]) / 2)
        }
    }'
}

wait_for_socks() {
    local attempt
    for attempt in {1..80}; do
        if curl \
            --silent \
            --show-error \
            --fail \
            --max-time 2 \
            --noproxy '' \
            --socks5-hostname "127.0.0.1:$proxy_port" \
            "http://10.77.0.2:$http_port/probe" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

start_client() {
    local mode=$1
    local instance_name=$2
    local http_proxy_arg=
    if [[ "$mode" == shared ]]; then
        http_proxy_arg="--outbound-http-proxy-listen=127.0.0.1:$proxy_port"
    fi

    RUST_LOG=warn "$core" \
        --instance-name "$instance_name" \
        --network-name userspace-proxy-test \
        --network-secret userspace-proxy-secret \
        --ipv4 10.77.0.1 \
        --tun=userspace-networking \
        --no-listener \
        --rpc-portal="127.0.0.1:$client_rpc_port" \
        --peers "udp://127.0.0.1:$underlay_port" \
        --socks5-server="127.0.0.1:$proxy_port" \
        ${http_proxy_arg:+"$http_proxy_arg"} \
        --disable-ipv6=true \
        --disable-upnp=true \
        --disable-p2p=true \
        >"$run_dir/$instance_name.log" 2>&1 &
    client_pid=$!
}

list_interfaces >"$run_dir/interfaces-before"

python3 "$probe" server \
    --tcp-port "$tcp_port" \
    --udp-port "$udp_port" \
    --http-port "$http_port" \
    >"$run_dir/service.log" 2>&1 &
service_pid=$!

RUST_LOG=warn "$core" \
    --instance-name userspace-proxy-server \
    --network-name userspace-proxy-test \
    --network-secret userspace-proxy-secret \
    --hostname userspace-proxy-server \
    --ipv4 10.77.0.2 \
    --tun=userspace-networking \
    --listeners "udp://127.0.0.1:$underlay_port" \
    --rpc-portal="127.0.0.1:$server_rpc_port" \
    --disable-ipv6=true \
    --disable-upnp=true \
    --disable-p2p=true \
    >"$run_dir/server.log" 2>&1 &
server_pid=$!

start_client shared userspace-proxy-client-shared

if ! wait_for_socks; then
    sed -n '1,240p' "$run_dir/server.log" >&2
    sed -n '1,320p' "$run_dir/userspace-proxy-client-shared.log" >&2
    exit 1
fi

shared_rss_samples="$run_dir/shared-rss"
for _ in {1..10}; do
    sample_rss_kib "$client_pid" >>"$shared_rss_samples"
    sleep 0.1
done
shared_idle_rss_kib=$(median_values <"$shared_rss_samples")

python3 "$probe" client \
    --proxy-port "$proxy_port" \
    --target-ip 10.77.0.2 \
    --target-hostname userspace-proxy-server.et.net \
    --tcp-port "$tcp_port" \
    --udp-port "$udp_port" \
    --http-port "$http_port" \
    --benchmark-bytes "$benchmark_bytes" \
    --benchmark-runs "$benchmark_runs" \
    --rtt-runs "$rtt_runs" \
    --setup-runs "$setup_runs" \
    --output "$run_dir/results.json" &
probe_pid=$!

active_rss_kib=$shared_idle_rss_kib
while kill -0 "$probe_pid" 2>/dev/null; do
    current_rss_kib=$(sample_rss_kib "$client_pid")
    if (( current_rss_kib > active_rss_kib )); then
        active_rss_kib=$current_rss_kib
    fi
    sleep 0.05
done
if ! wait "$probe_pid"; then
    sed -n '1,240p' "$run_dir/server.log" >&2
    sed -n '1,400p' "$run_dir/userspace-proxy-client-shared.log" >&2
    exit 1
fi
probe_pid=

list_interfaces >"$run_dir/interfaces-after"
if ! diff -u "$run_dir/interfaces-before" "$run_dir/interfaces-after" >"$run_dir/interfaces.diff"; then
    cat "$run_dir/interfaces.diff" >&2
    echo "Userspace mode changed the operating system interface list." >&2
    exit 1
fi

kill "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=
sleep 0.5

start_client socks-only userspace-proxy-client-socks
if ! wait_for_socks; then
    sed -n '1,320p' "$run_dir/userspace-proxy-client-socks.log" >&2
    exit 1
fi

socks_rss_samples="$run_dir/socks-rss"
for _ in {1..10}; do
    sample_rss_kib "$client_pid" >>"$socks_rss_samples"
    sleep 0.1
done
socks_idle_rss_kib=$(median_values <"$socks_rss_samples")

python3 - "$run_dir/results.json" \
    "$shared_idle_rss_kib" "$socks_idle_rss_kib" "$active_rss_kib" <<'PY'
import json
import sys

path, shared_idle, socks_idle, active = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    results = json.load(source)
results["memory_kib"] = {
    "shared_idle": int(shared_idle),
    "socks_only_idle": int(socks_idle),
    "shared_active_peak": int(active),
    "shared_minus_socks_idle": int(shared_idle) - int(socks_idle),
}
results["interface_check"] = "no interface changes"
results["effective_uid"] = __import__("os").geteuid()
with open(path, "w", encoding="utf-8") as destination:
    json.dump(results, destination, indent=2, sort_keys=True)
    destination.write("\n")
PY

if [[ -n "$result_file" ]]; then
    cp "$run_dir/results.json" "$result_file"
fi

cat "$run_dir/results.json"
echo "Userspace proxy tests passed"
