#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
harness="$repo_root/script/wireguard-macos-bench/e2e.sh"
dockerfile="$repo_root/script/wireguard-macos-bench/Dockerfile"
readme="$repo_root/script/wireguard-macos-bench/README.md"

test -f "$harness"
test -f "$dockerfile"
test -f "$readme"
grep -q '^set -euo pipefail$' "$harness"
grep -q '^umask 077$' "$harness"
grep -q 'trap cleanup EXIT INT TERM' "$harness"
grep -q 'sudo -n test -S "$uapi_socket"' "$harness"
grep -q 'WIREGUARD_GO_SOURCE' "$harness"
grep -q 'mtu=${MTU:-1360}' "$harness"
grep -q 'wg genkey' "$harness"
grep -q 'mac_private_hex' "$harness"
grep -q 'private_key=' "$harness"
grep -q 'endpoint=127.0.0.1:%s' "$harness"
grep -q -- '-p "${host_udp_port}:51820/udp"' "$harness"
grep -q 'throughput.tsv' "$harness"
grep -q 'resources.tsv' "$harness"
grep -q 'ps -M -p "$pid"' "$harness"
grep -q 'sudo -n vmmap -summary "$wg_pid"' "$harness"
grep -q 'PROFILE_DURATION' "$harness"
grep -q 'sudo -n sample "$wg_pid"' "$harness"
grep -q 'sudo -n sc_usage -l' "$harness"
grep -q 'perf_read_interface_counters' "$harness"
grep -q 'interface-counters.tsv' "$harness"
grep -q 'profiles' "$harness"
grep -q 'perf_cpu_cores_per_gbit' "$harness"
grep -q 'perf_write_metadata' "$harness"
grep -q 'wireguard-tools' "$dockerfile"
grep -q 'iperf3' "$dockerfile"
grep -q 'kernel' "$readme"
grep -q 'WireGuard' "$readme"
grep -q 'macOS' "$readme"

if grep -Eq 'environment\.txt.*(private|secret)|mac_private.*environment\.txt' "$harness"; then
    echo "private WireGuard key must not be persisted" >&2
    exit 1
fi

bash -n "$harness"
echo "wireguard macos benchmark static tests passed"
