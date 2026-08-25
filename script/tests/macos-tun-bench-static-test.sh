#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
harness="$repo_root/script/macos-tun-bench/e2e.sh"
readme="$repo_root/script/macos-tun-bench/README.md"

test -f "$harness"
test -f "$readme"
grep -q '^set -euo pipefail$' "$harness"
grep -q 'throughput-common.sh' "$harness"
grep -q 'PARALLEL_STREAMS' "$harness"
grep -q 'perf_write_metadata' "$harness"
grep -q 'perf_parse_iperf_json' "$harness"
grep -q 'loaded-latency' "$harness"
grep -q 'cpu_cores_per_gbit' "$harness"
grep -q 'perf_cpu_cores_per_gbit' "$harness"
grep -q 'resources.tsv' "$harness"
grep -q 'PROFILE_DURATION' "$harness"
grep -q 'sudo -n sample "$client_core_pid"' "$harness"
grep -q 'sudo -n sc_usage -l' "$harness"
grep -q 'sudo -n vmmap -summary "$client_core_pid"' "$harness"
grep -q 'perf_read_interface_counters' "$harness"
grep -q 'interface-counters.tsv' "$harness"
grep -q 'ENCRYPTION_ALGORITHM' "$harness"
grep -q -- '--encryption-algorithm' "$harness"
! grep -q -- '--interface-adapter' "$harness"
grep -q 'mtu=${MTU:-1360}' "$harness"
grep -q -- '--mtu "$mtu"' "$harness"
grep -q -- '--rpc-portal 127.0.0.1:15992' "$harness"
grep -q 'server.log' "$harness"
grep -q 'host.docker.internal' "$harness"
grep -q -- '--listeners "udp://0.0.0.0:${host_udp_port}"' "$harness"
if grep -q -- '-p "${host_udp_port}:11010/udp"' "$harness"; then
    echo "the macOS TUN benchmark must not use the Colima UDP port forwarder" >&2
    exit 1
fi
grep -q 'trap cleanup EXIT INT TERM' "$harness"
grep -q 'CPU per Gbit' "$readme"
grep -q 'port forwarding' "$readme"

bash -n "$harness"
echo "macos tun benchmark static tests passed"
