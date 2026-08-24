#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
harness="$repo_root/script/kernel-wireguard-bench/e2e.sh"
readme="$repo_root/script/kernel-wireguard-bench/README.md"
dockerfile="$repo_root/script/wireguard-macos-bench/Dockerfile"

test -f "$harness"
test -f "$readme"
test -x "$harness"
grep -q '^set -euo pipefail$' "$harness"
grep -q '^umask 077$' "$harness"
grep -q 'trap cleanup EXIT INT TERM' "$harness"
grep -q 'LOWTIER_KERNEL_WG_NODE_A' "$harness"
grep -q 'LOWTIER_KERNEL_WG_NODE_B' "$harness"
grep -q 'ip link add wg0 type wireguard' "$harness"
grep -q 'grep -w wireguard /proc/modules' "$harness"
grep -q 'ip -d link show wg0' "$harness"
grep -q 'wg show wg0' "$harness"
grep -q 'private-key /tmp/wireguard-private-key' "$harness"
grep -q 'IPERF_TIMEOUT_SECONDS' "$harness"
grep -q 'STREAM_COUNTS' "$harness"
grep -q 'raw_gate_bps' "$harness"
grep -q 'vm-cpu-cores-per-gbit.tsv' "$harness"
grep -q 'perf_parse_iperf_json' "$harness"
grep -q 'workload-errors.tsv' "$harness"
grep -q 'wireguard-tools' "$dockerfile"
grep -q 'kernel WireGuard' "$readme"
grep -q 'wireguard-go' "$readme"

if grep -Eq 'environment\.txt.*private|private_[ab].*environment\.txt' "$harness"; then
    echo "the harness must not persist private WireGuard keys" >&2
    exit 1
fi

bash -n "$harness"
echo "kernel WireGuard benchmark static tests passed"
