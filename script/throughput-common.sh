#!/usr/bin/env bash

# Shared, side-effect-light helpers for EasyTier throughput harnesses.
# The caller owns `set -euo pipefail` so this file can also be sourced by tests.

perf_result_header() {
    printf '%s\n' \
        $'direction\trun\tprotocol\tstreams\toffered_bps\treceived_bps\tretransmits\tlost_percent\thost_cpu_percent\tremote_cpu_percent'
}

perf_parse_iperf_json() {
    local direction=$1
    local run=$2
    local json_file=$3

    jq -er \
        --arg direction "$direction" \
        --arg run "$run" '
            (.start.test_start.protocol | strings | ascii_downcase) as $protocol
            | (.start.test_start.num_streams | numbers) as $streams
            | (.end.sum_received.bits_per_second | numbers) as $received
            | (.end.cpu_utilization_percent.host_total | numbers) as $host_cpu
            | (.end.cpu_utilization_percent.remote_total | numbers) as $remote_cpu
            | [
                $direction,
                ($run | tonumber),
                $protocol,
                $streams,
                (if $protocol == "udp" then (.start.test_start.target_bitrate | numbers) else 0 end),
                $received,
                (if $protocol == "tcp" then (.end.sum_sent.retransmits // 0 | numbers) else 0 end),
                (if $protocol == "udp" then (.end.sum_received.lost_percent // 0 | numbers) else 0 end),
                $host_cpu,
                $remote_cpu
            ]
            | @tsv
        ' "$json_file"
}

perf_cpu_cores_per_gbit() {
    local cpu_percent=$1
    local bits_per_second=$2

    jq -nr \
        --argjson cpu_percent "$cpu_percent" \
        --argjson bits_per_second "$bits_per_second" '
            if $bits_per_second <= 0 then
                "nan"
            else
                (($cpu_percent / 100) / ($bits_per_second / 1000000000))
                | "\(. * 1000000 | round / 1000000)"
                | if contains(".") then
                    . + ("000000"[0:(6 - (split(".")[1] | length))])
                  else
                    . + ".000000"
                  end
            end
        '
}

perf_parse_netstat_link_counters() {
    local interface=$1
    awk -v interface="$interface" '
        $1 == interface && $3 ~ /^<Link/ {
            printf "%s\t%s\t%s\t%s\n", $4, $6, $7, $9
            found = 1
            exit
        }
        END { if (!found) exit 1 }
    '
}

perf_read_interface_counters() {
    local interface=$1
    netstat -ibn -I "$interface" | perf_parse_netstat_link_counters "$interface"
}

perf_write_metadata() {
    local result_dir=$1
    local context=$2
    local repo_root
    repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

    mkdir -p "$result_dir"
    {
        printf 'context=%s\n' "$context"
        printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'git_revision=%s\n' "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)"
        printf 'uname=%s\n' "$(uname -a)"
        if command -v sw_vers >/dev/null 2>&1; then
            printf 'macos_product=%s\n' "$(sw_vers -productVersion)"
        fi
        if command -v colima >/dev/null 2>&1; then
            printf 'colima_version=%s\n' "$(colima version 2>/dev/null | head -1)"
        fi
        if command -v docker >/dev/null 2>&1; then
            printf 'docker_version=%s\n' "$(docker version --format '{{.Client.Version}}' 2>/dev/null || printf unavailable)"
        fi
    } >"$result_dir/environment.txt"
}
