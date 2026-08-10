#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docker_context="${COLIMA_DOCKER_CONTEXT:-colima-easytier-l2}"
image_name="easytier-l2-qemu-test:local"
network_name="easytier-l2-qemu-net"
nodes=(easytier-qemu-a easytier-qemu-b easytier-qemu-c)

docker_cmd=(docker --context "${docker_context}")

cleanup() {
    for node in "${nodes[@]}"; do
        "${docker_cmd[@]}" rm -f "${node}" >/dev/null 2>&1 || true
    done
    "${docker_cmd[@]}" network rm "${network_name}" >/dev/null 2>&1 || true
}

wait_for_interface() {
    local node="$1"
    local attempt
    for attempt in $(seq 1 60); do
        if "${docker_cmd[@]}" exec "${node}" ip link show et0 >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "${node} did not create et0" >&2
    "${docker_cmd[@]}" exec "${node}" cat /tmp/easytier.log || true
    return 1
}

wait_for_ping() {
    local node="$1"
    local destination="$2"
    local attempt
    for attempt in $(seq 1 30); do
        if "${docker_cmd[@]}" exec "${node}" ping -n -c 1 -W 2 "${destination}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "${node} could not reach ${destination}" >&2
    return 1
}

wait_for_file() {
    local node="$1"
    local path="$2"
    local attempt
    for attempt in $(seq 1 140); do
        if "${docker_cmd[@]}" exec "${node}" test -f "${path}"; then
            return 0
        fi
        sleep 0.05
    done
    echo "${node} did not create ${path}" >&2
    return 1
}

start_frame_receiver() {
    local node="$1"
    local case_name="$2"
    local source_mac="$3"
    local destination_mac="$4"
    local token="$5"
    local suffix="$6"
    local frame_size="${7:-128}"
    local expectation="${8:-receive}"
    local ready_file="/tmp/frame-${suffix}.ready"
    local result_file="/tmp/frame-${suffix}.result"
    local args=(
        python3 /usr/local/bin/frame_probe.py receive
        --interface et0
        --case "${case_name}"
        --source-mac "${source_mac}"
        --destination-mac "${destination_mac}"
        --token "${token}"
        --frame-size "${frame_size}"
        --ready-file "${ready_file}"
        --result-file "${result_file}"
    )
    if [[ "${expectation}" == "timeout" ]]; then
        args+=(--expect-timeout --timeout 1.5)
    fi
    "${docker_cmd[@]}" exec "${node}" rm -f "${ready_file}" "${result_file}"
    "${docker_cmd[@]}" exec -d "${node}" "${args[@]}"
    wait_for_file "${node}" "${ready_file}"
}

check_frame_result() {
    local node="$1"
    local suffix="$2"
    local result_file="/tmp/frame-${suffix}.result"
    wait_for_file "${node}" "${result_file}"
    local result
    result="$("${docker_cmd[@]}" exec "${node}" cat "${result_file}")"
    if [[ "${result}" != "PASS" ]]; then
        echo "${node} ${suffix}: ${result}" >&2
        return 1
    fi
}

send_frame() {
    local node="$1"
    local case_name="$2"
    local source_mac="$3"
    local destination_mac="$4"
    local token="$5"
    local frame_size="${6:-128}"
    "${docker_cmd[@]}" exec "${node}" python3 /usr/local/bin/frame_probe.py send \
        --interface et0 \
        --case "${case_name}" \
        --source-mac "${source_mac}" \
        --destination-mac "${destination_mac}" \
        --token "${token}" \
        --frame-size "${frame_size}"
}

run_exact_frame_check() {
    local case_name="$1"
    local source_node="$2"
    local destination_node="$3"
    local source_mac="$4"
    local destination_mac="$5"
    local token="$6"
    local frame_size="${7:-128}"
    local suffix="${case_name}-${token}"
    echo "Frame case: ${case_name}"
    start_frame_receiver "${destination_node}" "${case_name}" "${source_mac}" \
        "${destination_mac}" "${token}" "${suffix}" "${frame_size}"
    send_frame "${source_node}" "${case_name}" "${source_mac}" \
        "${destination_mac}" "${token}" "${frame_size}"
    check_frame_result "${destination_node}" "${suffix}"
}

run_tap_frame_matrix() {
    local mac_a
    local mac_b
    local mac_c
    local tap_mtu
    local maximum_frame_size
    mac_a="$("${docker_cmd[@]}" exec "${nodes[0]}" cat /sys/class/net/et0/address)"
    mac_b="$("${docker_cmd[@]}" exec "${nodes[1]}" cat /sys/class/net/et0/address)"
    mac_c="$("${docker_cmd[@]}" exec "${nodes[2]}" cat /sys/class/net/et0/address)"
    tap_mtu="$("${docker_cmd[@]}" exec "${nodes[0]}" cat /sys/class/net/et0/mtu)"
    maximum_frame_size=$((tap_mtu + 14))

    run_exact_frame_check unknown-ethertype "${nodes[0]}" "${nodes[2]}" \
        "${mac_a}" "${mac_c}" 01010101
    run_exact_frame_check vlan-8021q "${nodes[0]}" "${nodes[2]}" \
        "${mac_a}" "${mac_c}" 02020202
    run_exact_frame_check qinq-8021ad "${nodes[0]}" "${nodes[2]}" \
        "${mac_a}" "${mac_c}" 03030303
    run_exact_frame_check lldp-multicast "${nodes[0]}" "${nodes[2]}" \
        "${mac_a}" 01:80:c2:00:00:0e 04040404
    run_exact_frame_check broadcast "${nodes[0]}" "${nodes[2]}" \
        "${mac_a}" ff:ff:ff:ff:ff:ff 05050505
    run_exact_frame_check mtu-boundary "${nodes[0]}" "${nodes[2]}" \
        "${mac_a}" "${mac_c}" 06060606 "${maximum_frame_size}"

    local learned_mac="02:ee:00:00:00:44"
    run_exact_frame_check broadcast "${nodes[1]}" "${nodes[0]}" \
        "${learned_mac}" ff:ff:ff:ff:ff:ff 07070707
    start_frame_receiver "${nodes[1]}" known-unicast "${mac_a}" "${learned_mac}" \
        08080808 known-b
    start_frame_receiver "${nodes[2]}" known-unicast "${mac_a}" "${learned_mac}" \
        08080808 known-c 128 timeout
    send_frame "${nodes[0]}" known-unicast "${mac_a}" "${learned_mac}" 08080808
    check_frame_result "${nodes[1]}" known-b
    check_frame_result "${nodes[2]}" known-c

    local unknown_mac="02:ee:00:00:00:99"
    start_frame_receiver "${nodes[1]}" unknown-unicast "${mac_a}" "${unknown_mac}" \
        09090909 unknown-b
    start_frame_receiver "${nodes[2]}" unknown-unicast "${mac_a}" "${unknown_mac}" \
        09090909 unknown-c
    send_frame "${nodes[0]}" unknown-unicast "${mac_a}" "${unknown_mac}" 09090909
    check_frame_result "${nodes[1]}" unknown-b
    check_frame_result "${nodes[2]}" unknown-c

    run_exact_frame_check broadcast "${nodes[2]}" "${nodes[0]}" \
        "${learned_mac}" ff:ff:ff:ff:ff:ff 0a0a0a0a
    start_frame_receiver "${nodes[1]}" mac-move "${mac_a}" "${learned_mac}" \
        0b0b0b0b move-b 128 timeout
    start_frame_receiver "${nodes[2]}" mac-move "${mac_a}" "${learned_mac}" \
        0b0b0b0b move-c
    send_frame "${nodes[0]}" mac-move "${mac_a}" "${learned_mac}" 0b0b0b0b
    check_frame_result "${nodes[1]}" move-b
    check_frame_result "${nodes[2]}" move-c

    "${docker_cmd[@]}" exec "${nodes[0]}" python3 /usr/local/bin/frame_probe.py send \
        --interface et0 \
        --case oversized-frame \
        --source-mac "${mac_a}" \
        --destination-mac "${mac_c}" \
        --token 0c0c0c0c \
        --frame-size "$((maximum_frame_size + 1))" \
        --expect-send-error
}

assert_stable_ping() {
    local node="$1"
    local destination="$2"
    local output

    wait_for_ping "${node}" "${destination}"
    output="$("${docker_cmd[@]}" exec "${node}" ping -n -c 3 -W 2 "${destination}")"
    printf '%s\n' "${output}"
    grep -q '0% packet loss' <<<"${output}"
}

start_node() {
    local node="$1"
    local mode="$2"
    local overlay_ip="$3"
    local peer_url="${4:-}"

    "${docker_cmd[@]}" run -d \
        --name "${node}" \
        --network "${network_name}" \
        --cap-add NET_ADMIN \
        --device /dev/net/tun \
        "${image_name}" sleep infinity >/dev/null

    local args=(
        easytier-core
        --network-name colima-l2
        --network-secret colima-l2-secret
        --secure-mode
        --port-mode "${mode}"
        --dev-name et0
        --ipv4 "${overlay_ip}/24"
        --listeners udp://0.0.0.0:11010
        --l2-fdb-capacity 1024
        --l2-fdb-age-seconds 120
        --l2-flood-bps 8388608
    )
    if [[ -n "${peer_url}" ]]; then
        args+=(--peers "${peer_url}")
    fi
    "${docker_cmd[@]}" exec -d "${node}" \
        sh -c 'exec "$@" >/tmp/easytier.log 2>&1' \
        sh "${args[@]}"
}

run_suite() {
    local mode="$1"
    local subnet="$2"

    cleanup
    "${docker_cmd[@]}" network create "${network_name}" >/dev/null

    start_node "${nodes[0]}" "${mode}" "${subnet}.1"
    start_node "${nodes[1]}" "${mode}" "${subnet}.2" "udp://${nodes[0]}:11010"
    start_node "${nodes[2]}" "${mode}" "${subnet}.3" "udp://${nodes[1]}:11010"

    for node in "${nodes[@]}"; do
        wait_for_interface "${node}"
    done

    if [[ "${mode}" == "tap" ]]; then
        "${docker_cmd[@]}" exec "${nodes[0]}" ip -d link show et0 | grep -q 'tap'
    fi

    assert_stable_ping "${nodes[0]}" "${subnet}.3"
    assert_stable_ping "${nodes[2]}" "${subnet}.1"

    if [[ "${mode}" == "tap" ]]; then
        "${docker_cmd[@]}" exec -d "${nodes[2]}" iperf3 -s -1 -p 5201
        "${docker_cmd[@]}" exec "${nodes[0]}" iperf3 -c "${subnet}.3" -p 5201 -t 3
        run_tap_frame_matrix
    fi

    if [[ "${mode}" == "l2-tun" ]]; then
        "${docker_cmd[@]}" exec "${nodes[0]}" ip -d link show et0 | grep -q 'tun'
        "${docker_cmd[@]}" exec -d "${nodes[2]}" iperf3 -s -1 -p 5202
        "${docker_cmd[@]}" exec "${nodes[0]}" iperf3 -c "${subnet}.3" -p 5202 -t 3
    fi
}

run_mixed_suite() {
    cleanup
    "${docker_cmd[@]}" network create "${network_name}" >/dev/null

    start_node "${nodes[0]}" l2-tun 10.80.0.1
    start_node "${nodes[1]}" tap 10.80.0.2 "udp://${nodes[0]}:11010"

    wait_for_interface "${nodes[0]}"
    wait_for_interface "${nodes[1]}"
    "${docker_cmd[@]}" exec "${nodes[0]}" ip -d link show et0 | grep -q 'tun'
    "${docker_cmd[@]}" exec "${nodes[1]}" ip -d link show et0 | grep -q 'tap'

    assert_stable_ping "${nodes[0]}" 10.80.0.2
    assert_stable_ping "${nodes[1]}" 10.80.0.1
    "${docker_cmd[@]}" exec "${nodes[1]}" ip neigh show dev et0 | grep -q '02:45:'
}

trap cleanup EXIT INT TERM

"${docker_cmd[@]}" info >/dev/null
if [[ "${SKIP_IMAGE_BUILD:-0}" != "1" ]]; then
    "${docker_cmd[@]}" build -f "${repo_root}/script/colima-l2/Dockerfile" -t "${image_name}" "${repo_root}"
fi

case "${EASYTIER_L2_TEST_SCOPE:-all}" in
    tap)
        run_suite tap 10.77.0
        ;;
    all)
        run_suite tap 10.77.0
        run_suite l3 10.78.0
        run_suite l2-tun 10.79.0
        run_mixed_suite
        ;;
    *)
        echo "Unsupported test scope: ${EASYTIER_L2_TEST_SCOPE}" >&2
        exit 2
        ;;
esac

echo "Colima QEMU exact L2, L2-TUN, mixed-edge, and L3 checks passed"
