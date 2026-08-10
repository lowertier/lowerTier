#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docker_context="${COLIMA_DOCKER_CONTEXT:-colima-easytier-l2}"
image_name="easytier-stun-qemu-test:local"
public_net="et-stun-public"
private_a_net="et-stun-private-a"
private_b_net="et-stun-private-b"
containers=(et-stun-relay et-stun-nat-a et-stun-nat-b et-stun-node-a et-stun-node-b)
docker_cmd=(docker --context "${docker_context}")

cleanup() {
    local container network
    for container in "${containers[@]}"; do
        "${docker_cmd[@]}" rm -f "${container}" >/dev/null 2>&1 || true
    done
    for network in "${public_net}" "${private_a_net}" "${private_b_net}"; do
        "${docker_cmd[@]}" network rm "${network}" >/dev/null 2>&1 || true
    done
}

create_networks() {
    "${docker_cmd[@]}" network create --subnet 172.30.0.0/24 "${public_net}" >/dev/null
    "${docker_cmd[@]}" network create --internal --subnet 10.210.0.0/24 "${private_a_net}" >/dev/null
    "${docker_cmd[@]}" network create --internal --subnet 10.220.0.0/24 "${private_b_net}" >/dev/null
}

start_router() {
    local name="$1" private_net="$2" private_ip="$3" public_ip="$4" private_cidr="$5" mode="$6"
    "${docker_cmd[@]}" run -d --name "${name}" --privileged \
        --network "${private_net}" --ip "${private_ip}" "${image_name}" sleep infinity >/dev/null
    "${docker_cmd[@]}" network connect --ip "${public_ip}" "${public_net}" "${name}"

    "${docker_cmd[@]}" exec "${name}" sh -eu -c '
        private_ip="$1"; public_ip="$2"; private_cidr="$3"; mode="$4"
        private_if="$(ip -o -4 addr show | awk -v ip="${private_ip}" '\''$4 ~ ("^" ip "/") {print $2; exit}'\'')"
        public_if="$(ip -o -4 addr show | awk -v ip="${public_ip}" '\''$4 ~ ("^" ip "/") {print $2; exit}'\'')"
        test -n "${private_if}"; test -n "${public_if}"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        iptables -P FORWARD ACCEPT
        iptables -A FORWARD -i "${private_if}" -o "${public_if}" -d 10.0.0.0/8 -j REJECT
        if [ "${mode}" = cone ]; then
            iptables -t nat -A POSTROUTING -s "${private_cidr}" -o "${public_if}" -p udp -j SNAT --to-source "${public_ip}"
            # Forward punch/data ephemerals but deliberately exclude the stable
            # EasyTier listener so the experiment cannot take the direct-listener shortcut.
            iptables -t nat -A PREROUTING -i "${public_if}" -p udp --dport 32768:65535 -j DNAT --to-destination "${private_ip%.*}.10"
        else
            iptables -t nat -A POSTROUTING -s "${private_cidr}" -o "${public_if}" -p udp -j MASQUERADE --random-fully
        fi
        iptables -t nat -A POSTROUTING -s "${private_cidr}" -o "${public_if}" -j MASQUERADE
        tc qdisc add dev "${public_if}" root netem delay 12ms 3ms loss 8%
    ' sh "${private_ip}" "${public_ip}" "${private_cidr}" "${mode}"
}

start_node() {
    local name="$1" private_net="$2" private_ip="$3" gateway="$4" overlay_ip="$5"
    "${docker_cmd[@]}" run -d --name "${name}" --cap-add NET_ADMIN --device /dev/net/tun \
        --network "${private_net}" --ip "${private_ip}" "${image_name}" sleep infinity >/dev/null
    "${docker_cmd[@]}" exec "${name}" ip route replace default via "${gateway}"
    "${docker_cmd[@]}" exec -d "${name}" sh -c '
        exec easytier-core \
          --network-name colima-stun \
          --network-secret colima-stun-secret \
          --ipv4 "$1/24" \
          --dev-name et0 \
          --listeners udp://0.0.0.0:11010 \
          --peers udp://172.30.0.10:11010 \
          --disable-upnp true \
          --disable-sym-hole-punching true \
          --need-p2p true \
          --latency-first true \
          --stun-servers 172.30.0.10:11010 stun.cloudflare.com:3478 172.30.0.10:11011 \
          --console-log-level debug \
          > /tmp/easytier.log 2>&1
    ' sh "${overlay_ip}"
}

wait_for_log() {
    local name="$1" pattern="$2" timeout_seconds="$3" started_at="$4"
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        if "${docker_cmd[@]}" exec "${name}" grep -q "${pattern}" /tmp/easytier.log 2>/dev/null; then
            python3 - <<PY
import time
print(f"{time.monotonic() - ${started_at}:.3f}")
PY
            return 0
        fi
        sleep 0.2
    done
    "${docker_cmd[@]}" exec "${name}" tail -200 /tmp/easytier.log >&2 || true
    return 1
}

wait_for_hole_punch() {
    local timeout_seconds="$1"
    local started_at="$2"
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        for name in et-stun-node-a et-stun-node-b; do
            if "${docker_cmd[@]}" exec "${name}" grep -q 'hole punched' /tmp/easytier.log 2>/dev/null; then
                selected_node="${name}"
                setup_seconds="$(python3 - <<PY
import time
print(f"{time.monotonic() - ${started_at}:.3f}")
PY
)"
                return 0
            fi
        done
        sleep 0.2
    done
    return 1
}

trap cleanup EXIT
cleanup
"${docker_cmd[@]}" info >/dev/null
"${docker_cmd[@]}" build -f "${repo_root}/script/colima-stun/Dockerfile" -t "${image_name}" "${repo_root}"
create_networks

"${docker_cmd[@]}" run -d --name et-stun-relay --network "${public_net}" --ip 172.30.0.10 \
    --cap-add NET_ADMIN --device /dev/net/tun "${image_name}" sleep infinity >/dev/null
"${docker_cmd[@]}" exec -d et-stun-relay sh -c '
    exec easytier-core --network-name colima-stun --network-secret colima-stun-secret \
      --ipv4 10.230.0.1/24 --dev-name et0 \
      --listeners udp://0.0.0.0:11010 udp://0.0.0.0:11011 \
      --disable-udp-hole-punching true > /tmp/easytier.log 2>&1
'

start_router et-stun-nat-a "${private_a_net}" 10.210.0.2 172.30.0.2 10.210.0.0/24 cone
start_router et-stun-nat-b "${private_b_net}" 10.220.0.2 172.30.0.3 10.220.0.0/24 cone

started_at="$(python3 -c 'import time; print(time.monotonic())')"
start_node et-stun-node-a "${private_a_net}" 10.210.0.10 10.210.0.2 10.230.0.2
sleep 1.4
start_node et-stun-node-b "${private_b_net}" 10.220.0.10 10.220.0.2 10.230.0.3
"${docker_cmd[@]}" exec -d et-stun-node-a sh -c '
    while :; do ping -n -c 1 -W 1 10.230.0.3 >/dev/null 2>&1 || true; sleep 0.2; done
'

if ! wait_for_hole_punch 45 "${started_at}"; then
    for name in et-stun-node-a et-stun-node-b; do
        echo "${name} punch diagnostics:" >&2
        "${docker_cmd[@]}" exec "${name}" grep -E \
            'STUN candidate observed|hole punch got remote|SendPunchPacketConeRequest|got raw packet|got udp hole punch|triggered hole punch|punched socket found|failed to connect with socket' \
            /tmp/easytier.log | tail -160 >&2 || true
    done
    "${docker_cmd[@]}" exec et-stun-nat-a conntrack -L -p udp >&2 || true
    "${docker_cmd[@]}" exec et-stun-nat-b conntrack -L -p udp >&2 || true
    exit 1
fi
ping_output="$("${docker_cmd[@]}" exec et-stun-node-a ping -n -c 20 -i 0.1 -W 2 10.230.0.3)"
selected_line="$("${docker_cmd[@]}" exec "${selected_node}" grep 'punched socket found' /tmp/easytier.log | tail -1)"
stun_lines="$("${docker_cmd[@]}" exec "${selected_node}" grep 'STUN candidate observed' /tmp/easytier.log | tail -3)"

printf 'direct_setup_seconds=%s\n' "${setup_seconds}"
printf '%s\n' "${stun_lines}"
printf '%s\n' "${selected_line}"
printf '%s\n' "${ping_output}"
loss_percent="$(sed -n 's/.*, \([0-9][0-9]*\)% packet loss.*/\1/p' <<<"${ping_output}")"
test -n "${loss_percent}"
if (( loss_percent > 20 )); then
    echo "direct path packet loss ${loss_percent}% exceeds the 20% impairment ceiling" >&2
    exit 1
fi

echo "Colima QEMU public-STUN, skew, loss, cone-to-cone NAT experiment passed"
