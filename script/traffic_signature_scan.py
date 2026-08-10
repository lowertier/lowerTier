#!/usr/bin/env python3
"""Capture UDP payloads and measure passive traffic signatures."""

from __future__ import annotations

import argparse
import json
import math
import socket
import time
from collections import Counter
from pathlib import Path


ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
VLAN_TYPES = {0x8100, 0x88A8}


def common_prefix_length(packets: list[bytes]) -> int:
    if not packets:
        return 0
    limit = min(map(len, packets))
    for index in range(limit):
        if len({packet[index] for packet in packets}) != 1:
            return index
    return limit


def common_suffix_length(packets: list[bytes]) -> int:
    if not packets:
        return 0
    reversed_packets = [packet[::-1] for packet in packets]
    return common_prefix_length(reversed_packets)


def byte_entropy(values: list[int]) -> float:
    counts = Counter(values)
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def scan_packets(packets: list[bytes], forbidden: list[bytes]) -> dict[str, object]:
    if not packets:
        raise ValueError("the capture has no packets")
    minimum_length = min(map(len, packets))
    entropies = [byte_entropy([packet[index] for packet in packets])
                 for index in range(minimum_length)]
    forbidden_hits = {
        value.decode("ascii", errors="backslashreplace"): sum(
            packet.count(value) for packet in packets
        )
        for value in forbidden
    }
    return {
        "packet_count": len(packets),
        "minimum_packet_bytes": minimum_length,
        "maximum_packet_bytes": max(map(len, packets)),
        "unique_packet_ratio": len(set(packets)) / len(packets),
        "common_prefix_bytes": common_prefix_length(packets),
        "common_suffix_bytes": common_suffix_length(packets),
        "fixed_absolute_positions": sum(value == 0.0 for value in entropies),
        "minimum_position_entropy_bits": min(entropies, default=0.0),
        "mean_position_entropy_bits": sum(entropies) / len(entropies),
        "forbidden_hits": forbidden_hits,
    }


def udp_datagram_from_ethernet(frame: bytes) -> tuple[int, int, bytes] | None:
    if len(frame) < 14:
        return None
    offset = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in VLAN_TYPES:
        if len(frame) < offset + 4:
            return None
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    header_length = (frame[offset] & 0x0F) * 4
    if header_length < 20 or len(frame) < offset + header_length + 8:
        return None
    if frame[offset + 9] != socket.IPPROTO_UDP:
        return None
    udp_offset = offset + header_length
    udp_length = int.from_bytes(frame[udp_offset + 4:udp_offset + 6], "big")
    if udp_length < 8 or len(frame) < udp_offset + udp_length:
        return None
    source_port = int.from_bytes(frame[udp_offset:udp_offset + 2], "big")
    destination_port = int.from_bytes(frame[udp_offset + 2:udp_offset + 4], "big")
    payload = frame[udp_offset + 8:udp_offset + udp_length]
    return source_port, destination_port, payload


def capture_packets(args: argparse.Namespace) -> int:
    packet_socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
    )
    packet_socket.bind((args.interface, 0))
    packet_socket.settimeout(0.1)
    deadline = time.monotonic() + args.timeout
    packets = []
    with packet_socket:
        while len(packets) < args.count and time.monotonic() < deadline:
            try:
                frame, address = packet_socket.recvfrom(65535)
            except TimeoutError:
                continue
            if len(address) > 2 and address[2] == PACKET_OUTGOING:
                continue
            datagram = udp_datagram_from_ethernet(frame)
            if datagram is None:
                continue
            source_port, destination_port, payload = datagram
            if len(payload) < 8:
                continue
            if args.udp_port not in (source_port, destination_port):
                continue
            packets.append(payload)
    if len(packets) < args.count:
        raise RuntimeError(f"captured {len(packets)} of {args.count} UDP packets")
    Path(args.output).write_text(
        "".join(packet.hex() + "\n" for packet in packets), encoding="utf-8"
    )
    return 0


def scan_capture(args: argparse.Namespace) -> int:
    packets = [
        bytes.fromhex(line.strip())[args.strip_bytes:]
        for line in Path(args.input).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    forbidden = [value.encode("utf-8") for value in args.forbid]
    forbidden.extend(bytes.fromhex(value) for value in args.forbid_hex)
    report = scan_packets(packets, forbidden)
    output = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output)
    has_forbidden = any(report["forbidden_hits"].values())
    fixed_edge = max(
        int(report["common_prefix_bytes"]), int(report["common_suffix_bytes"])
    )
    return int(has_forbidden or fixed_edge > args.max_common_edge)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture")
    capture.add_argument("--interface", required=True)
    capture.add_argument("--udp-port", type=int, required=True)
    capture.add_argument("--count", type=int, default=128)
    capture.add_argument("--timeout", type=float, default=10.0)
    capture.add_argument("--output", required=True)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--input", required=True)
    scan.add_argument("--output")
    scan.add_argument("--strip-bytes", type=int, default=0)
    scan.add_argument("--forbid", action="append", default=[])
    scan.add_argument("--forbid-hex", action="append", default=[])
    scan.add_argument("--max-common-edge", type=int, default=0)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if args.command == "capture":
        return capture_packets(args)
    return scan_capture(args)


if __name__ == "__main__":
    raise SystemExit(main())
