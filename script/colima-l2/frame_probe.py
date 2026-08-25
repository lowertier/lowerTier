#!/usr/bin/env python3
"""Inject and verify exact Ethernet frames through a Linux TAP interface."""

from __future__ import annotations

import argparse
import errno
import socket
import struct
import sys
import time
from pathlib import Path


ETH_P_ALL = 0x0003
LINUX_AF_PACKET = 17
PACKET_OUTGOING = 4
PACKET_AUXDATA = 8
SOL_PACKET = 263
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6
MIN_FRAME_SIZE = 60


def parse_mac(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {value}")
    return bytes(int(part, 16) for part in parts)


def case_header(case: str) -> bytes:
    if case == "vlan-8021q":
        return b"\x81\x00\x00\x2a\x88\xb5"
    if case == "qinq-8021ad":
        return b"\x88\xa8\x00\x64\x81\x00\x00\x2a\x88\xb5"
    if case == "lldp-multicast":
        return b"\x88\xcc"
    return b"\x88\xb5"


def build_frame(args: argparse.Namespace) -> bytes:
    destination = parse_mac(args.destination_mac)
    source = parse_mac(args.source_mac)
    header = destination + source + case_header(args.case)
    marker = b"ETL2" + bytes.fromhex(args.token) + args.case.encode("ascii") + b"\x00"
    frame_size = max(args.frame_size, MIN_FRAME_SIZE, len(header) + len(marker))
    fill_length = frame_size - len(header) - len(marker)
    fill = bytes((index * 29 + 17) & 0xFF for index in range(fill_length))
    return header + marker + fill


def open_packet_socket(interface: str) -> socket.socket:
    packet_socket = socket.socket(
        LINUX_AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
    )
    packet_socket.bind((interface, 0))
    return packet_socket


def restore_vlan_tag(frame: bytes, auxdata: bytes) -> bytes:
    status, _, _, _, _, vlan_tci, vlan_tpid = struct.unpack("=IIIHHHH", auxdata[:20])
    if not status & TP_STATUS_VLAN_VALID:
        return frame
    if not status & TP_STATUS_VLAN_TPID_VALID:
        vlan_tpid = 0x8100
    tag = struct.pack("!HH", vlan_tpid, vlan_tci)
    return frame[:12] + tag + frame[12:]


def write_result(path: str | None, message: str) -> None:
    if path is None:
        return
    result_path = Path(path)
    temporary_path = result_path.with_suffix(result_path.suffix + ".tmp")
    temporary_path.write_text(message + "\n", encoding="utf-8")
    temporary_path.replace(result_path)


def send_frame(args: argparse.Namespace) -> int:
    frame = build_frame(args)
    with open_packet_socket(args.interface) as packet_socket:
        try:
            sent = packet_socket.send(frame)
        except OSError as error:
            if args.expect_send_error and error.errno == errno.EMSGSIZE:
                return 0
            raise
    if args.expect_send_error:
        raise RuntimeError("the oversized frame was accepted")
    if sent != len(frame):
        raise RuntimeError(f"sent {sent} of {len(frame)} bytes")
    return 0


def receive_frame(args: argparse.Namespace) -> int:
    expected = build_frame(args)
    marker = b"ETL2" + bytes.fromhex(args.token)
    deadline = time.monotonic() + args.timeout
    with open_packet_socket(args.interface) as packet_socket:
        packet_socket.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        packet_socket.settimeout(0.1)
        if args.ready_file:
            Path(args.ready_file).touch()
        while time.monotonic() < deadline:
            try:
                frame, ancillary, _, address = packet_socket.recvmsg(
                    65535, socket.CMSG_SPACE(20)
                )
            except TimeoutError:
                continue
            if len(address) > 2 and address[2] == PACKET_OUTGOING:
                continue
            for level, kind, data in ancillary:
                if level == SOL_PACKET and kind == PACKET_AUXDATA and len(data) >= 20:
                    frame = restore_vlan_tag(frame, data)
            if marker not in frame:
                continue
            if args.expect_timeout:
                raise RuntimeError("an excluded receiver got the frame")
            if frame != expected:
                raise RuntimeError(
                    f"frame mismatch: expected {expected.hex()}, received {frame.hex()}"
                )
            return 0
    if args.expect_timeout:
        return 0
    raise TimeoutError("the expected frame did not arrive")


def add_frame_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--destination-mac", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--frame-size", type=int, default=128)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send")
    add_frame_arguments(send_parser)
    send_parser.add_argument("--expect-send-error", action="store_true")

    receive_parser = subparsers.add_parser("receive")
    add_frame_arguments(receive_parser)
    receive_parser.add_argument("--timeout", type=float, default=5.0)
    receive_parser.add_argument("--expect-timeout", action="store_true")
    receive_parser.add_argument("--ready-file")
    receive_parser.add_argument("--result-file")

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        if args.command == "send":
            return send_frame(args)
        status = receive_frame(args)
    except Exception as error:
        write_result(getattr(args, "result_file", None), f"FAIL: {error}")
        print(error, file=sys.stderr)
        return 1
    write_result(args.result_file, "PASS")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
