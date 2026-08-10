#!/usr/bin/env python3
"""Test the EasyTier userspace proxy path."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import statistics
import struct
import time
from pathlib import Path
from typing import Callable


READ_TIMEOUT_SECONDS = 15
TRANSFER_CHUNK = b"lowerTier-userspace-path\n" * 2731
RTT_TOKEN = b"ETRTT001"
HTTP_MARKER = b"userspace-http-ok"


def recv_exact(stream: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError(f"The stream closed with {remaining} bytes missing.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_header(stream: socket.socket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        chunk = stream.recv(1)
        if not chunk:
            raise RuntimeError("The proxy closed before the response header.")
        data.extend(chunk)
        if len(data) > 16384:
            raise RuntimeError("The proxy response header is too large.")
    return bytes(data)


def read_socks_address(stream: socket.socket, address_type: int) -> tuple[str, int]:
    if address_type == 1:
        host = socket.inet_ntoa(recv_exact(stream, 4))
    elif address_type == 3:
        host = recv_exact(stream, recv_exact(stream, 1)[0]).decode("ascii")
    elif address_type == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
    else:
        raise RuntimeError(f"The SOCKS5 address type is invalid: {address_type}.")
    port = struct.unpack("!H", recv_exact(stream, 2))[0]
    return host, port


def open_proxy_socket(proxy_port: int) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", proxy_port), READ_TIMEOUT_SECONDS)
    stream.settimeout(READ_TIMEOUT_SECONDS)
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return stream


def open_socks5(
    proxy_port: int,
    target_ip: str,
    target_port: int,
) -> socket.socket:
    stream = open_proxy_socket(proxy_port)
    stream.sendall(b"\x05\x01\x00")
    if recv_exact(stream, 2) != b"\x05\x00":
        stream.close()
        raise RuntimeError("The SOCKS5 proxy rejected unauthenticated access.")

    request = b"\x05\x01\x00\x01" + socket.inet_aton(target_ip)
    request += struct.pack("!H", target_port)
    stream.sendall(request)
    response = recv_exact(stream, 4)
    if response[:2] != b"\x05\x00":
        stream.close()
        raise RuntimeError(f"The SOCKS5 connection failed with status {response[1]}.")
    read_socks_address(stream, response[3])
    return stream


def open_http_connect(
    proxy_port: int,
    target_ip: str,
    target_port: int,
) -> socket.socket:
    stream = open_proxy_socket(proxy_port)
    authority = f"{target_ip}:{target_port}"
    request = (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode("ascii")
    stream.sendall(request)
    response = recv_header(stream)
    if not response.startswith(b"HTTP/1.1 200 "):
        stream.close()
        raise RuntimeError(f"The HTTP CONNECT request failed: {response!r}.")
    return stream


def open_direct(_proxy_port: int, _target_ip: str, target_port: int) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", target_port), READ_TIMEOUT_SECONDS)
    stream.settimeout(READ_TIMEOUT_SECONDS)
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return stream


Connector = Callable[[int, str, int], socket.socket]


def verify_tcp(connector: Connector, proxy_port: int, target_ip: str, target_port: int) -> None:
    with connector(proxy_port, target_ip, target_port) as stream:
        stream.sendall(b"ECHO\n" + RTT_TOKEN)
        if recv_exact(stream, len(RTT_TOKEN)) != RTT_TOKEN:
            raise RuntimeError("The TCP echo response does not match the request.")


def verify_http_proxy(proxy_port: int, target_ip: str, http_port: int) -> None:
    with open_proxy_socket(proxy_port) as stream:
        authority = f"{target_ip}:{http_port}"
        request = (
            f"GET http://{authority}/probe HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Proxy-Connection: close\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream.sendall(request)
        response = bytearray()
        while True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    if not response.startswith(b"HTTP/1.1 200 ") or HTTP_MARKER not in response:
        raise RuntimeError(f"The ordinary HTTP proxy response is invalid: {response!r}.")


def verify_socks5_udp(proxy_port: int, target_ip: str, target_port: int) -> None:
    with open_proxy_socket(proxy_port) as control:
        control.sendall(b"\x05\x01\x00")
        if recv_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("The SOCKS5 proxy rejected the UDP association.")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        response = recv_exact(control, 4)
        if response[:2] != b"\x05\x00":
            raise RuntimeError(f"The SOCKS5 UDP association failed: {response!r}.")
        relay_host, relay_port = read_socks_address(control, response[3])
        if relay_host in {"0.0.0.0", "::"}:
            relay_host = "127.0.0.1"

        payload = b"lowerTier-socks5-udp"
        datagram = b"\x00\x00\x00\x01" + socket.inet_aton(target_ip)
        datagram += struct.pack("!H", target_port) + payload
        family = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(READ_TIMEOUT_SECONDS)
            udp.sendto(datagram, (relay_host, relay_port))
            reply, _ = udp.recvfrom(65536)

    if len(reply) < 10 or reply[:3] != b"\x00\x00\x00":
        raise RuntimeError(f"The SOCKS5 UDP response header is invalid: {reply!r}.")
    if reply[3] != 1:
        raise RuntimeError(f"The SOCKS5 UDP response address type is invalid: {reply[3]}.")
    if reply[10:] != payload:
        raise RuntimeError("The SOCKS5 UDP response does not match the request.")


def measure_setup(
    connector: Connector,
    proxy_port: int,
    target_ip: str,
    target_port: int,
    runs: int,
) -> list[float]:
    values: list[float] = []
    for _ in range(runs):
        start = time.perf_counter_ns()
        with connector(proxy_port, target_ip, target_port) as stream:
            stream.sendall(b"ECHO\n" + RTT_TOKEN)
            recv_exact(stream, len(RTT_TOKEN))
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    return values


def measure_rtt(
    connector: Connector,
    proxy_port: int,
    target_ip: str,
    target_port: int,
    runs: int,
) -> list[float]:
    values: list[float] = []
    with connector(proxy_port, target_ip, target_port) as stream:
        stream.sendall(b"ECHO\n")
        for _ in range(10):
            stream.sendall(RTT_TOKEN)
            recv_exact(stream, len(RTT_TOKEN))
        for _ in range(runs):
            start = time.perf_counter_ns()
            stream.sendall(RTT_TOKEN)
            recv_exact(stream, len(RTT_TOKEN))
            values.append((time.perf_counter_ns() - start) / 1_000_000)
    return values


def measure_throughput(
    connector: Connector,
    proxy_port: int,
    target_ip: str,
    target_port: int,
    byte_count: int,
    runs: int,
) -> list[float]:
    values: list[float] = []
    for _ in range(runs):
        with connector(proxy_port, target_ip, target_port) as stream:
            start = time.perf_counter_ns()
            stream.sendall(f"DOWNLOAD {byte_count}\n".encode("ascii"))
            recv_exact(stream, byte_count)
            seconds = (time.perf_counter_ns() - start) / 1_000_000_000
            values.append(byte_count * 8 / seconds / 1_000_000)
    return values


def metric_summary(values: list[float]) -> dict[str, object]:
    return {
        "median": round(statistics.median(values), 3),
        "runs": [round(value, 3) for value in values],
    }


def run_client(args: argparse.Namespace) -> None:
    connectors: dict[str, Connector] = {
        "direct_loopback": open_direct,
        "socks5_overlay": open_socks5,
        "http_connect_overlay": open_http_connect,
    }

    verify_tcp(open_socks5, args.proxy_port, args.target_ip, args.tcp_port)
    verify_tcp(open_http_connect, args.proxy_port, args.target_ip, args.tcp_port)
    verify_http_proxy(args.proxy_port, args.target_ip, args.http_port)
    verify_socks5_udp(args.proxy_port, args.target_ip, args.udp_port)

    setup: dict[str, object] = {}
    rtt: dict[str, object] = {}
    throughput: dict[str, object] = {}
    for name, connector in connectors.items():
        setup[name] = metric_summary(
            measure_setup(
                connector,
                args.proxy_port,
                args.target_ip,
                args.tcp_port,
                args.setup_runs,
            )
        )
        rtt[name] = metric_summary(
            measure_rtt(
                connector,
                args.proxy_port,
                args.target_ip,
                args.tcp_port,
                args.rtt_runs,
            )
        )
        throughput[name] = metric_summary(
            measure_throughput(
                connector,
                args.proxy_port,
                args.target_ip,
                args.tcp_port,
                args.benchmark_bytes,
                args.benchmark_runs,
            )
        )

    results = {
        "benchmark_bytes": args.benchmark_bytes,
        "benchmark_runs": args.benchmark_runs,
        "correctness": {
            "http_connect_tcp": "pass",
            "http_forward": "pass",
            "socks5_tcp": "pass",
            "socks5_udp": "pass",
        },
        "rtt_ms": rtt,
        "rtt_runs": args.rtt_runs,
        "setup_and_echo_ms": setup,
        "setup_runs": args.setup_runs,
        "throughput_mbps": throughput,
    }
    output = Path(args.output)
    output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        command = await asyncio.wait_for(reader.readline(), READ_TIMEOUT_SECONDS)
        if command == b"ECHO\n":
            while True:
                data = await reader.readexactly(len(RTT_TOKEN))
                writer.write(data)
                await writer.drain()
        elif command.startswith(b"DOWNLOAD "):
            remaining = int(command.split()[1])
            while remaining:
                chunk = TRANSFER_CHUNK[:remaining]
                writer.write(chunk)
                remaining -= len(chunk)
                if remaining % (1024 * 1024) < len(chunk):
                    await writer.drain()
            await writer.drain()
        else:
            raise RuntimeError(f"The test server received an invalid command: {command!r}.")
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT_SECONDS)
        if not header.startswith(b"GET /probe HTTP/1.1\r\n"):
            raise RuntimeError(f"The test HTTP request is invalid: {header!r}.")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(HTTP_MARKER)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + HTTP_MARKER
        )
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


class EchoDatagramProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        self.transport.sendto(data, address)


async def run_server(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()
    tcp_server = await asyncio.start_server(handle_tcp, "127.0.0.1", args.tcp_port)
    http_server = await asyncio.start_server(handle_http, "127.0.0.1", args.http_port)
    udp_transport, _ = await loop.create_datagram_endpoint(
        EchoDatagramProtocol,
        local_addr=("127.0.0.1", args.udp_port),
    )
    print("READY", flush=True)
    try:
        async with tcp_server, http_server:
            await asyncio.gather(
                tcp_server.serve_forever(),
                http_server.serve_forever(),
            )
    finally:
        udp_transport.close()


def print_ports() -> None:
    sockets: list[socket.socket] = []
    ports: list[int] = []
    families = [socket.SOCK_DGRAM, socket.SOCK_STREAM, socket.SOCK_STREAM]
    families += [socket.SOCK_DGRAM, socket.SOCK_STREAM]
    try:
        for socket_type in families:
            probe = socket.socket(socket.AF_INET, socket_type)
            probe.bind(("127.0.0.1", 0))
            sockets.append(probe)
            ports.append(probe.getsockname()[1])
        print(*ports)
    finally:
        for probe in sockets:
            probe.close()


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("The value must be greater than zero.")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ports")

    server = commands.add_parser("server")
    server.add_argument("--tcp-port", type=positive_integer, required=True)
    server.add_argument("--udp-port", type=positive_integer, required=True)
    server.add_argument("--http-port", type=positive_integer, required=True)

    client = commands.add_parser("client")
    client.add_argument("--proxy-port", type=positive_integer, required=True)
    client.add_argument("--target-ip", required=True)
    client.add_argument("--tcp-port", type=positive_integer, required=True)
    client.add_argument("--udp-port", type=positive_integer, required=True)
    client.add_argument("--http-port", type=positive_integer, required=True)
    client.add_argument("--benchmark-bytes", type=positive_integer, required=True)
    client.add_argument("--benchmark-runs", type=positive_integer, required=True)
    client.add_argument("--rtt-runs", type=positive_integer, required=True)
    client.add_argument("--setup-runs", type=positive_integer, required=True)
    client.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "ports":
        print_ports()
    elif args.command == "server":
        asyncio.run(run_server(args))
    else:
        run_client(args)


if __name__ == "__main__":
    main()
