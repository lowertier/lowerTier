#!/usr/bin/env python3
"""Bounded IPv4 STUN Binding service for the LowTier test mesh.

No TURN allocation, credentials, forwarding, or automatic lifetime expiry.
Run under a supervised service. RFC 8489 XOR-MAPPED-ADDRESS is supported;
CHANGE-PORT is supported over UDP. CHANGE-IP is deliberately unsupported.
"""
import argparse
import asyncio
import signal
import socket
import struct
import time

COOKIE = 0x2112A442
MAX_BODY = 512
MAX_CLIENTS = 64


class RateLimit:
    def __init__(self):
        self.second = -1
        self.counts = {}
        self.total = 0

    def allow(self, source, now=None):
        second = int(time.monotonic() if now is None else now)
        if second != self.second:
            self.second, self.total = second, 0
            self.counts.clear()
        if self.total >= 2048 or (source not in self.counts and len(self.counts) >= 256):
            return False
        count = self.counts.get(source, 0)
        if count >= 128:
            return False
        self.counts[source] = count + 1
        self.total += 1
        return True


def binding_response(data, source):
    """Return (response, change_port), or None for an unsupported/invalid request."""
    if len(data) < 20:
        return None
    kind, size, cookie = struct.unpack_from('!HHI', data)
    if kind != 1 or cookie != COOKIE or size > MAX_BODY or size % 4 or len(data) != 20 + size:
        return None
    change_port = False
    offset = 20
    while offset < len(data):
        if offset + 4 > len(data):
            return None
        attr, length = struct.unpack_from('!HH', data, offset)
        end = offset + 4 + length
        if end > len(data):
            return None
        if attr == 3:
            if length != 4:
                return None
            flags = struct.unpack_from('!I', data, offset + 4)[0]
            if flags & ~2:  # No CHANGE-IP or unknown bits.
                return None
            change_port = bool(flags & 2)
        elif attr < 0x8000 and attr != 0x0026:  # PADDING is harmless.
            return None
        offset = (end + 3) & ~3
    if offset != len(data):
        return None
    try:
        address = socket.inet_aton(source[0])
        port = int(source[1])
        if not 0 < port <= 65535:
            return None
    except (OSError, ValueError, TypeError):
        return None
    mask = struct.pack('!I', COOKIE)
    value = struct.pack('!BBH', 0, 1, port ^ (COOKIE >> 16))
    value += bytes(a ^ b for a, b in zip(address, mask))
    return struct.pack('!HH', 0x101, 12) + data[4:20] + struct.pack('!HH', 0x20, 8) + value, change_port


async def serve(address, ports, stop):
    limiter = RateLimit()
    datagrams = {}
    active = 0

    class UDP(asyncio.DatagramProtocol):
        def __init__(self, port):
            self.port = port

        def datagram_received(self, data, source):
            if not limiter.allow(source[0]):
                return
            result = binding_response(data, source)
            if result is None:
                return
            reply, change_port = result
            port = ports[1] if self.port == ports[0] else ports[0]
            transport = datagrams.get(port if change_port else self.port)
            if transport is not None:
                transport.sendto(reply, source)

    async def tcp(reader, writer):
        nonlocal active
        if active >= MAX_CLIENTS:
            writer.close()
            return
        active += 1
        try:
            while True:
                header = await asyncio.wait_for(reader.readexactly(20), 60)
                size = int.from_bytes(header[2:4], 'big')
                if size > MAX_BODY or size % 4:
                    break
                body = await asyncio.wait_for(reader.readexactly(size), 5)
                source = writer.get_extra_info('peername')
                if not source or not limiter.allow(source[0]):
                    break
                result = binding_response(header + body, source)
                if result is None or result[1]:
                    break
                writer.write(result[0])
                await asyncio.wait_for(writer.drain(), 5)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        finally:
            active -= 1
            writer.close()

    loop = asyncio.get_running_loop()
    servers = []
    try:
        for port in ports:
            transport, _ = await loop.create_datagram_endpoint(lambda p=port: UDP(p), local_addr=(address, port))
            datagrams[port] = transport
            servers.append(await asyncio.start_server(tcp, address, port, limit=1024, backlog=64))
        print('STUN Binding service ready', flush=True)
        await stop.wait()
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for transport in datagrams.values():
            transport.close()


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--ports', type=int, nargs=2, default=[16780, 16781])
    args = parser.parse_args()
    if len(set(args.ports)) != 2 or any(p < 1024 or p > 65535 for p in args.ports):
        parser.error('two distinct unprivileged ports are required')
    socket.inet_aton(args.bind)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await serve(args.bind, args.ports, stop)


if __name__ == '__main__':
    asyncio.run(main())
