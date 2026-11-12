#!/usr/bin/env python3
"""Two nodes with no configured peers find each other through a tracker and carry data.

Starts lowertier-tracker on loopback and two userspace nodes that know only the
tracker URLs. Passes when the nodes connect directly and a random file served on
node B's side arrives through node A's SOCKS5 proxy with the same SHA-256.

    cargo build --release -p lowertier --bin lowertier \
      -p lowertier-tracker --features lowertier-tracker/server --bin lowertier-tracker
    python3 script/tests/tracker-bootstrap-test.py
"""

import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

NETWORK = 'tracker-bootstrap-test'
ADDRESSES = {'a': '10.203.0.1', 'b': '10.203.0.2'}
PAYLOAD_BYTES = 4 * 1024 * 1024
CONNECT_DEADLINE = 60


def available_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise RuntimeError('the SOCKS connection closed')
        result += part
    return result


def fetch_through_socks(proxy, address, port, path):
    """GET http://address:port/path through a SOCKS5 proxy and return status and body."""
    with socket.create_connection(('127.0.0.1', proxy), timeout=20) as stream:
        stream.sendall(b'\x05\x01\x00')
        assert receive(stream, 2) == b'\x05\x00', 'SOCKS5 rejected no-auth'
        stream.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(address) + struct.pack('!H', port))
        reply = receive(stream, 4)
        if reply[1] != 0:
            raise RuntimeError(f'SOCKS5 connect to {address}:{port} failed with code {reply[1]}')
        length = {1: 4, 4: 16}.get(reply[3]) or receive(stream, 1)[0]
        receive(stream, length + 2)
        stream.sendall(f'GET {path} HTTP/1.1\r\nHost: {address}:{port}\r\nConnection: close\r\n\r\n'.encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        return response.status, response.read()


def node_config(directory, name, ports, tracker_udp, tracker_http):
    node = directory / name
    node.mkdir(mode=0o700, exist_ok=True)
    return f'''[node]
hostname = "boot-{name}"

[network]
name = "{NETWORK}"
secret_file = "{directory / 'network.secret'}"

[address]
ipv4 = "{ADDRESSES[name]}/24"

[tun]
mode = "userspace"

[transport]
listen = ["h2://127.0.0.1:{ports['h2']}", "quic://127.0.0.1:{ports['quic']}", "wss://127.0.0.1:{ports['wss']}"]

[nat]
stun = []
stun_tcp = []

[discovery]
private_trackers = ["udp://127.0.0.1:{tracker_udp}/announce", "http://127.0.0.1:{tracker_http}/announce"]
bind = "127.0.0.1:{ports['discovery']}"
advertise = "127.0.0.1:{ports['discovery']}"

[proxy]
socks5 = "127.0.0.1:{ports['socks']}"

[gui]
enabled = false

[control]
portal = "127.0.0.1:{ports['portal']}"
token_file = "{node / 'control.token'}"
'''


def peers(binary, ports, token):
    output = subprocess.run(
        [str(binary), '-p', f'127.0.0.1:{ports["portal"]}', '--token-file', str(token), '-o', 'json', 'peers'],
        capture_output=True, text=True, timeout=10,
    )
    if output.returncode != 0:
        return []
    return json.loads(output.stdout).get('data', {}).get('peers', [])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path('target/release/lowertier'))
    parser.add_argument('--tracker-binary', type=Path, default=Path('target/release/lowertier-tracker'))
    parser.add_argument('--work-dir', type=Path)
    args = parser.parse_args()
    binary, tracker_binary = args.binary.resolve(), args.tracker_binary.resolve()
    directory = args.work_dir or Path(tempfile.mkdtemp(prefix='lowertier-tracker-bootstrap-'))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    (directory / 'network.secret').write_text(os.urandom(24).hex() + '\n')
    os.chmod(directory / 'network.secret', 0o600)

    payload = os.urandom(PAYLOAD_BYTES)
    digest = hashlib.sha256(payload).hexdigest()

    class Payload(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    # Node B's machine serves the payload on loopback. Node A reaches it at B's overlay address.
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Payload)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    payload_port = server.server_address[1]

    tracker_udp, tracker_http = available_port(socket.SOCK_DGRAM), available_port()
    ports = {}
    for name in ADDRESSES:
        quic = available_port(socket.SOCK_DGRAM)
        ports[name] = {
            'h2': available_port(), 'quic': quic, 'wss': available_port(),
            'discovery': available_port(socket.SOCK_DGRAM),
            'socks': available_port(), 'portal': available_port(),
        }
    children = []
    try:
        logs = {}
        log = open(directory / 'tracker.log', 'w')
        children.append(subprocess.Popen(
            [str(tracker_binary), '--udp-listen', f'127.0.0.1:{tracker_udp}',
             '--http-listen', f'127.0.0.1:{tracker_http}', '--interval', '2'],
            stdout=log, stderr=subprocess.STDOUT,
        ))
        for name in ADDRESSES:
            config = directory / name / 'node.toml'
            text = node_config(directory, name, ports[name], tracker_udp, tracker_http)
            config.parent.mkdir(mode=0o700, exist_ok=True)
            config.write_text(text)
            assert '[[peer]]' not in text, 'the nodes must start without configured peers'
            logs[name] = open(directory / name / 'run.log', 'w')
            children.append(subprocess.Popen(
                [str(binary), 'run', '-c', str(config)], cwd=directory / name,
                stdout=logs[name], stderr=subprocess.STDOUT,
            ))

        started = time.monotonic()
        token = directory / 'a' / 'control.token'
        peer = None
        while time.monotonic() - started < CONNECT_DEADLINE:
            for child in children:
                if child.poll() is not None:
                    raise RuntimeError(f'a process exited with {child.returncode}; see {directory}')
            # A direct peer has at least one live connection of its own.
            peer = next((p for p in peers(binary, ports['a'], token)
                         if (p.get('route') or {}).get('hostname') == 'boot-b' and p.get('conns')), None)
            if peer:
                break
            time.sleep(1)
        if not peer:
            raise RuntimeError(f'node A has no direct connection to node B after {CONNECT_DEADLINE} s; see {directory}')
        connected = time.monotonic() - started

        begin = time.monotonic()
        status, body = fetch_through_socks(ports['a']['socks'], ADDRESSES['b'], payload_port, '/payload')
        elapsed = time.monotonic() - begin
        received = hashlib.sha256(body).hexdigest()
        if status != 200 or len(body) != PAYLOAD_BYTES or received != digest:
            raise RuntimeError(f'payload mismatch: status {status}, {len(body)} bytes, sha256 {received}, expected {digest}')
        print(f'connected in {connected:.1f} s with no configured peers')
        print(f'transferred {PAYLOAD_BYTES} bytes in {elapsed:.2f} s, sha256 {digest}')
        print('ok')
    finally:
        for child in reversed(children):
            child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
        server.shutdown()


if __name__ == '__main__':
    main()
