#!/usr/bin/env python3
"""Check instance selection through a QUIC userspace proxy and an overlapping loopback port."""

import argparse
import http.client
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import tomllib


def available_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def receive(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise RuntimeError('The SOCKS connection closed')
        result += part
    return result


def request(proxy, port, path, key=None, host=None, body=None):
    with socket.create_connection(('127.0.0.1', proxy), timeout=3) as stream:
        stream.sendall(b'\x05\x01\x00')
        assert receive(stream, 2) == b'\x05\x00'
        stream.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('10.201.70.2') + struct.pack('!H', port))
        reply = receive(stream, 4)
        assert reply[1] == 0, ('SOCKS connection failed', reply[1])
        length = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            length = receive(stream, 1)[0]
        receive(stream, length + 2)
        headers = {'Host': host or f'10.201.70.2:{port}', 'Connection': 'close'}
        if key:
            headers['x-lowertier-key'] = key
        if body is not None:
            headers['Content-Type'] = 'application/toml'
            headers['Content-Length'] = str(len(body.encode()))
        message = ('POST ' if body is not None else 'GET ') + path + ' HTTP/1.1\r\n'
        message += ''.join(name + ': ' + value + '\r\n' for name, value in headers.items()) + '\r\n'
        if body is not None:
            message += body
        stream.sendall(message.encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        return response.status, response.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path('target/release/lowertier'))
    parser.add_argument('--work-dir', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    directory = args.work_dir or Path(tempfile.mkdtemp(prefix='lowertier-gui-proxy-'))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    ports = set()

    def port():
        while True:
            value = available_port()
            if value not in ports:
                ports.add(value)
                return value

    proxy, link, gui_port, other_loopback, foreign_loopback = [port() for _ in range(5)]
    children = []
    try:
        for name, address in [('c', '10.201.70.3'), ('b', '10.201.70.2'), ('a', '10.201.70.1')]:
            node = directory / name
            node.mkdir(mode=0o700)
            configuration = f'''[node]
instance_name = "gui-proxy-{name}"
hostname = "gui-proxy-{name}"
[network]
name = "gui-proxy-test"
secret = "local-only-smoke-secret"
[address]
ipv4 = "{address}/24"
[tun]
mode = "userspace"
ipv6 = false
[transport]
listen = {json.dumps([f'quic://127.0.0.1:{link}'] if name == 'b' else [])}
[nat]
p2p = "off"
stun = []
stun_v6 = []
stun_tcp = []
[underlay]
deny_cidrs = ["100.64.0.0/10"]
[control]
portal = "127.0.0.1:{port()}"
token_file = {json.dumps(str(node / 'control.token'))}
[log]
console = "info"
'''
            if name == 'a':
                configuration += f'''[proxy]
socks5 = "127.0.0.1:{proxy}"
[[peer]]
uri = "quic://127.0.0.1:{link}"
[gui]
loopback_port = {gui_port}
'''
            elif name == 'b':
                configuration += f'''[gui]
port = {gui_port}
loopback_port = {other_loopback}
allow = ["10.201.70.1/32"]
'''
            else:
                configuration += f'''[gui]
loopback_port = {foreign_loopback}
allow = []
'''
            config = node / 'node.toml'
            config.write_text(configuration)
            config.chmod(0o600)
            with (node / 'daemon.log').open('w') as output:
                children.append(subprocess.Popen([str(binary), 'run', '-c', str(config)], stdout=output, stderr=subprocess.STDOUT))
        deadline = time.monotonic() + 40
        while True:
            assert all(child.poll() is None for child in children), 'A test daemon stopped'
            ready = True
            for name in ['a', 'b', 'c']:
                lines = (directory / name / 'daemon.log').read_text().splitlines()
                ready &= any('GUI listening in the userspace stack' in line for line in lines)
                ready &= any('GUI listening on the overlay address' in line and 'address=127.0.0.1' in line for line in lines)
            try:
                if ready:
                    page = request(proxy, gui_port, '/')
                    if page[0] in (200, 403):
                        break
            except (OSError, RuntimeError, AssertionError, http.client.HTTPException):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError('The overlay GUI did not become available')
            time.sleep(0.1)
        assert page[0] == 200, ('The overlay GUI reached another instance on loopback', page[0])
        key = (directory / 'b/gui.key').read_text().strip()
        assert request(proxy, gui_port, '/api/snapshot')[0] == 403
        status, body = request(proxy, gui_port, '/api/snapshot', key)
        assert status == 200, status
        assert tomllib.loads(body.decode())['node']['node']['hostname'] == 'gui-proxy-b'
        assert request(proxy, gui_port, '/', host='foreign.invalid')[0] == 403
        acl = '''[set.acl]
udp_ports = ["53"]
[[set.acl.acl_v1.chains]]
name = "preserved-rule-chain"
chain_type = 3
enabled = true
default_action = 1
'''
        status, body = request(proxy, gui_port, '/api/config', key, body=acl)
        assert status == 200 and not tomllib.loads(body.decode()).get('result', {}).get('errors'), body
        status, before = request(proxy, gui_port, '/api/config', key)
        assert status == 200
        original = tomllib.loads(before.decode())['active']['acl']
        patch = '[set]\n"acl.tcp_ports" = ["' + str(gui_port) + '"]\n'
        status, body = request(proxy, gui_port, '/api/config', key, body=patch)
        assert status == 200 and not tomllib.loads(body.decode()).get('result', {}).get('errors'), body
        status, after = request(proxy, gui_port, '/api/config', key)
        assert status == 200
        updated = tomllib.loads(after.decode())['active']['acl']
        assert updated['acl_v1'] == original['acl_v1'], 'A port update replaced unrelated ACL rules'
        assert updated['udp_ports'] == original['udp_ports'], 'A TCP port update replaced UDP ports'
        assert updated['tcp_ports'] == [str(gui_port)]
        for port, key_file in [(other_loopback, directory / 'b/gui.key'), (foreign_loopback, directory / 'c/gui.key')]:
            try:
                status, _ = request(proxy, port, '/api/snapshot', key_file.read_text().strip(), host=f'127.0.0.1:{port}')
            except (OSError, RuntimeError, AssertionError, http.client.HTTPException):
                continue
            assert status != 200, ('The overlay proxy reached a loopback GUI', port)
        print(json.dumps(dict(result='passed', instance='gui-proxy-b', page=200, unauthorized_api=403, authorized_api=200, foreign_host=403, loopback_proxy='blocked', acl_rules_preserved=True, evidence=str(directory))))
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == '__main__':
    main()
