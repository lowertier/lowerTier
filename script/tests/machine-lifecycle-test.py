#!/usr/bin/env python3
"""Verify join policy, saved offline records, and returning node identity on loopback."""

import argparse
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import tomllib


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/lowertier"))
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    directory = (args.work_dir or Path(tempfile.mkdtemp(prefix="lowertier-machines-"))).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    children = []
    used = set()

    def port():
        while True:
            with socket.socket() as stream:
                stream.bind(("127.0.0.1", 0))
                value = stream.getsockname()[1]
            if value not in used:
                used.add(value)
                return value

    link = port()
    gui_ports = {name: port() for name in ["controller", "vm"]}
    for name, address in [("controller", "10.253.67.1"), ("vm", "10.253.67.2")]:
        node = directory / name
        node.mkdir(mode=0o700)
        config = f'''[node]
hostname = "{name}"
offline_retention = 3600
[network]
name = "local-machine-history-test"
secret = "local-fixture-secret"
[address]
ipv4 = "{address}/24"
[tun]
mode = "userspace"
ipv6 = false
[transport]
listen = {json.dumps([f"quic://127.0.0.1:{link}"] if name == "controller" else [])}
[nat]
p2p = "off"
stun = []
stun_v6 = []
stun_tcp = []
[control]
portal = "127.0.0.1:{port()}"
token_file = {json.dumps(str(node / "control.token"))}
[gui]
loopback_port = {gui_ports[name]}
[log]
console = "info"
'''
        if name == "vm":
            config += f'\n[[peer]]\nuri = "quic://127.0.0.1:{link}"\n'
        path = node / "node.toml"
        path.write_text(config)
        path.chmod(0o600)

    def request(name, path, body=None, authenticated=True):
        connection = http.client.HTTPConnection("127.0.0.1", gui_ports[name], timeout=5)
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["x-lowertier-key"] = (directory / name / "gui.key").read_text().strip()
        try:
            connection.request("POST" if body is not None else "GET", "/api/" + path,
                               body=json.dumps(body) if body is not None else None, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def wait_for(label, predicate, timeout=60):
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, ValueError, http.client.HTTPException) as error:
                last_error = str(error)
            time.sleep(0.1)
        raise TimeoutError(f"{label}: {last_error or 'The expected state did not appear.'}")

    def start(name):
        with (directory / name / "daemon.log").open("ab") as output:
            process = subprocess.Popen([str(binary), "run", "-c", str(directory / name / "node.toml")],
                                       stdout=output, stderr=subprocess.STDOUT)
        children.append(process)
        def ready():
            if process.poll() is not None:
                raise RuntimeError(f"{name} stopped. Read {directory / name / 'daemon.log'}.")
            return request(name, "snapshot")[0] == 200
        wait_for(name + " web interface", ready)
        return process

    def stop(process):
        process.terminate()
        process.wait(timeout=15)

    def snapshot():
        status, body = request("controller", "snapshot")
        assert status == 200, body
        return body

    def live_vm():
        return next((peer for peer in snapshot().get("peers", [])
                     if peer.get("route", {}).get("hostname") == "vm"
                     and peer.get("path_peer_ids")), None)

    def offline_vm():
        return next((machine for machine in snapshot().get("offline_machines", [])
                     if machine.get("route", {}).get("hostname") == "vm"), None)

    try:
        controller = start("controller")
        vm = start("vm")
        peer = wait_for("Authenticated VM route", live_vm)
        assert peer.get("peer_key"), peer
        assert int(peer["route"]["offline_retention"]) == 3600
        instance = peer["route"]["inst_id"]
        machine_id = "instance:" + instance + ":key:" + peer["peer_key"]
        history_path = directory / "controller/node.machines.json"
        wait_for("Saved VM observation", lambda: history_path.exists() and machine_id in history_path.read_text())
        status, _ = request("controller", "rpc/ForgetMachine", {"id": machine_id}, authenticated=False)
        assert status == 403, status
        status, body = request("controller", "rpc/ForgetMachine", {"id": machine_id})
        assert status == 409 and body["error"]["code"] == "conflict", (status, body)

        for policy in [0, 3600, -1]:
            status, body = request("controller", "rpc/CreateJoinCode", {"offline_retention": policy})
            assert status == 200 and not body.get("error"), body
            destination = directory / f"join-{policy}.toml"
            subprocess.run([str(binary), "init", str(destination), "--join", body["code"]],
                           check=True, capture_output=True, timeout=15)
            config = tomllib.loads(destination.read_text())
            assert config["node"]["offline_retention"] == policy, config["node"]
            subprocess.run([str(binary), "check", "-c", str(destination)],
                           check=True, capture_output=True, timeout=15)
        status, body = request("controller", "rpc/CreateJoinCode", {"offline_retention": -2})
        assert status == 400 and body["error"]["code"] == "invalid_argument", (status, body)
        print("Join policies reached valid node configurations.", flush=True)

        stop(vm)
        offline = wait_for("Retained offline VM", offline_vm)
        assert offline["id"] == machine_id
        assert int(offline["last_seen_unix_ms"]) > 0
        assert not live_vm()
        saved_at = offline["last_seen_unix_ms"]
        stop(controller)
        controller = start("controller")
        restored = wait_for("Restored offline VM after restart", offline_vm)
        assert restored["id"] == machine_id
        assert restored["last_seen_unix_ms"] == saved_at
        status, watched = request("controller", "rpc/WatchChanges", {"resources": ["peers"]})
        assert status == 200 and watched["cursor"]
        status, body = request("controller", "rpc/ForgetMachine", {"id": machine_id})
        assert status == 200 and not body.get("error"), body
        assert not offline_vm()
        assert json.loads(history_path.read_text())["machines"] == []
        status, changed = request("controller", "rpc/WatchChanges", {
            "resources": ["peers"], "cursor": watched["cursor"], "max_wait_ms": 1000,
        })
        assert status == 200 and "peers" in changed.get("changed", []), changed
        print("Offline history survived restart and supported removal.", flush=True)

        vm = start("vm")
        returning = wait_for("Returning VM", live_vm)
        assert returning["route"]["inst_id"] == instance
        assert not offline_vm()
        wait_for("Returning VM saved once", lambda: len(json.loads(history_path.read_text())["machines"]) == 1)
        status, body = request("vm", "config", {"set": {"node.offline_retention": 0}})
        assert status == 200 and not body.get("result", {}).get("errors"), body
        wait_for("Temporary policy advertisement", lambda: (live_vm() or {}).get("route", {}).get("offline_retention") == "0")
        wait_for("Temporary policy persisted", lambda: json.loads(history_path.read_text())["machines"] == [])
        stop(vm)
        wait_for("Temporary VM route removal", lambda: not live_vm())
        assert not offline_vm()
        stop(controller)
        controller = start("controller")
        assert not offline_vm()
        print(json.dumps({"result": "passed", "join_policies": [0, 3600, -1],
                          "restart_persistence": True, "returning_identity": True,
                          "temporary_removal": True, "evidence": str(directory)}), flush=True)
    finally:
        for process in children:
            if process.poll() is None:
                process.terminate()
        for process in children:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
