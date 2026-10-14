#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUILD_DIR=${CARGO_TARGET_DIR:-"$REPO_ROOT/target"}
CORE_BIN=${CORE_BIN:-"$BUILD_DIR/debug/lowertier-core"}
CLI_BIN=${CLI_BIN:-"$BUILD_DIR/debug/lowertier-cli"}
PYTHON_BIN=${PYTHON_BIN:-python3}
INSTANCE_A=11111111-1111-4111-8111-111111111111
INSTANCE_B=22222222-2222-4222-8222-222222222222
CORE_PID=

if [[ "${SKIP_BUILD:-0}" != 1 ]] || [[ ! -x "$CORE_BIN" ]] || [[ ! -x "$CLI_BIN" ]]; then
    cargo build -p lowertier --bin lowertier-core --bin lowertier-cli
fi

RUN_DIR=$(mktemp -d -t lowertier-cli-e2e.XXXXXX)
cleanup() {
    if [[ -n "$CORE_PID" ]]; then
        kill "$CORE_PID" 2>/dev/null || true
        wait "$CORE_PID" 2>/dev/null || true
    fi
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT
mkdir "$RUN_DIR/config"
RPC_PORT=$("$PYTHON_BIN" - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

write_config() {
    local name=$1 id=$2
    cat >"$RUN_DIR/config/$name.toml" <<EOF
instance_name = "e2e-inst-$name"
instance_id = "$id"
listeners = []

[network_identity]
network_name = "e2e-net-$name"
network_secret = "e2e-secret-$name"

[flags]
no_tun = true
enable_ipv6 = false
EOF
}
write_config a "$INSTANCE_A"
write_config b "$INSTANCE_B"
"$CORE_BIN" --config-dir "$RUN_DIR/config" --rpc-portal "127.0.0.1:$RPC_PORT" \
    >"$RUN_DIR/core.log" 2>&1 &
CORE_PID=$!
cli=("$CLI_BIN" -p "127.0.0.1:$RPC_PORT" --control-token-file "$RUN_DIR/config/control.token" -o json)

ready=false
for _ in $(seq 1 50); do
    if "${cli[@]}" --instance "$INSTANCE_A" node show >"$RUN_DIR/node.json" 2>/dev/null \
        && "${cli[@]}" --instance "$INSTANCE_B" node show >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.2
done
if [[ "$ready" != true ]]; then
    cat "$RUN_DIR/core.log" >&2
    exit 1
fi

"${cli[@]}" instance list >"$RUN_DIR/instances.json"
if "${cli[@]}" node show >"$RUN_DIR/ambiguous.json" 2>/dev/null; then
    echo "A node request requires an instance ID when two instances exist." >&2
    exit 1
else
    test "$?" -eq 4
fi

printf '%s\n' '{"tcp_whitelist":["80","443"]}' >"$RUN_DIR/acl.json"
"${cli[@]}" --instance "$INSTANCE_A" acl set --file "$RUN_DIR/acl.json" >"$RUN_DIR/write.json"
"${cli[@]}" --instance "$INSTANCE_A" acl get >"$RUN_DIR/acl-a.json"
"${cli[@]}" --instance "$INSTANCE_B" acl get >"$RUN_DIR/acl-b.json"
"$PYTHON_BIN" - "$RUN_DIR" "$INSTANCE_A" "$INSTANCE_B" <<'PY'
import json
from pathlib import Path
import sys

directory = Path(sys.argv[1])
instance_a, instance_b = sys.argv[2:]

def read(name, instance=None):
    envelope = json.loads((directory / name).read_text())
    assert envelope["schema_version"] == 1, envelope
    assert envelope["request_id"], envelope
    assert envelope.get("error") is None, envelope
    if instance:
        assert envelope["instance_id"] == instance, envelope
    return envelope["data"]

instances = read("instances.json")["instances"]
assert {item["instance_id"] for item in instances} == {instance_a, instance_b}, instances
assert {item["name"] for item in instances} == {"e2e-inst-a", "e2e-inst-b"}, instances
assert "node" in read("node.json", instance_a)
error = json.loads((directory / "ambiguous.json").read_text())
assert error["schema_version"] == 1, error
assert error["error"]["code"] == "ambiguous", error
read("write.json", instance_a)
assert read("acl-a.json", instance_a)["tcp_whitelist"] == ["80", "443"]
assert read("acl-b.json", instance_b).get("tcp_whitelist", []) == []
PY
echo "CLI multi-instance E2E passed"
