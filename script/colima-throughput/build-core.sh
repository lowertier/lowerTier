#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
docker_context=${DOCKER_CONTEXT:-colima}
builder_image=${LOWTIER_BUILDER_IMAGE:-easytier-throughput:wan-builder}
cache_volume=${LOWTIER_BUILD_CACHE_VOLUME:-lowertier-linux-build-cache}
output=${LOWTIER_CORE_OUTPUT:-$repo_root/benchmark-results/.work/lowertier-core-linux}
host_cargo_dir=${CARGO_HOME:-$HOME/.cargo}
work_dir=$repo_root/benchmark-results/.work
mkdir -p "$work_dir"
stage=$(mktemp -d "$work_dir/linux-source.XXXXXX")

cleanup() {
    rm -rf "$stage"
}
trap cleanup EXIT INT TERM

if [[ ! -d "$host_cargo_dir/registry" || ! -d "$host_cargo_dir/git" ]]; then
    echo "The host Cargo cache is incomplete: $host_cargo_dir" >&2
    exit 64
fi

mkdir -p "$(dirname "$output")"

# Share only build inputs. The repository target directory can exceed 100 GB.
rsync -a --relative \
    Cargo.toml \
    Cargo.lock \
    rust-toolchain.toml \
    .cargo/config.toml \
    lowertier \
    vendor \
    assets \
    LICENSE \
    README.md \
    README_CN.md \
    "$stage/"

docker_cmd=(docker --context "$docker_context")
"${docker_cmd[@]}" info >/dev/null
"${docker_cmd[@]}" image inspect "$builder_image" >/dev/null
"${docker_cmd[@]}" volume create "$cache_volume" >/dev/null

# Copy the host Cargo cache one time. Later builds use only VM-local cache data.
"${docker_cmd[@]}" run --rm --pull never --network none --cap-add NET_ADMIN \
    -v "$cache_volume:/cache" \
    -v "$host_cargo_dir:/host-cargo:ro" \
    "$builder_image" sh -eu -c '
        if [ ! -f /cache/cargo/.host-cache-ready ]; then
            mkdir -p /cache/cargo/registry /cache/cargo/git
            cp -a /host-cargo/registry/. /cache/cargo/registry/
            cp -a /host-cargo/git/. /cache/cargo/git/
            touch /cache/cargo/.host-cache-ready
        fi
    '

output_dir=$(cd "$(dirname "$output")" && pwd -P)
output_name=$(basename "$output")

"${docker_cmd[@]}" run --rm --pull never --network none --cap-add NET_ADMIN \
    -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR=/cache/target \
    -v "$cache_volume:/cache" \
    -v "$stage:/work:ro" \
    -v "$output_dir:/output" \
    "$builder_image" sh -eu -c '
        rm -rf /cache/source.next
        mkdir -p /cache/source.next
        cp -a /work/. /cache/source.next/
        rm -rf /cache/source
        mv /cache/source.next /cache/source
        cd /cache/source
        /usr/local/cargo/bin/cargo +1.95 --offline build --locked --release \
            -p lowertier --bin lowertier-core \
            --no-default-features --features tun,quic
        install -m 0755 /cache/target/release/lowertier-core "/output/$1"
    ' sh "$output_name"

printf 'Linux binary: %s\n' "$output"
shasum -a 256 "$output"
