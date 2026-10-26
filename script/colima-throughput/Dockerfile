FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake libclang-dev mold pkg-config libssl-dev protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --quiet --locked --release -p lowertier \
        --bin lowertier \
        --no-default-features --features tun \
    && cp target/release/lowertier /tmp/lowertier

# Explicit target for QEMU/Linux validation. It is not part of the runtime
# image, but reuses the same registry, git, and target caches as the release
# build so platform-only offload tests stay cheap and reproducible.
FROM builder AS tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo test --locked -p lowertier --lib linux_tun_offload_ --no-default-features --features tun \
    && cargo test --locked -p lowertier --lib instance::linux_tun::tests --no-default-features --features tun \
    && cargo test --locked -p lowertier --lib tunnel::udp_vector_io::tests --no-default-features --features tun

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates ethtool iperf3 iproute2 iputils-ping jq procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/lowertier /usr/local/bin/lowertier
CMD ["/bin/sh"]
