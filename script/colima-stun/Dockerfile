FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential mold pkg-config libssl-dev protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --quiet --locked --release -p lowertier --bin lowertier-core --no-default-features --features tun \
    && cp target/release/lowertier-core /tmp/lowertier-core

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates conntrack iperf3 iproute2 iptables iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/lowertier-core /usr/local/bin/lowertier-core
CMD ["/bin/sh"]
