FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential mold pkg-config libssl-dev protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --quiet --locked --release -p lowertier --bin lowertier-core -p lowertier-tracker --bin lowertier-tracker --no-default-features --features lowertier/tun,lowertier-tracker/server \
    && cp target/release/lowertier-core target/release/lowertier-tracker /tmp/

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates conntrack iperf3 iproute2 iptables iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/lowertier-core /usr/local/bin/lowertier-core
COPY --from=builder /tmp/lowertier-tracker /usr/local/bin/lowertier-tracker
CMD ["/bin/sh"]
