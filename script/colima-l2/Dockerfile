FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential mold pkg-config libssl-dev protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --quiet --locked --release -p easytier --bin easytier-core --no-default-features --features tun \
    && cp target/release/easytier-core /tmp/easytier-core

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping iperf3 python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/easytier-core /usr/local/bin/easytier-core
COPY script/colima-l2/frame_probe.py /usr/local/bin/frame_probe.py
COPY script/traffic_signature_scan.py /usr/local/bin/traffic_signature_scan.py
CMD ["/bin/sh"]
