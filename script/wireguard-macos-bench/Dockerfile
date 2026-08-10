FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iperf3 \
        iproute2 \
        iputils-ping \
        procps \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
