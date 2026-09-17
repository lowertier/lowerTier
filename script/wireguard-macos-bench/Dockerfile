FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        ethtool \
        iperf3 \
        iproute2 \
        iputils-ping \
        jq \
        procps \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
