ARG LOWTIER_BUILDER_IMAGE=rust:1.95-bookworm
ARG LOWTIER_RUNTIME_IMAGE=debian:bookworm-slim

FROM ${LOWTIER_BUILDER_IMAGE} AS builder

ARG LOWTIER_BUILD_FEATURES=tun
ARG LOWTIER_INSTALL_PACKAGES=true
ARG LOWTIER_CARGO_COMMAND=cargo

RUN if [ "$LOWTIER_INSTALL_PACKAGES" = true ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends build-essential mold pkg-config libssl-dev protobuf-compiler libprotobuf-dev \
        && rm -rf /var/lib/apt/lists/*; \
    fi
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    $LOWTIER_CARGO_COMMAND build --quiet --locked --release -p lowertier --bin lowertier-core --bin lowertier-cli --no-default-features --features "$LOWTIER_BUILD_FEATURES" \
    && cp target/release/lowertier-core /tmp/lowertier-core \
    && cp target/release/lowertier-cli /tmp/lowertier-cli

FROM ${LOWTIER_RUNTIME_IMAGE}

ARG LOWTIER_INSTALL_PACKAGES=true
ARG LOWTIER_BUILD_FEATURES=tun
ARG LOWTIER_SOURCE_REVISION=unknown
ARG LOWTIER_SOURCE_DIGEST=unknown
LABEL org.opencontainers.image.revision="${LOWTIER_SOURCE_REVISION}"
LABEL dev.lowertier.source-digest="${LOWTIER_SOURCE_DIGEST}"
LABEL dev.lowertier.build-features="${LOWTIER_BUILD_FEATURES}"
RUN if [ "$LOWTIER_INSTALL_PACKAGES" = true ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends iproute2 iputils-ping iperf3 python3 ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi
COPY --from=builder /tmp/lowertier-core /usr/local/bin/lowertier-core
COPY --from=builder /tmp/lowertier-cli /usr/local/bin/lowertier-cli
COPY script/colima-l2/frame_probe.py /usr/local/bin/frame_probe.py
COPY script/traffic_signature_scan.py /usr/local/bin/traffic_signature_scan.py
CMD ["/bin/sh"]
