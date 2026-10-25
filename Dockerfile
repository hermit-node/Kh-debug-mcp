FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN cargo build --locked --release --bin kh-debug-mcp -j 2

FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04
USER root
RUN groupadd --gid 10001 khdebug && useradd --uid 10001 --gid 10001 --create-home khdebug \
    && mkdir -p /data/screenshots && chown -R 10001:10001 /data
COPY --from=builder /build/target/release/kh-debug-mcp /usr/local/bin/kh-debug-mcp
USER 10001:10001
ENV KH_DEBUG_BIND=0.0.0.0:41370 KH_DEBUG_IMAGE_DIR=/data/screenshots HOME=/tmp XDG_CONFIG_HOME=/tmp/.config
WORKDIR /home/khdebug
EXPOSE 41370
ENTRYPOINT ["/usr/local/bin/kh-debug-mcp"]
