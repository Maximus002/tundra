FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin tundra-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash tundra
COPY --from=builder /app/target/release/tundra-server /usr/local/bin/tundra-server
USER tundra
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/bin/sh", "-c", "ss -tlnp | grep -q 8443 || exit 1"]
ENTRYPOINT ["tundra-server"]
CMD ["--config", "/etc/tundra/tundra-server.toml"]
