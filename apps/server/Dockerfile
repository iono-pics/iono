FROM rust:1.97-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin iono-gateway --bin iono-ingest --bin iono-viewer --bin iono-janitor

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/iono-gateway /app/target/release/iono-ingest /app/target/release/iono-viewer /app/target/release/iono-janitor /usr/local/bin/
ENV HOST=0.0.0.0
EXPOSE 8080 8081 8082 8083
COPY --chmod=755 entrypoint.sh /usr/local/bin/iono-entrypoint
CMD ["iono-entrypoint"]
