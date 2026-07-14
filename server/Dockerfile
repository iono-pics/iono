FROM rust:1-slim AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin iono-gateway --bin iono-ingest --bin iono-viewer

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/iono-gateway /app/target/release/iono-ingest /app/target/release/iono-viewer /usr/local/bin/
EXPOSE 8080 8081 8082
CMD ["bash", "-c", "iono-gateway & iono-ingest & iono-viewer & wait -n"]
