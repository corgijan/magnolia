FROM rust:1-slim-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --bin sbomstash-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sbomstash-server /usr/local/bin/sbomstash-server

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/sbomstash-server"]
