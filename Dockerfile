# syntax=docker/dockerfile:1

# ---- dependency-only build stage --------------------------------------
# cargo-chef splits "compile every dependency crate" from "compile
# Magnolia's own code" into two layers keyed on different inputs: the cook
# step below is keyed on recipe.json, which is a function of the workspace's
# Cargo.toml/Cargo.lock files only (not .rs source) -- editing application
# code no longer busts it, so a plain `cargo build` after a source-only
# change reuses every already-built dependency crate instead of recompiling
# the whole dependency graph (magnolia-api alone pulls in axum, sqlx,
# reqwest, etc.) from scratch. See https://github.com/LukeMathWalker/cargo-chef.
FROM rust:1-slim-bookworm AS chef
WORKDIR /app
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cache mounts (persist across builds independent of layer caching, unlike
# a plain COPY-based layer) so even a genuine dependency-graph change (a new
# crate, a version bump) doesn't re-download every crate from crates.io --
# only the ones that actually changed. `target` is mounted too so the
# *compiled* dependency artifacts survive across builds as well; its
# contents never become part of the image layer, hence copying the final
# binary out of it explicitly below.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

# Real source, copied only after the dependency layer above is settled --
# this COPY (and everything after it) is the only thing a day-to-day
# source-code change invalidates.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY scripts ./scripts

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=aise-api-target,target=/app/target,sharing=locked \
    cargo build --release --bin magnolia-server && \
    cp target/release/magnolia-server /app/magnolia-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/magnolia-server /usr/local/bin/magnolia-server

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/magnolia-server"]
