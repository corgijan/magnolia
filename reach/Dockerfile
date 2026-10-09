# syntax=docker/dockerfile:1
#
# `reach` builds independently of AISE — its own Cargo project, its own
# dependency graph, its own image. Same cargo-chef layering as the root
# Dockerfile so a source-only change does not recompile axum and reqwest.

FROM rust:1-slim-bookworm AS chef
WORKDIR /app
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
# The eval fixtures and cases ship in the image so the suite is runnable
# inside the container (`docker compose exec reach eval`), which is how the
# submission demonstrates it without a Rust toolchain on the host.
COPY eval ./eval

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=aise-reach-target,target=/app/target,sharing=locked \
    cargo build --release --bins && \
    cp target/release/reach /app/reach && \
    cp target/release/eval /app/eval-bin

FROM debian:bookworm-slim
# git and tar are runtime dependencies, not build ones: the fetcher shells
# out to them. ca-certificates is what makes https:// clones work at all.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git tar \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/reach /usr/local/bin/reach
COPY --from=builder /app/eval-bin /usr/local/bin/reach-eval
COPY --from=builder /app/eval /opt/reach/eval

# Never run the analyser as root: it checks out untrusted repositories and
# shells out to git. Repository content is never executed, but a non-root
# user is the cheap second lock on that.
RUN useradd --create-home --uid 10001 reach \
    && mkdir -p /data /cache \
    && chown -R reach:reach /data /cache /opt/reach
USER reach

ENV REACH_DB_PATH=/data/reach.db \
    REACH_CACHE_DIR=/cache \
    REACH_SERVER_ADDR=0.0.0.0:3100

EXPOSE 3100

# start-period is generous on purpose: the process now refuses to bind its
# listener at all until a real test completion against the configured
# inference endpoint succeeds (see main.rs), and that can legitimately take
# most of REACH_AI_TIMEOUT_SECS (120s by default in compose) on a slow or
# cold local model. Before the listener is up, every healthcheck attempt
# fails fast (connection refused) rather than hanging, but a start-period
# too short would still mark a container "unhealthy" while it is correctly
# waiting, not failing — 180s comfortably covers the default timeout.
HEALTHCHECK --interval=15s --timeout=3s --start-period=180s --retries=5 \
    CMD ["/usr/local/bin/reach", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/reach"]
