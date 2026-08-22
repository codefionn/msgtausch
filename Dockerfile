# syntax=docker/dockerfile:1.7

# Run the compiler on the builder's native CPU. Zig supplies the target musl
# toolchain, so an amd64 runner can produce arm64 binaries without QEMU.
FROM --platform=${BUILDPLATFORM} docker.io/rust:1.97-alpine AS rust-builder
ARG TARGETPLATFORM
ARG TARGETARCH
ARG BUILDARCH
ARG VERSION=dev
RUN test "${TARGETPLATFORM}" = "linux/amd64" || test "${TARGETPLATFORM}" = "linux/arm64"
RUN apk add --no-cache musl-dev pkgconfig protobuf && \
    if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      apk add --no-cache zig && \
      cargo install cargo-zigbuild --version 0.23.0 --locked; \
    fi
RUN if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      case "${TARGETARCH}" in \
        amd64) rust_target=x86_64-unknown-linux-musl ;; \
        arm64) rust_target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
      esac && \
      rustup target add "${rust_target}"; \
    fi
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=msgtausch-target-${TARGETPLATFORM},target=/src/target \
    if [ "${TARGETARCH}" = "${BUILDARCH}" ]; then \
      MSGTAUSCH_VERSION=${VERSION} cargo build --release --bin msgtausch && \
      cp target/release/msgtausch /tmp/msgtausch; \
    else \
      case "${TARGETARCH}" in \
        amd64) rust_target=x86_64-unknown-linux-musl ;; \
        arm64) rust_target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
      esac && \
      MSGTAUSCH_VERSION=${VERSION} cargo zigbuild --release --bin msgtausch --target "${rust_target}" && \
      cp "target/${rust_target}/release/msgtausch" /tmp/msgtausch; \
    fi

# The artifact stage is intentionally only the proxy binary. Bake's local
# exporters use it so their architecture-specific output directories do not
# contain a copied Alpine root filesystem.
FROM scratch AS binary
COPY --from=rust-builder /tmp/msgtausch /msgtausch

FROM --platform=${BUILDPLATFORM} docker.io/rust:1.97-alpine AS rust-checks
RUN apk add --no-cache musl-dev pkgconfig protobuf && \
    rustup component add clippy rustfmt
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY examples ./examples

FROM rust-checks AS format-check
RUN cargo fmt --all --check

FROM rust-checks AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=msgtausch-check-target,target=/src/target \
    cargo test --workspace --all-targets

FROM rust-checks AS clippy
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=msgtausch-clippy-target,target=/src/target \
    cargo clippy --workspace --all-targets --all-features -- -D warnings

FROM rust-checks AS simulation
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=msgtausch-simulation-target,target=/src/target \
    cargo build -p msgtausch-cli --bin msgtausch && \
    cargo build -p msgtausch-simulation --bin msgtausch-simulation && \
    target/debug/msgtausch-simulation --binary target/debug/msgtausch --scenario crates/msgtausch-simulation/corpus/plain-connect-789.json --stats && \
    target/debug/msgtausch-simulation --binary target/debug/msgtausch --scenario crates/msgtausch-simulation/corpus/http-methods-bodies-792.json --stats && \
    target/debug/msgtausch-simulation --binary target/debug/msgtausch --scenario crates/msgtausch-simulation/corpus/forward-routes-790.json --enable-forwards --stats && \
    target/debug/msgtausch-simulation --binary target/debug/msgtausch --scenario crates/msgtausch-simulation/corpus/policy-dns-domains-791.json --enable-policy-fixtures --stats && \
    target/debug/msgtausch-simulation --binary target/debug/msgtausch --scenario crates/msgtausch-simulation/corpus/routes-policy-failures-793.json --enable-policy-fixtures --stats && \
    target/debug/msgtausch-simulation 9000 --binary target/debug/msgtausch --runs 4 --jobs 2 --enable-policy-fixtures --stats

# Throughput is a loopback check. It deliberately stays on BUILDPLATFORM via
# rust-checks rather than running under QEMU as part of the release image.
FROM rust-checks AS throughput
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=msgtausch-throughput-target,target=/src/target \
    cargo build -p msgtausch-cli --bin msgtausch && \
    cargo run -p msgtausch-throughput -- --protocol both --requests 16 --concurrency 2 --body-size 8192 --warmup 1 --deadline 30s

FROM --platform=${TARGETPLATFORM} docker.io/library/alpine:3.22.1 AS runtime-dev
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H app
COPY --from=rust-builder /tmp/msgtausch /msgtausch
USER app
EXPOSE 8080 9090
ENTRYPOINT ["/msgtausch"]
CMD ["--config", "/config.json"]

FROM runtime-dev AS runtime-release

FROM nixos/nix:2.28.3 AS nix-build
WORKDIR /src
RUN nix --version
COPY flake.nix flake.lock ./
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY examples ./examples
RUN nix --extra-experimental-features 'nix-command flakes' build .#msgtausch && \
    test -x result/bin/msgtausch && \
    result/bin/msgtausch --help
