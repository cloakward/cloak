# syntax=docker/dockerfile:1.7
#
# W9e — Multi-arch container image for `cloakd` (the Cloak daemon).
#
# This image ships ONLY the daemon. The `cloak` CLI and the `cloak-mcp`
# shim are designed for an interactive desktop and have no place in a
# headless container — IPC into the daemon happens over a Unix domain
# socket which the host application is expected to mount.
#
# Build: `docker build -t cloakd-local .`              (host arch only)
# Multi-arch builds happen in CI (.github/workflows/docker-push.yml)
# via `docker buildx build --platform linux/amd64,linux/arm64 ...`.
#
# Runtime contract:
#   * Vault state lives at /var/lib/cloak (declared as a VOLUME).
#   * The pepper file is read from /run/secrets/cloak-pepper. Mount it
#     as a Docker secret — never bake it into the image.
#   * No ports are exposed; IPC is UDS-only.

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
# `rust:1-bookworm` tracks the latest stable Rust on Debian 12, which
# matches `rust-toolchain.toml` (channel = "stable"). Bookworm is also
# what the distroless runtime is built from, so glibc versions line up.
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

# `libsodium-sys-stable` is configured with the `fetch-latest` feature
# in the workspace Cargo.toml, so the build script downloads and
# statically links libsodium itself. We still need pkg-config and the
# usual C toolchain for the build script to run, plus libclang for any
# bindgen invocations.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config \
        libsodium-dev \
        ca-certificates \
        build-essential \
        clang \
 && rm -rf /var/lib/apt/lists/*

# `TARGETARCH` is supplied automatically by buildx (`amd64` or `arm64`).
# Map it to the matching Rust triple. We only support glibc Linux here;
# the musl matrix row in CI is for static-CLI distribution, not the
# daemon container.
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) RUST_TARGET=x86_64-unknown-linux-gnu ;; \
        arm64) RUST_TARGET=aarch64-unknown-linux-gnu ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${RUST_TARGET}"; \
    echo "${RUST_TARGET}" > /tmp/rust-target

WORKDIR /src
COPY . .

# Build only the daemon — the CLI and MCP shim are not shipped here.
# `cargo build --release -p cloak-core --bin cloakd` is the canonical
# invocation; the workspace `Cargo.lock` is committed so we get a
# reproducible build.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    RUST_TARGET="$(cat /tmp/rust-target)"; \
    cargo build --release \
        --target "${RUST_TARGET}" \
        -p cloak-core \
        --bin cloakd; \
    cp "/src/target/${RUST_TARGET}/release/cloakd" /cloakd

# Resolve any dynamic libsodium dependency. With `fetch-latest`,
# libsodium is statically linked into `cloakd`, so `ldd` reports no
# libsodium entry and we leave a zero-byte placeholder. If a future
# toolchain change switches to dynamic linking, this branch copies the
# `.so` so the runtime image still works.
#
# The placeholder exists because `COPY --from=builder` in stage 2
# requires the source path to be present; conditional COPY is not a
# Dockerfile feature.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    mkdir -p /sodium; \
    if ldd /cloakd | grep -q libsodium; then \
        SODIUM_PATH="$(ldd /cloakd | awk '/libsodium/ {print $3}')"; \
        cp -L "${SODIUM_PATH}" /sodium/libsodium.so; \
    else \
        : > /sodium/.static; \
    fi

# -----------------------------------------------------------------------------
# Stage 2 — runtime (distroless)
# -----------------------------------------------------------------------------
# `cc-debian12` ships glibc + libgcc + libstdc++ but no shell and no
# package manager, which keeps the attack surface minimal. The daemon
# never needs to shell out, so this is sufficient.
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/cloakward/cloak"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="cloakd"
LABEL org.opencontainers.image.description="MCP-native local secrets vault — daemon"
LABEL org.opencontainers.image.documentation="https://github.com/cloakward/cloak/blob/main/docs/QUICKSTART.md"
LABEL io.cloak.volume.var-lib-cloak="vault state — mount a named volume here so secrets survive container restarts"

COPY --from=builder /cloakd /cloakd
# Copy the libsodium directory from stage 1. With the current
# `fetch-latest` build this contains only a `.static` marker (which is
# harmless); if dynamic linking ever returns it will contain the
# `libsodium.so` the linker resolves at runtime. Distroless's dynamic
# linker searches /usr/lib by default.
COPY --from=builder /sodium/ /usr/lib/cloak/

# Vault state. Operators are expected to mount a named volume here.
VOLUME ["/var/lib/cloak"]

# Pepper is mounted as a Docker secret. The daemon reads the path from
# this env var; it never needs to be on the image filesystem at build
# time.
ENV CLOAK_PEPPER_FILE=/run/secrets/cloak-pepper

# IPC is UDS-only. No ports are exposed.

ENTRYPOINT ["/cloakd"]
