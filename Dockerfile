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
# via two native runner jobs (ubuntu-24.04 for linux/amd64,
# ubuntu-24.04-arm for linux/arm64); the per-arch images are then
# stitched into a multi-arch manifest with `docker buildx imagetools
# create`. We deliberately do NOT cross-compile inside Docker — the
# previous `FROM --platform=$BUILDPLATFORM` + `rustup target add`
# arrangement consistently failed with `error[E0463]: can't find
# crate for core` (#46).
#
# Runtime contract:
#   * Vault, audit, policy, and runtime socket state live under
#     /var/lib/cloak (declared as a VOLUME and wired via XDG env vars).
#   * The pepper file is read from /run/secrets/cloak-pepper. Mount it
#     as a Docker secret — never bake it into the image.
#   * No ports are exposed; IPC is UDS-only.

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
# `rust:1-bookworm` tracks the latest stable Rust on Debian 12, which
# matches `rust-toolchain.toml` (channel = "stable"). Bookworm is also
# what the distroless runtime is built from, so glibc versions line up.
#
# No `--platform=$BUILDPLATFORM` here: each CI build runs on a native
# runner for the target architecture (ubuntu-24.04 for amd64,
# ubuntu-24.04-arm for arm64), so the builder pulls the right
# rust:1-bookworm tag automatically and the entire compile is native.
FROM rust:1-bookworm AS builder

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

WORKDIR /src
COPY . .

# Build only the daemon — the CLI and MCP shim are not shipped here.
# `cargo build --release -p cloak-core --bin cloakd` is the canonical
# invocation; the workspace `Cargo.lock` is committed so we get a
# reproducible build. No `--target` flag because the host arch IS
# the target arch (native build per-runner).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    cargo build --release -p cloak-core --bin cloakd; \
    cp /src/target/release/cloakd /cloakd

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

# Seed the runtime volume with directories owned by distroless nonroot
# (uid/gid 65532). Docker named volumes copy this ownership from the
# image on first use; bind mounts must be owned/chmodded by the operator.
RUN set -eux; \
    install -d -m 0700 \
      /runtime-var-lib-cloak/.local/share/cloak \
      /runtime-var-lib-cloak/.config/cloak \
      /runtime-var-lib-cloak/run \
      /runtime-var-lib-cloak/tmp; \
    chown -R 65532:65532 /runtime-var-lib-cloak

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
COPY --from=builder --chown=65532:65532 /runtime-var-lib-cloak/ /var/lib/cloak/

# Vault/audit/config/runtime state. Operators are expected to mount a named
# volume here. These env vars make Rust's `dirs` resolution land on the
# declared volume instead of the distroless user's default home.
ENV HOME=/var/lib/cloak
ENV XDG_DATA_HOME=/var/lib/cloak/.local/share
ENV XDG_CONFIG_HOME=/var/lib/cloak/.config
ENV XDG_RUNTIME_DIR=/var/lib/cloak/run
ENV TMPDIR=/var/lib/cloak/tmp
VOLUME ["/var/lib/cloak"]

# Pepper is mounted as a Docker secret. The daemon reads the path from
# this env var; it never needs to be on the image filesystem at build
# time.
ENV CLOAK_PEPPER_FILE=/run/secrets/cloak-pepper

# IPC is UDS-only. No ports are exposed.

ENTRYPOINT ["/cloakd"]
