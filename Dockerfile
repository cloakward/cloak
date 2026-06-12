# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# W9e - Multi-arch container image for `cloakd` (the Cloak daemon).
#
# This image starts the daemon and also carries the trusted `cloak` CLI
# sibling needed by installed-binary peer pinning. It does not ship the
# `cloak-mcp` shim; IPC into the daemon happens over a Unix domain socket
# which the host application is expected to mount.
#
# Build: `docker build -t cloakd-local .`              (host arch only)
# Multi-arch builds happen in CI (.github/workflows/docker-push.yml)
# via two native runner jobs (ubuntu-24.04 for linux/amd64,
# ubuntu-24.04-arm for linux/arm64); the per-arch images are then
# stitched into a multi-arch manifest with `docker buildx imagetools
# create`. We deliberately do NOT cross-compile inside Docker - the
# previous `FROM --platform=$BUILDPLATFORM` + `rustup target add`
# arrangement consistently failed with `error[E0463]: can't find
# crate for core` (#46).
#
# Runtime contract:
#   * Vault, audit, policy, and runtime socket state live under
#     /var/lib/cloak (declared as a VOLUME and wired via XDG env vars).
#   * The pepper file is read from /run/secrets/cloak-pepper. Mount it
#     as a Docker secret - never bake it into the image.
#   * No ports are exposed; IPC is UDS-only.

# -----------------------------------------------------------------------------
# Stage 1 - builder
# -----------------------------------------------------------------------------
# `rust:1.94.1-bookworm` matches `rust-toolchain.toml` and is pinned by
# multi-arch index digest. Bookworm is also what the distroless runtime is
# built from, so glibc versions line up.
#
# Debian apt inputs are pinned to a snapshot timestamp so rerunning the same
# tag does not silently pick up newer build tools. Bump this timestamp in the
# same review as any intentional Docker builder package refresh.
ARG DEBIAN_SNAPSHOT=20250115T000000Z
#
# No `--platform=$BUILDPLATFORM` here: each CI build runs on a native
# runner for the target architecture (ubuntu-24.04 for amd64,
# ubuntu-24.04-arm for arm64), so the builder pulls the right
# pinned rust index automatically and the entire compile is native.
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS builder
ARG DEBIAN_SNAPSHOT=20250115T000000Z

# The workspace builds libsodium from a source archive pinned by SHA via
# `scripts/prepare-libsodium-dist.sh`, so the C crypto library does not move
# without an intentional hash update.
RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends \
      pkg-config \
      ca-certificates \
      curl \
      build-essential; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build the daemon and its trusted CLI sibling. The container entrypoint is
# still `cloakd`, but the daemon's installed-binary peer pin requires a
# `cloak` binary next to `cloakd` at startup. The MCP shim is not shipped in
# this image.
RUN ./scripts/prepare-libsodium-dist.sh /src/.cargo/libsodium-dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    SODIUM_DIST_DIR=/src/.cargo/libsodium-dist \
      cargo build --locked --release -p cloak-core --bin cloakd -p cloak-cli --bin cloak; \
    cp /src/target/release/cloakd /cloakd; \
    cp /src/target/release/cloak /cloak

# The release image must not depend on a runtime-provided libsodium. If the
# build ever regresses to dynamic libsodium linkage, fail here instead of
# shipping an image that only works when an unpinned system library happens to
# be present.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    ! ldd /cloakd | grep -i libsodium; \
    ! ldd /cloak | grep -i libsodium

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
# Stage 2 - runtime (distroless)
# -----------------------------------------------------------------------------
# `cc-debian12` ships glibc + libgcc + libstdc++ but no shell and no
# package manager, and is pinned by multi-arch index digest. The daemon
# never needs to shell out, so this is sufficient.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c

LABEL org.opencontainers.image.source="https://github.com/cloakward/cloak"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.title="cloakd"
LABEL org.opencontainers.image.description="MCP-native local secrets vault - daemon"
LABEL org.opencontainers.image.documentation="https://github.com/cloakward/cloak/blob/main/docs/QUICKSTART.md"
LABEL io.cloak.volume.var-lib-cloak="vault state - mount a named volume here so secrets survive container restarts"

COPY --from=builder /cloakd /cloakd
COPY --from=builder /cloak /cloak
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
