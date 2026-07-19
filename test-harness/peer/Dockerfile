# Portable, self-building peer image (the default). The builder stage compiles the native peer for the
# image's TARGET platform, so `docker compose build` produces the right binary on ANY host/arch —
# linux/amd64, linux/arm64, and Apple Silicon (Colima or Apple's `container` CLI, which run a linux/arm64
# VM). No cross-compilation and no QEMU: on an arm64 host the arm64 image builds natively (native gcc →
# BoringSSL arm64 → linuxArm64 peer); on x64, x64. Heavy first build (K/N toolchain + BoringSSL), cached
# after. For a fast CI/Linux path that skips this, see Dockerfile.prebuilt (used by run-interop.sh when
# the binary is already built on the host).
#
# Build context is the REPO ROOT (compose sets context: ..), so the builder sees every module.

FROM eclipse-temurin:21-jdk AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake make gcc g++ git perl ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Map Docker's TARGETARCH → the Kotlin/Native target, then link the release peer for THIS platform.
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) KN=X64 ;; \
      arm64) KN=Arm64 ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    ./gradlew --no-daemon --no-configuration-cache \
        ":webrtc-harness-endpoint:linkPeerReleaseExecutableLinux${KN}"; \
    cp "webrtc-harness-endpoint/build/bin/linux${KN}/peerReleaseExecutable/peer.kexe" /peer.kexe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 libstdc++6 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /peer.kexe /usr/local/bin/peer
COPY test-harness/peer/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/peer
ENTRYPOINT ["/entrypoint.sh"]
