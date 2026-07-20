# The Pion (Go) interop echo-peer image. Multi-arch (builds natively for the image's TARGETARCH — x64 or
# arm64 — no cross-compile, no QEMU), so it matches the L2 harness's arch-matched runner strategy. The Go
# module is self-contained (go.mod/go.sum pinned), so the build context is just this directory.
#
# Build context is test-harness/pion (compose sets `context: ./pion`).

FROM golang:1.22-bookworm AS builder
WORKDIR /src
# Pre-fetch deps against the pinned go.sum so the layer caches across source edits.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binary (CGO off) → runs on the slim runtime with no libc coupling.
RUN CGO_ENABLED=0 go build -trimpath -o /pion-echo .

FROM debian:bookworm-slim
# iproute2 for the NAT default-route rewrite in entrypoint.sh (same as the native peer image).
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /pion-echo /usr/local/bin/pion-echo
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/pion-echo
ENTRYPOINT ["/entrypoint.sh"]
