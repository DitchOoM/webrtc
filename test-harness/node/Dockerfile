# The node/werift (pure-TypeScript WebRTC) interop echo-peer image — a JavaScript-engine differential
# oracle alongside Pion (Go) and the browsers. Multi-arch: werift is JS + prebuilt native addons that npm
# resolves for the image's platform, so this builds natively for x64 or arm64 (no cross-compile, no QEMU),
# matching the L2 harness's arch-matched runner strategy.
#
# Build context is test-harness/node (compose sets `context: ./node`).

FROM node:24-slim

# iproute2 for the NAT default-route rewrite in entrypoint.sh (same as the pion/native images).
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first so the layer caches across source edits. We ship no committed package-lock.json —
# werift is pinned EXACTLY in package.json — so `npm install --omit=dev` (not `npm ci`, which requires a
# lockfile). --omit=dev keeps only the runtime dependency (werift).
COPY package.json ./
RUN npm install --omit=dev

# Source (the ESM peer + its signaling client).
COPY peer.mjs signaling.mjs ./
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
