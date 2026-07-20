# The headless-browser interop echo-peer image (W7 Phase 2(b)). Node + a Playwright-managed browser,
# selected at build time by `--build-arg BROWSER=chromium|firefox` (and driven at runtime by the same
# BROWSER env — see driver.mjs). Only the chosen engine is installed, so each browser lane's image stays
# lean. Multi-arch: `playwright install --with-deps` fetches the per-arch build (amd64 or arm64) — no
# cross-compile, no QEMU. Build context is test-harness/browser (compose sets `context: ./browser`).

# Node 24 (current Active LTS; Node 20 is EOL). -slim over the full image saves ~700 MB of base tooling we
# don't need — `playwright install --with-deps` below pulls the browser's actual runtime libs via apt.
FROM node:24-bookworm-slim

WORKDIR /app

# Which engine this image runs — chromium (Chrome lane) or firefox (Firefox lane).
ARG BROWSER=chromium

# iproute2 for the NAT default-route rewrite in entrypoint.sh (same as the native/Pion peer images).
# ca-certificates so the npm + Playwright browser downloads validate TLS. (Not cleaning the apt lists
# here: `playwright install --with-deps` immediately below needs a populated apt cache to resolve the
# browser's system deps; it does its own apt-get update, but keeping the lists avoids a redundant fetch.)
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 ca-certificates

# Install playwright first (its version pins the browser build fetched below), cached across driver edits.
COPY package.json ./
RUN npm install --no-audit --no-fund

# Fetch ONLY the selected engine + its system dependencies, for THIS image's arch.
RUN npx playwright install --with-deps "${BROWSER}" && rm -rf /var/lib/apt/lists/*

COPY driver.mjs entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
