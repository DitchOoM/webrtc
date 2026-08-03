# The headless-browser interop echo-peer image (W7 Phase 2(b)). Node + a Playwright-managed browser,
# selected at build time by `--build-arg BROWSER=chromium|firefox|webkit` (and driven at runtime by the
# same BROWSER env — see driver.mjs). Only the chosen engine is installed, so each browser lane's image
# stays lean. Multi-arch: `playwright install --with-deps` fetches the per-arch build (amd64 or arm64) —
# no cross-compile, no QEMU. Build context is test-harness/browser (compose sets `context: ./browser`).

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
#
# Bounded and retried IN THE BUILD, which is the whole point (webrtc#101). The Playwright CDN
# intermittently **stalls mid-transfer** on the arm64 runner — the download sits at ~50% of 174 MiB and
# never progresses, never errors. Nothing here used to bound the transfer, so a single stall consumed the
# entire 12-minute step budget, and the job's retry step then re-fetched from the same CDN on the same
# host with the same unbounded transfer: it could not protect against the failure mode that actually
# occurred. Worse, the surfaced signal was a red *interop lane* on whatever PR was in flight, pointing a
# reader at the code under review when no peer binary had run at all.
#
# `timeout` turns a stall into a fast, retryable failure: each attempt gets 4 minutes, and a fresh attempt
# opens a new connection, which is what actually clears a wedged transfer. Three attempts plus backoff is
# ~13 minutes worst case, which is why the workflow step budget moved to 16 (it was 12, sized for a
# different failure — the gha cache-export stall — and never for this one).
#
# The status is captured with `|| status=$?` rather than an `if`/`fi`: after a failed `if` with no `else`,
# POSIX defines the compound's status as **0**, so reading `$?` there would report success on every
# failure and the loop would exit 0 on a build that never installed a browser.
RUN set -eu; \
    ok=0; \
    for attempt in 1 2 3; do \
      status=0; \
      timeout --signal=KILL 4m npx playwright install --with-deps "${BROWSER}" || status=$?; \
      if [ "$status" -eq 0 ]; then ok=1; break; fi; \
      if [ "$status" -eq 137 ]; then \
        echo "playwright install: attempt ${attempt} STALLED (SIGKILLed at 4m) — the CDN transfer wedged"; \
      else \
        echo "playwright install: attempt ${attempt} failed with status ${status}"; \
      fi; \
      sleep $((attempt * 15)); \
    done; \
    if [ "$ok" -ne 1 ]; then echo "playwright install: giving up after 3 attempts"; exit 1; fi; \
    rm -rf /var/lib/apt/lists/*

COPY driver.mjs entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
