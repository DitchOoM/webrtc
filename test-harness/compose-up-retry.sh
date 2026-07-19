#!/usr/bin/env bash
# Bring up the named services with --wait, retrying transient Docker Hub pull/build failures (i/o
# timeouts on CI runners redden the lane for no real reason). Re-running `up` is idempotent. Mirrors
# socket's test-harness/compose-up-retry.sh.
#
# `--build` forces images to reflect CURRENT source on every run: without it, `compose up` reuses any
# cached image, so a dev box with a stale image (e.g. an older rendezvous.py before the signaling wire
# schema changed) silently runs the wrong code and the whole harness mis-signals. CI is fresh so this is
# free there; locally the incremental rebuild is cached-fast.
#
# Usage: compose-up-retry.sh <service> [<service> ...]   (env/compose files are the caller's concern)
set -uo pipefail
cd "$(dirname "$0")"

attempts=3
for i in $(seq 1 "$attempts"); do
    if docker compose up -d --wait --build "$@"; then
        exit 0
    fi
    if [ "$i" -lt "$attempts" ]; then
        backoff=$((i * 15))
        echo "::warning::'docker compose up --wait $*' failed (attempt $i/$attempts) — likely a transient pull/build; retrying in ${backoff}s"
        sleep "$backoff"
    fi
done
echo "::error::docker harness failed to come up after $attempts attempts ($*)"
exit 1
