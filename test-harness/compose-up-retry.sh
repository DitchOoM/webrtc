#!/usr/bin/env bash
# Bring up the named services with --wait, retrying transient Docker Hub pull/build failures (i/o
# timeouts on CI runners redden the lane for no real reason). Re-running `up` is idempotent. Mirrors
# socket's test-harness/compose-up-retry.sh.
#
# Usage: compose-up-retry.sh <service> [<service> ...]   (env/compose files are the caller's concern)
set -uo pipefail
cd "$(dirname "$0")"

attempts=3
for i in $(seq 1 "$attempts"); do
    if docker compose up -d --wait "$@"; then
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
