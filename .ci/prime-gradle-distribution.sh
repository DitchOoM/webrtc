#!/usr/bin/env bash
# Fetch the Gradle distribution the wrapper needs, retrying a flaky CDN, BEFORE any step that runs a
# real build. Mirrors test-harness/compose-up-retry.sh, for the same reason: a transient upstream fetch
# should not redden a lane that has nothing wrong with it.
#
# WHY THIS EXISTS. `./gradlew` downloads gradle-<version>-bin.zip from services.gradle.org on a cache
# miss, and `org.gradle.wrapper.Install` has NO retry — one bad response is a dead job. On 2026-08-12
# that CDN served intermittent 503s and truncated responses (`java.net.SocketException: Unexpected end
# of file from server`) for ~2.5 hours, and it took out jobs across four workflows on both open PRs.
# PR runs are the exposed ones: `gradle/actions/setup-gradle` restores its cache READ-ONLY off the
# default branch, so a PR whose key does not match ("Entry not restored: no match found") fetches fresh
# every time.
#
# The one that hurt was `compute-version`. Every downstream lane needs its output, so a ~10-second
# configuration-only job losing a coin flip against a CDN skipped build-linux, build-apple,
# consumer-smoke and validate — a whole PR build, with no failure anywhere in the tree.
#
# Priming once per job is enough for the whole job: the wrapper unpacks into
# <gradle-user-home>/wrapper/dists and every later `./gradlew` in that job reuses it. So this runs once
# after setup-gradle, and the 14 `./gradlew` call sites stay untouched.
#
# What this does NOT do is survive a sustained outage — five attempts span ~2.5 minutes, and the
# incident above ran far longer. It buys the blips, which are the common case, and when it does give up
# it says so as a named CI error instead of a raw Java stack trace from the wrapper.
#
# Usage: prime-gradle-distribution.sh [<gradle-user-home>]
#   With no argument the wrapper's default applies (GRADLE_USER_HOME, else ~/.gradle) — every lane
#   except consumer-smoke, which builds under a throwaway home. `-g` redirects the WRAPPER's own
#   download too, not just the build's caches, so that lane has to prime the home it will actually use
#   or it re-downloads unprotected. Priming there costs its coldness nothing: `--version` neither
#   resolves a dependency nor reads a build cache, which is all "cold" means for that lane.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

guh_args=()
if [ "$#" -gt 0 ] && [ -n "$1" ]; then
    guh_args=(-g "$1")
fi

attempts=5
for i in $(seq 1 "$attempts"); do
    if ./gradlew "${guh_args[@]}" --version; then
        exit 0
    fi
    if [ "$i" -lt "$attempts" ]; then
        backoff=$((i * 15))
        echo "::warning::Gradle distribution fetch failed (attempt $i/$attempts) — likely a transient CDN error; retrying in ${backoff}s"
        sleep "$backoff"
    fi
done
echo "::error::Gradle distribution unreachable after $attempts attempts — services.gradle.org is failing, not this branch"
exit 1
