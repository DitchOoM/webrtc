#!/usr/bin/env bash
# L2 interop orchestrator — drives the container harness through the full scenario matrix and asserts a
# two-peer establish + data-channel echo in each. This is the Phase-1 exit gate: two peers establish over
# EACH NAT profile against real kernels (plus a relay-only and an impaired lane).
#
# For every scenario it: swaps the NAT profile(s)/policy, (re)starts coturn + rendezvous + both NATs,
# applies any netem, runs both peers to completion, and PASSES iff BOTH peers exit 0 (each exits 0 only
# after it CONNECTED and the ping/pong crossed the encrypted data channel). Fails the whole run if any
# scenario fails. Every run tears the stack down (containers + networks + volumes) via an EXIT trap.
#
# Usage:
#   ./run-interop.sh                 # full matrix, prebuilt-binary fast path (host gradle build)
#   HARNESS_SELF_BUILD=1 ./run-interop.sh   # build the peer inside its image (portable: macOS/Apple, arm64)
#   ./run-interop.sh <scenario-name> # run a single scenario by name
set -uo pipefail
cd "$(dirname "$0")"

# ── config from the single source of truth (also exported for compose ${VAR} substitution) ──
set -a
# shellcheck disable=SC1091
. ./harness.env
set +a

# ── peer image path: three ways to get the binary into the image ──
#   1. HARNESS_SELF_BUILD=1        → build inside the image (portable: macOS/Apple, any arch)
#   2. PEER_KEXE points at a file  → use it as-is, DON'T build (CI ships a cross-built artifact this way —
#                                    K/N can't host on linux-arm64, so the arm64 peer is cross-built on x64
#                                    and the arm64 runner only RUNS it)
#   3. otherwise                   → build on the host for the host arch (local Linux dev)
if [ "${HARNESS_SELF_BUILD:-0}" = "1" ]; then
    export PEER_DOCKERFILE="Dockerfile"
    echo "[run] peer image: self-building inside the image (portable — arm64 / Apple / x64)"
elif [ -n "${PEER_KEXE:-}" ] && [ -f "../${PEER_KEXE}" ]; then
    export PEER_DOCKERFILE="Dockerfile.prebuilt"
    echo "[run] peer image: prebuilt (supplied) ${PEER_KEXE}"
else
    case "$(uname -m)" in
        x86_64|amd64) KN=X64 ;;
        aarch64|arm64) KN=Arm64 ;;
        *) echo "[run] unknown arch $(uname -m); falling back to self-build"; KN="" ;;
    esac
    if [ -n "$KN" ]; then
        echo "[run] building peer binary on host (linux$KN)…"
        ( cd .. && ./gradlew --no-daemon --no-configuration-cache \
            ":webrtc-harness-endpoint:linkPeerReleaseExecutableLinux${KN}" )
        export PEER_DOCKERFILE="Dockerfile.prebuilt"
        export PEER_KEXE="webrtc-harness-endpoint/build/bin/linux${KN}/peerReleaseExecutable/peer.kexe"
        echo "[run] peer image: prebuilt $PEER_KEXE"
    else
        export PEER_DOCKERFILE="Dockerfile"
    fi
fi

INFRA="coturn rendezvous nat_a nat_b"

# Docker-host setup: a container acting as a router BETWEEN two Docker bridge networks only forwards if
# host bridge-netfilter is OFF — otherwise the bridged frames traverse the host's Docker FORWARD/ISOLATION
# chain (via physdev) and get dropped, so no traffic crosses the NAT (seen as peers stuck in New/Connecting).
# Set it via a privileged host-netns container (the daemon is root even where the caller isn't).
#
# This is a HOST-GLOBAL sysctl affecting every Docker workload, so we capture the original value and
# RESTORE it on teardown rather than leaving the host mutated. On a plain Linux CI runner you may instead
# `sudo sysctl` it in the workflow (there the runner is disposable, so restore is moot).
BRIDGE_NF_ORIG=$(docker run --rm --privileged --network host alpine:3.20 \
    sh -c 'cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null' 2>/dev/null || echo "")

teardown() {
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    # Restore the host sysctl we changed, so the harness leaves no global footprint.
    if [ -n "$BRIDGE_NF_ORIG" ]; then
        docker run --rm --privileged --network host alpine:3.20 \
            sysctl -w "net.bridge.bridge-nf-call-iptables=$BRIDGE_NF_ORIG" >/dev/null 2>&1 || true
    fi
}
trap teardown EXIT

docker run --rm --privileged --network host alpine:3.20 \
    sysctl -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1 \
    || echo "::warning::could not set bridge-nf-call-iptables=0 — container routing across NATs may fail"

# ── the scenario matrix — name | nat_a | nat_b | ice_policy | netem(args or "-") ──
# Covers each of the four NAT profiles, the symmetric→relay fallback, an explicit relay-only lane, and an
# impaired data path. Each expects BOTH peers to exit 0.
SCENARIOS="
full-cone            | full-cone          | full-cone          | all   | -
port-restricted      | port-restricted    | port-restricted    | all   | -
address-restricted   | address-restricted | address-restricted | all   | -
symmetric-relay      | symmetric          | symmetric          | all   | -
mixed-sym-port       | symmetric          | port-restricted    | all   | -
relay-only           | port-restricted    | port-restricted    | relay | -
impaired-loss-delay  | port-restricted    | port-restricted    | all   | loss 5% delay 20ms 5ms distribution normal
"

only="${1:-}"
pass=0; fail=0; failed_names=""

run_scenario() {
    local name="$1" nat_a="$2" nat_b="$3" policy="$4" netem="$5"
    echo ""
    echo "═══ scenario: $name  (nat_a=$nat_a nat_b=$nat_b policy=$policy netem=${netem}) ═══"

    export NAT_A_PROFILE="$nat_a" NAT_B_PROFILE="$nat_b" ICE_POLICY="$policy" SESSION="$name"

    # Fresh stack per scenario for isolation (NAT rules + conntrack state must not bleed across profiles).
    teardown
    if ! ./compose-up-retry.sh $INFRA; then
        echo "::error::[$name] infra failed to come up"; fail=$((fail+1)); failed_names="$failed_names $name"; return
    fi

    if [ "$netem" != "-" ]; then
        # Fail-HARD if netem can't be applied — otherwise the impaired lane silently runs UNIMPAIRED and
        # passes, giving false confidence in the one scenario whose whole point is the degraded data path.
        if ! docker compose exec -T nat_a /netem.sh add $netem || ! docker compose exec -T nat_b /netem.sh add $netem; then
            echo "::error::[$name] netem failed to apply — impaired lane would run unimpaired"
            fail=$((fail + 1)); failed_names="$failed_names $name"; return
        fi
    fi

    # Start both peers; they run to completion (establish + echo, or watchdog timeout) and exit.
    docker compose up -d peer_a peer_b
    # `docker compose wait` blocks until stop; its output form varies ("0" vs "container … status code 0"),
    # so extract the trailing exit code robustly.
    local rc_a rc_b
    rc_a=$(docker compose wait peer_a 2>/dev/null | grep -oE '[0-9]+$' | tail -1)
    rc_b=$(docker compose wait peer_b 2>/dev/null | grep -oE '[0-9]+$' | tail -1)

    echo "── peer_a (offerer) ──"; docker compose logs --no-log-prefix peer_a
    echo "── peer_b (answerer) ──"; docker compose logs --no-log-prefix peer_b

    if [ "$rc_a" = "0" ] && [ "$rc_b" = "0" ]; then
        echo "✅ [$name] PASS (offerer rc=$rc_a answerer rc=$rc_b)"; pass=$((pass+1))
    else
        echo "::error::❌ [$name] FAIL (offerer rc=$rc_a answerer rc=$rc_b)"
        fail=$((fail+1)); failed_names="$failed_names $name"
    fi
}

# Here-string (not a pipe) so the loop runs in THIS shell and the tallies persist.
while IFS='|' read -r name a b policy netem; do
    name=$(echo "$name" | xargs); [ -z "$name" ] && continue
    a=$(echo "$a" | xargs); b=$(echo "$b" | xargs); policy=$(echo "$policy" | xargs); netem=$(echo "$netem" | xargs)
    if [ -n "$only" ] && [ "$only" != "$name" ]; then continue; fi
    run_scenario "$name" "$a" "$b" "$policy" "$netem"
done <<< "$SCENARIOS"

echo ""
echo "═══ summary: $pass passed, $fail failed${failed_names:+ (failed:$failed_names)} ═══"
[ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]
exit $?
