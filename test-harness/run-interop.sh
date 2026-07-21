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

# ── JVM peer jar (only used by a_impl=jvm scenarios; resolved up front, mirroring the native binary) ──
#   1. HARNESS_SELF_BUILD=1        → build the jar inside the image (portable, any arch)
#   2. PEER_JAR points at a file   → use it as-is (CI ships ONE arch-independent jar this way)
#   3. otherwise                   → build the jar on the host (arch-independent, so no per-arch step)
if [ "${HARNESS_SELF_BUILD:-0}" = "1" ]; then
    export PEER_JVM_DOCKERFILE="Dockerfile"
    echo "[run] jvm peer image: self-building inside the image"
elif [ -n "${PEER_JAR:-}" ] && [ -f "../${PEER_JAR}" ]; then
    export PEER_JVM_DOCKERFILE="Dockerfile.prebuilt"
    echo "[run] jvm peer image: prebuilt (supplied) ${PEER_JAR}"
else
    echo "[run] building jvm peer jar on host…"
    ( cd .. && ./gradlew --no-daemon --no-configuration-cache ":webrtc-harness-endpoint:peerJar" )
    export PEER_JVM_DOCKERFILE="Dockerfile.prebuilt"
    export PEER_JAR="webrtc-harness-endpoint/build/libs/webrtc-harness-peer-all.jar"
    echo "[run] jvm peer image: prebuilt $PEER_JAR"
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

# Per-scenario stack reset — brings the compose stack down (fresh NAT rules + conntrack per profile).
# It MUST NOT touch the host bridge-nf sysctl: that is set ONCE for the whole run and restored ONCE at the
# very end. (An earlier version restored bridge-nf here, in the per-scenario reset — which re-enabled bridge
# netfilter before every scenario after the first, breaking NAT forwarding for the rest of the matrix.)
stack_down() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }

# Final teardown (EXIT only): stack down + restore the one host sysctl we changed, so the harness leaves
# no global footprint.
teardown() {
    stack_down
    if [ -n "$BRIDGE_NF_ORIG" ]; then
        docker run --rm --privileged --network host alpine:3.20 \
            sysctl -w "net.bridge.bridge-nf-call-iptables=$BRIDGE_NF_ORIG" >/dev/null 2>&1 || true
    fi
}
trap teardown EXIT

docker run --rm --privileged --network host alpine:3.20 \
    sysctl -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1 \
    || echo "::warning::could not set bridge-nf-call-iptables=0 — container routing across NATs may fail"

# ── scenario matrix — name | nat_a | nat_b | ice_policy | netem(args or "-") | a_impl | b_impl ──
#   a_impl (offerer / "our side") ∈ native | jvm
#   b_impl (answerer)             ∈ native | pion | chrome | firefox
# Covers each of the four NAT profiles, the symmetric→relay fallback, an explicit relay-only lane, an
# impaired data path (all native ⇄ native), the W7 Phase-2 interop lanes where the answerer is a real Pion
# (Go) peer [2(a)] or a real headless browser — Chrome / Firefox [2(b)], PLUS the JVM-offerer lanes: the
# pure-Kotlin engine on the JVM (socket-udp NIO datapath) ⇄ native / Pion / Chrome / Firefox — proving the
# pure engine on the real wire from a managed runtime. Each expects BOTH peers to exit 0. Both impl columns
# default to native when omitted. The pion lanes force DTLS 1.2 (Pion v3 is 1.2-only); every other lane runs
# DTLS 1.3 (the default) — see run_scenario.
SCENARIOS="
full-cone            | full-cone          | full-cone          | all   | -                                                | native | native
port-restricted      | port-restricted    | port-restricted    | all   | -                                                | native | native
address-restricted   | address-restricted | address-restricted | all   | -                                                | native | native
symmetric-relay      | symmetric          | symmetric          | all   | -                                                | native | native
mixed-sym-port       | symmetric          | port-restricted    | all   | -                                                | native | native
relay-only           | port-restricted    | port-restricted    | relay | -                                                | native | native
impaired-loss-delay  | port-restricted    | port-restricted    | all   | loss 5% delay 20ms 5ms distribution normal      | native | native
pion-interop         | port-restricted    | port-restricted    | all   | -                                                | native | pion
chrome-interop       | port-restricted    | port-restricted    | all   | -                                                | native | chrome
firefox-interop      | port-restricted    | port-restricted    | all   | -                                                | native | firefox
jvm-native           | port-restricted    | port-restricted    | all   | -                                                | jvm    | native
jvm-pion             | port-restricted    | port-restricted    | all   | -                                                | jvm    | pion
jvm-chrome           | port-restricted    | port-restricted    | all   | -                                                | jvm    | chrome
jvm-firefox          | port-restricted    | port-restricted    | all   | -                                                | jvm    | firefox
"

# Scenario selection:
#   * positional args = an ALLOWLIST of scenario names to run (e.g. `run-interop.sh chrome-interop`, or a
#     space-separated set). No args → the whole matrix.
#   * $HARNESS_SKIP = a space-separated SKIPLIST of scenario names (e.g. the CI native lane runs the full
#     matrix minus the browser lanes, which run as their own parallel per-browser jobs).
# Padded with spaces so a `case` glob matches a whole word, never a substring.
only=" $* "
skip=" ${HARNESS_SKIP:-} "
pass=0; fail=0; failed_names=""

run_scenario() {
    local name="$1" nat_a="$2" nat_b="$3" policy="$4" netem="$5" a_impl="${6:-native}" b_impl="${7:-native}"
    echo ""
    echo "═══ scenario: $name  (nat_a=$nat_a nat_b=$nat_b policy=$policy netem=${netem} a=${a_impl} b=${b_impl}) ═══"

    export NAT_A_PROFILE="$nat_a" NAT_B_PROFILE="$nat_b" ICE_POLICY="$policy" SESSION="$name"

    # Choose the offerer ("our side", a_service) and the answerer (b_service), and activate exactly the
    # compose profiles for the non-default services this scenario needs. The Pion lane pins DTLS 1.2 on BOTH
    # peers (PEER_DTLS13=false) — Pion v3 is 1.2-only, and our offerer (native OR jvm, both read
    # ${PEER_DTLS13}) would otherwise negotiate up to 1.3; every other lane runs the 1.3 default.
    local a_service b_service profiles=""
    case "$a_impl" in
        jvm) a_service="peer_a_jvm"; profiles="$profiles jvm" ;;
        *)   a_service="peer_a" ;;
    esac
    case "$b_impl" in
        pion)    b_service="pion";    profiles="$profiles pion";    export PEER_DTLS13="false" ;;
        chrome)  b_service="chrome";  profiles="$profiles chrome";  export PEER_DTLS13="true" ;;
        firefox) b_service="firefox"; profiles="$profiles firefox"; export PEER_DTLS13="true" ;;
        *)       b_service="peer_b";                                export PEER_DTLS13="true" ;;
    esac
    profiles=$(echo "$profiles" | xargs | tr ' ' ',')  # trim + COMMA-separate (COMPOSE_PROFILES format)
    if [ -n "$profiles" ]; then export COMPOSE_PROFILES="$profiles"; else unset COMPOSE_PROFILES; fi

    # Fresh stack per scenario for isolation (NAT rules + conntrack state must not bleed across profiles).
    # stack_down ONLY — the host bridge-nf sysctl stays as set for the whole run (restored once on EXIT).
    stack_down
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

    # BUILD the peer images first, then start BOTH peers together in ONE `up` (offerer + answerer must come
    # up together — starting them in two separate `up` commands perturbs the offerer's offer-publish and it
    # never PUTs the offer). The offerer image (native peer_a or peer_a_jvm) must reflect the freshly-built
    # binary/jar → always build it (see compose-up-retry.sh for the stale-image rationale). The browser
    # images take minutes to build (engine download), so CI prebuilds them ONCE with a persistent buildx/gha
    # layer cache and sets HARNESS_NO_BROWSER_BUILD=1 to reuse that cache-warmed image; locally we build it.
    docker compose build "$a_service"
    if [ "${HARNESS_NO_BROWSER_BUILD:-0}" = "1" ] && { [ "$b_service" = "chrome" ] || [ "$b_service" = "firefox" ]; }; then
        : # browser image was prebuilt + gha-cached by CI — don't rebuild
    else
        docker compose build "$b_service"
    fi
    # Now start both together with the already-built images (no build here → same ordering as before).
    # They run to completion (establish + echo, or watchdog timeout) and exit.
    docker compose up -d --no-build "$a_service" "$b_service"
    # `docker compose wait` blocks until stop; its output form varies ("0" vs "container … status code 0"),
    # so extract the trailing exit code robustly.
    local rc_a rc_b
    rc_a=$(docker compose wait "$a_service" 2>/dev/null | grep -oE '[0-9]+$' | tail -1)
    rc_b=$(docker compose wait "$b_service" 2>/dev/null | grep -oE '[0-9]+$' | tail -1)

    echo "── $a_service (offerer) ──"; docker compose logs --no-log-prefix "$a_service"
    echo "── $b_service (answerer) ──"; docker compose logs --no-log-prefix "$b_service"

    if [ "$rc_a" = "0" ] && [ "$rc_b" = "0" ]; then
        echo "✅ [$name] PASS (offerer rc=$rc_a answerer rc=$rc_b)"; pass=$((pass+1))
    else
        echo "::error::❌ [$name] FAIL (offerer rc=$rc_a answerer rc=$rc_b)"
        fail=$((fail+1)); failed_names="$failed_names $name"
    fi
}

# Here-string (not a pipe) so the loop runs in THIS shell and the tallies persist. Read the scenario list
# on a DEDICATED fd (3), NOT stdin: `docker compose exec` (used by the netem `impaired` lane) attaches and
# drains its stdin, which — if the loop read from stdin — would swallow every remaining scenario line, so
# the matrix would silently stop after the first netem lane (it ran 7/9, skipping pion-interop +
# chrome-interop). Reading from fd 3 keeps the list out of reach of any inner command's stdin.
while IFS='|' read -r name a b policy netem a_impl b_impl <&3; do
    name=$(echo "$name" | xargs); [ -z "$name" ] && continue
    a=$(echo "$a" | xargs); b=$(echo "$b" | xargs); policy=$(echo "$policy" | xargs); netem=$(echo "$netem" | xargs)
    a_impl=$(echo "$a_impl" | xargs); [ -z "$a_impl" ] && a_impl=native
    b_impl=$(echo "$b_impl" | xargs); [ -z "$b_impl" ] && b_impl=native
    # Allowlist (positional args): if any were given, run only those names.
    if [ -n "$*" ]; then case "$only" in *" $name "*) ;; *) continue ;; esac; fi
    # Skiplist ($HARNESS_SKIP): never run a named-skipped scenario.
    case "$skip" in *" $name "*) echo "── skip $name (HARNESS_SKIP)"; continue ;; esac
    run_scenario "$name" "$a" "$b" "$policy" "$netem" "$a_impl" "$b_impl"
done 3<<< "$SCENARIOS"

echo ""
echo "═══ summary: $pass passed, $fail failed${failed_names:+ (failed:$failed_names)} ═══"
[ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]
exit $?
