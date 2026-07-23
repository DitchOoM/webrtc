#!/usr/bin/env bash
# L2 interop orchestrator — drives the container harness through the full scenario matrix and asserts a
# two-peer establish + data-channel echo in each. This is the Phase-1 exit gate: two peers establish over
# EACH NAT profile against real kernels (plus a relay-only and an impaired lane).
#
# For every scenario it: swaps the NAT profile(s)/policy, (re)starts coturn + rendezvous + both NATs,
# applies any netem, runs both peers to completion, and PASSES iff BOTH peers exit 0 (each exits 0 only
# after it CONNECTED and the ping/pong crossed the encrypted data channel). Fails the whole run if any
# GATING scenario fails. Every run tears the stack down (containers + networks + volumes) via an EXIT trap.
#
# NON-GATING lanes (see $NON_GATING below): the kernel-random netem `impaired-loss-delay` lane exercises the
# degraded data path against real kernels, but its loss is drawn from kernel entropy and can NEVER be proven
# flake-free — so it is INFORMATIONAL only: a failure is logged (::warning::) but does NOT fail the run. The
# HARD gate for loss/impairment behavior is the deterministic, seeded, virtual-time
# `DtlsSctpLossReproductionTest` (webrtc/src/commonTest/kotlin/com/ditchoom/webrtc/DtlsSctpLossReproductionTest.kt),
# which reproduces the DTLS↔SCTP loss stall 100% deterministically and runs in the fast PR lanes.
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

# IP family for this run — v4 (default) | dual | v6. Step 4 wires it to COMPOSE_FILE overlays + a
# family-skip; here it only names the diagnostics bundle dir (diag/<family>/…) so v4/v6/dual captures never
# collide. On the untouched v4 matrix this stays "v4" and the harness is byte-identical to before.
IP_FAMILY="${IP_FAMILY:-v4}"

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

INFRA="coturn coturn_pcap rendezvous nat_a nat_b"

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

# ── scenario matrix — name | nat_a | nat_b | ice_policy | netem(args or "-") | a_impl | b_impl | topo ──
#   a_impl (offerer / "our side") ∈ native | jvm
#   b_impl (answerer)             ∈ native | pion | chrome | firefox | webkit
#   topo (NAT layering)           ∈ single | cgnat | hairpin      (defaults to single when omitted)
# Covers each of the four NAT profiles, the symmetric→relay fallback, an explicit relay-only lane, an
# impaired data path (all native ⇄ native), the W7 Phase-2 interop lanes where the answerer is a real Pion
# (Go) peer [2(a)] or a real headless browser — Chrome / Firefox / WebKit [2(b)], the JVM-offerer lanes:
# the pure-Kotlin engine on the JVM (socket-udp NIO datapath) ⇄ native / Pion / Chrome / Firefox / WebKit
# — proving the pure engine on the real wire from a managed runtime — PLUS two carrier-grade NAT (NAT444)
# topologies: `cgnat` (each CPE behind its OWN carrier NAT — a genuine double NAT, traversed via srflx or
# relay) and `hairpin` (both CPEs behind ONE shared carrier NAT — a single external identity, so ICE falls
# back to the coturn relay). `hairpin` PINS ice_policy=relay (like `relay-only`) so a green rc PROVES the
# relay was traversed — under `all` a stray direct/srflx path (an accidentally-hairpinning NAT) would
# establish and pass silently, deleting the lane's reason to exist; run_scenario also asserts the selected
# pair is a relay pair from the offerer's Connected trace. `impaired-loss-delay` is NON-GATING (informational
# — see $NON_GATING + the header): its kernel-random loss can't be provably flake-free, so the deterministic
# DtlsSctpLossReproductionTest is the retained hard loss gate. Each expects BOTH peers to exit 0. The impl +
# topo columns default to native/native/single when omitted. The pion lanes force DTLS 1.2 (Pion v3 is
# 1.2-only); every other lane runs DTLS 1.3 (the default) — see run_scenario.
SCENARIOS="
full-cone            | full-cone          | full-cone          | all   | -                                                | native | native  | single
port-restricted      | port-restricted    | port-restricted    | all   | -                                                | native | native  | single
address-restricted   | address-restricted | address-restricted | all   | -                                                | native | native  | single
symmetric-relay      | symmetric          | symmetric          | all   | -                                                | native | native  | single
mixed-sym-port       | symmetric          | port-restricted    | all   | -                                                | native | native  | single
relay-only           | port-restricted    | port-restricted    | relay | -                                                | native | native  | single
impaired-loss-delay  | port-restricted    | port-restricted    | all   | loss 5% delay 20ms 5ms distribution normal      | native | native  | single
cgnat                | port-restricted    | port-restricted    | all   | -                                                | native | native  | cgnat
hairpin              | port-restricted    | port-restricted    | relay | -                                                | native | native  | hairpin
pion-interop         | port-restricted    | port-restricted    | all   | -                                                | native | pion    | single
chrome-interop       | port-restricted    | port-restricted    | all   | -                                                | native | chrome  | single
firefox-interop      | port-restricted    | port-restricted    | all   | -                                                | native | firefox | single
webkit-interop       | port-restricted    | port-restricted    | all   | -                                                | native | webkit  | single
jvm-native           | port-restricted    | port-restricted    | all   | -                                                | jvm    | native  | single
jvm-pion             | port-restricted    | port-restricted    | all   | -                                                | jvm    | pion    | single
jvm-chrome           | port-restricted    | port-restricted    | all   | -                                                | jvm    | chrome  | single
jvm-firefox          | port-restricted    | port-restricted    | all   | -                                                | jvm    | firefox | single
jvm-webkit           | port-restricted    | port-restricted    | all   | -                                                | jvm    | webkit  | single
"

# Scenario selection:
#   * positional args = an ALLOWLIST of scenario names to run (e.g. `run-interop.sh chrome-interop`, or a
#     space-separated set). No args → the whole matrix.
#   * $HARNESS_SKIP = a space-separated SKIPLIST of scenario names (e.g. the CI native lane runs the full
#     matrix minus the browser lanes, which run as their own parallel per-browser jobs).
# Padded with spaces so a `case` glob matches a whole word, never a substring.
only=" $* "
skip=" ${HARNESS_SKIP:-} "

# NON-GATING (informational) scenarios — a failure here is logged but does NOT fail the run. The kernel-random
# netem impaired lane can never be provably flake-free; the deterministic DtlsSctpLossReproductionTest is the
# HARD loss gate (see the header). Keep this list minimal and space-padded so `case` matches whole words.
NON_GATING=" impaired-loss-delay "

pass=0; fail=0; failed_names=""
warn=0; warned_names=""

# Record a scenario failure. GATING scenarios increment $fail (fail the run); NON_GATING scenarios are logged
# as an informational ::warning:: and increment $warn only — the run can still pass. $2 is the reason string.
record_fail() {
    local name="$1" reason="$2"
    case "$NON_GATING" in
        *" $name "*)
            echo "::warning::⚠️ [$name] $reason — NON-GATING (informational); the deterministic DtlsSctpLossReproductionTest is the hard loss gate, so NOT failing the run"
            warn=$((warn + 1)); warned_names="$warned_names $name" ;;
        *)
            echo "::error::❌ [$name] $reason"
            fail=$((fail + 1)); failed_names="$failed_names $name" ;;
    esac
}

# ── capture-on-failure diagnostics (design §B) ──────────────────────────────────────────────────────
# The carrier NATs active in THIS scenario (cgnat_*), derived from run_scenario's $infra (visible here by
# bash dynamic scope). Empty in the single-NAT lanes.
compose_active_carriers() { echo "${infra:-}" | tr ' ' '\n' | grep -E '^cgnat' || true; }

# Background a ring-buffered tcpdump on every NAT for the whole scenario — the pcap is the gold-standard
# replay input (the real-wire packet + loss schedule that the seed alone can't reconstruct). Ring-bounded
# (-C 20 -W 3 → ≤60 MB/container) + copied out ONLY on failure (collect_diagnostics) + destroyed with the
# stack on pass, so a green lane pays only an idle capture. coturn is captured by the coturn_pcap sidecar
# (its image has no tcpdump); a NAT's `any` capture already sees every peer↔coturn relay packet too.
start_captures() {
    for nat in nat_a nat_b $(compose_active_carriers); do
        docker compose exec -d "$nat" sh -c 'mkdir -p /pcap && exec tcpdump -i any -w /pcap/cap.pcap -C 20 -W 3 -U' 2>/dev/null || true
    done
}

# Write the forensic bundle to test-harness/diag/<family>/<name>/ WHILE the containers are still up: every
# container's log, both-family firewall+conntrack state, the ring-buffered pcaps, the rendezvous mailbox
# (the exact offer/answer/candidate set exchanged), and a resolved-env/MANIFEST snapshot. This is the bridge
# from a real-UDP CI flake to a seeded virtual-time vnet fixture (standing directive #5). Called at every
# failure site inside run_scenario (via fail_scenario). Best-effort throughout: a missing/partly-up
# container degrades one file, never aborts the bundle. Reads run_scenario locals via dynamic scope.
collect_diagnostics() {
    local name="$1"
    local dir="diag/${IP_FAMILY}/${name}"
    local carriers; carriers=$(compose_active_carriers)
    mkdir -p "$dir/pcap"
    echo "[diag] collecting failure bundle → test-harness/$dir"

    # Per-container logs — ALL infra + both peers, not just the tee'd peer stdout — one file each.
    for svc in coturn rendezvous nat_a nat_b ${a_service:-peer_a} ${b_service:-peer_b} $carriers; do
        docker compose logs --no-log-prefix "$svc" > "$dir/$svc.log" 2>/dev/null || true
    done

    # Firewall + conntrack, BOTH families, per NAT — the exact filter/mapping state at the moment of failure.
    for nat in nat_a nat_b $carriers; do
        {
            echo "=== $nat: iptables -S ===";          docker compose exec -T "$nat" iptables -S
            echo "=== $nat: iptables -t nat -S ===";    docker compose exec -T "$nat" iptables -t nat -S
            echo "=== $nat: ip6tables -S ===";          docker compose exec -T "$nat" ip6tables -S
            echo "=== $nat: conntrack -L (v4) ===";     docker compose exec -T "$nat" conntrack -L
            echo "=== $nat: conntrack -L (v6) ===";     docker compose exec -T "$nat" conntrack -L -f ipv6
            echo "=== $nat: ip -o addr ===";            docker compose exec -T "$nat" ip -o addr
            echo "=== $nat: ip -6 route ===";           docker compose exec -T "$nat" ip -6 route
        } > "$dir/$nat.state.txt" 2>&1 || true
    done

    # pcaps — copy each capturing container's ring-buffer dir into its OWN subdir (the rotated files share a
    # basename across containers, so a flat copy would collide).
    for nat in nat_a nat_b $carriers; do
        mkdir -p "$dir/pcap/$nat"; docker compose cp "$nat:/pcap/." "$dir/pcap/$nat/" 2>/dev/null || true
    done
    mkdir -p "$dir/pcap/coturn"; docker compose cp "coturn_pcap:/cap/." "$dir/pcap/coturn/" 2>/dev/null || true

    # Rendezvous mailbox — the exact offer/answer/candidate set both sides exchanged (all slots), read off
    # the HTTP /dump face of the SAME in-memory mailbox. No curl needed: python3 is in the rendezvous image.
    docker compose exec -T rendezvous python3 -c \
        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:${RENDEZVOUS_HTTP_PORT}/dump').read().decode())" \
        > "$dir/rendezvous-mailbox.json" 2>/dev/null || true

    # Resolved topology — the fully-substituted compose model + the harness-relevant env, pinning the ACTIVE
    # family / addresses / overlays / profiles that produced this failure.
    docker compose config > "$dir/compose.resolved.yml" 2>/dev/null || true
    env | grep -E '^(IP_FAMILY|COMPOSE_|NAT_|PEER_|SEED_|SESSION|ICE_POLICY|WEBRTC_|.*_IP6?)=' | sort > "$dir/env.txt" 2>/dev/null || true

    # MANIFEST — the human index + the replay coordinates (family, seeds, the offerer's selected pair).
    {
        echo "scenario=$name"
        echo "family=${IP_FAMILY}"
        echo "profiles=${COMPOSE_PROFILES:-<none>}"
        echo "policy=${policy:-?}  topo=${topo:-?}  netem=${netem:-?}"
        echo "offerer=${a_service:-peer_a}  rc_a=${rc_a:-n/a}"
        echo "answerer=${b_service:-peer_b}  rc_b=${rc_b:-n/a}"
        echo "SEED_A=${SEED_A:-<peer default>}  SEED_B=${SEED_B:-<peer default>}"
        echo "--- offerer selected ICE pair ---"
        docker compose logs --no-log-prefix "${a_service:-peer_a}" 2>/dev/null | grep -F 'selectedPair=' || echo "(none logged)"
    } > "$dir/MANIFEST.txt" 2>&1
}

# Collect the forensic bundle FIRST (while containers are up), then record the failure. Every failure site
# inside run_scenario goes through here so a red lane always leaves a replayable bundle behind.
fail_scenario() { collect_diagnostics "$1"; record_fail "$1" "$2"; }

run_scenario() {
    local name="$1" nat_a="$2" nat_b="$3" policy="$4" netem="$5" a_impl="${6:-native}" b_impl="${7:-native}" topo="${8:-single}"
    echo ""
    echo "═══ scenario: $name  (nat_a=$nat_a nat_b=$nat_b policy=$policy netem=${netem} a=${a_impl} b=${b_impl} topo=${topo}) ═══"

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
        webkit)  b_service="webkit";  profiles="$profiles webkit";  export PEER_DTLS13="true" ;;
        *)       b_service="peer_b";                                export PEER_DTLS13="true" ;;
    esac

    # NAT layering (carrier-grade / hairpin). Point each CPE's upstream at the right carrier NAT, activate
    # that carrier NAT's compose profile, and add it to this scenario's infra so `up` starts it (a profiled
    # service only starts when named or its profile is active). `single` leaves the CPEs on pub directly —
    # the carrier gateways MUST be unset so nat-setup skips its behind-carrier block (they may be exported
    # from a previous cgnat/hairpin scenario in the loop).
    local infra="$INFRA"
    case "$topo" in
        cgnat)   # per-side carrier NATs → a genuine double NAT (distinct public IPs)
            export NAT_A_CARRIER_GW="$CGNAT_A_CAR_IP" NAT_B_CARRIER_GW="$CGNAT_B_CAR_IP"
            profiles="$profiles cgnat"; infra="$infra cgnat_a cgnat_b" ;;
        hairpin) # ONE shared carrier NAT → both peers share a single external identity → relay
            export NAT_A_CARRIER_GW="$CGNAT_SHARED_CAR_IP" NAT_B_CARRIER_GW="$CGNAT_SHARED_CAR_IP"
            profiles="$profiles hairpin"; infra="$infra cgnat" ;;
        *)       unset NAT_A_CARRIER_GW NAT_B_CARRIER_GW ;;
    esac

    profiles=$(echo "$profiles" | xargs | tr ' ' ',')  # trim + COMMA-separate (COMPOSE_PROFILES format)
    if [ -n "$profiles" ]; then export COMPOSE_PROFILES="$profiles"; else unset COMPOSE_PROFILES; fi

    # Fresh stack per scenario for isolation (NAT rules + conntrack state must not bleed across profiles).
    # stack_down ONLY — the host bridge-nf sysctl stays as set for the whole run (restored once on EXIT).
    stack_down
    if ! ./compose-up-retry.sh $infra; then
        fail_scenario "$name" "infra failed to come up"; return
    fi

    if [ "$netem" != "-" ]; then
        # Fail-HARD if netem can't be applied — otherwise the impaired lane silently runs UNIMPAIRED and
        # passes, giving false confidence in the one scenario whose whole point is the degraded data path.
        if ! docker compose exec -T nat_a /netem.sh add $netem || ! docker compose exec -T nat_b /netem.sh add $netem; then
            fail_scenario "$name" "netem failed to apply — impaired lane would run unimpaired"; return
        fi
    fi

    # Start the ring-buffered per-NAT packet capture now — infra + any netem are in place, and the peers are
    # about to run, so the capture spans the whole ICE→DTLS→SCTP handshake. Failure-only copy-out below.
    start_captures

    # BUILD the peer images first, then start BOTH peers together in ONE `up` (offerer + answerer must come
    # up together — starting them in two separate `up` commands perturbs the offerer's offer-publish and it
    # never PUTs the offer). The offerer image (native peer_a or peer_a_jvm) must reflect the freshly-built
    # binary/jar → always build it (see compose-up-retry.sh for the stale-image rationale). The browser
    # images take minutes to build (engine download), so CI prebuilds them ONCE with a persistent buildx/gha
    # layer cache and sets HARNESS_NO_BROWSER_BUILD=1 to reuse that cache-warmed image; locally we build it.
    docker compose build "$a_service"
    if [ "${HARNESS_NO_BROWSER_BUILD:-0}" = "1" ] && { [ "$b_service" = "chrome" ] || [ "$b_service" = "firefox" ] || [ "$b_service" = "webkit" ]; }; then
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
        # Belt-and-suspenders for the hairpin lane: a green rc only proves the peers ESTABLISHED — it does
        # NOT by itself prove the path was the coturn RELAY. ice_policy=relay (pinned above) already forces
        # relay-only gathering, but assert it independently from the offerer's Connected-state trace
        # (`selectedPair=CandidatePair(local=Relayed(…))`) so a future policy loosening — or an accidentally
        # hairpinning NAT selecting a direct/srflx pair — fails here instead of passing silently.
        if [ "$topo" = "hairpin" ] && ! docker compose logs --no-log-prefix "$a_service" 2>/dev/null \
                | grep -q 'selectedPair=CandidatePair(local=Relayed'; then
            fail_scenario "$name" "established but the selected ICE pair is NOT a relay pair (the hairpin lane must traverse the coturn TURN relay)"; return
        fi
        echo "✅ [$name] PASS (offerer rc=$rc_a answerer rc=$rc_b)"; pass=$((pass+1))
    else
        fail_scenario "$name" "FAIL (offerer rc=$rc_a answerer rc=$rc_b)"
    fi
}

# Here-string (not a pipe) so the loop runs in THIS shell and the tallies persist. Read the scenario list
# on a DEDICATED fd (3), NOT stdin: `docker compose exec` (used by the netem `impaired` lane) attaches and
# drains its stdin, which — if the loop read from stdin — would swallow every remaining scenario line, so
# the matrix would silently stop after the first netem lane (it ran 7/9, skipping pion-interop +
# chrome-interop). Reading from fd 3 keeps the list out of reach of any inner command's stdin.
while IFS='|' read -r name a b policy netem a_impl b_impl topo <&3; do
    name=$(echo "$name" | xargs); [ -z "$name" ] && continue
    a=$(echo "$a" | xargs); b=$(echo "$b" | xargs); policy=$(echo "$policy" | xargs); netem=$(echo "$netem" | xargs)
    a_impl=$(echo "$a_impl" | xargs); [ -z "$a_impl" ] && a_impl=native
    b_impl=$(echo "$b_impl" | xargs); [ -z "$b_impl" ] && b_impl=native
    topo=$(echo "$topo" | xargs); [ -z "$topo" ] && topo=single
    # Allowlist (positional args): if any were given, run only those names.
    if [ -n "$*" ]; then case "$only" in *" $name "*) ;; *) continue ;; esac; fi
    # Skiplist ($HARNESS_SKIP): never run a named-skipped scenario.
    case "$skip" in *" $name "*) echo "── skip $name (HARNESS_SKIP)"; continue ;; esac
    run_scenario "$name" "$a" "$b" "$policy" "$netem" "$a_impl" "$b_impl" "$topo"
done 3<<< "$SCENARIOS"

echo ""
echo "═══ summary: $pass passed, $fail failed${failed_names:+ (failed:$failed_names)}${warned_names:+, $warn non-gating failure(s):$warned_names (informational — deterministic DtlsSctpLossReproductionTest is the hard gate)} ═══"
# Exit non-zero iff a GATING scenario failed (or nothing ran+passed). NON-GATING failures ($warn) never fail
# the run — the deterministic DtlsSctpLossReproductionTest is the retained hard gate for loss behavior.
[ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]
exit $?
