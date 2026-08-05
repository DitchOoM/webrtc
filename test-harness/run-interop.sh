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
# Data-channel SEMANTICS (docs/DC_SEMANTICS_INTEROP_DESIGN.md): every lane additionally runs the
# offerer-driven phase sequence over the SAME association it establishes — s1 large/fragmented (byte-identity
# + the negotiated a=max-message-size boundary), s2 unordered, s3 partial-reliable (PR-SCTP + FORWARD-TSN
# no-wedge), s4 multiplexed, s5 reverse-direction (our lanes only), s7 per-channel close (RFC 8831 §6.7
# stream reset: neighbour survives, the peer's channel closed, the recycled stream id works), s9 consent
# freshness (the session held silent past a whole RFC 7675 revocation window — see the compressed consent
# block below), s8 ICE restart
# across a mid-session carrier switch (our lanes only — see the carrier-switch topology below), s6 DONE +
# graceful association SHUTDOWN — s6 ends the association, so it is always last and s8 sorts before it.
# The answerer is a scenario-agnostic reflector in every family, so this costs no new CI lanes. They landed
# NON-GATING-first and are now FULLY PROMOTED: a failed phase FAILS its lane, on EVERY lane. The holdout
# list ($SEMANTICS_NON_GATING, see below) is empty — the last two entries, the werift lanes, were promoted
# once the SCTP INIT deadlock that kept them at `Connecting` was fixed (issue #43).
#
# Usage:
#   ./run-interop.sh                 # full matrix, prebuilt-binary fast path (host gradle build)
#   HARNESS_SELF_BUILD=1 ./run-interop.sh   # build the peer inside its image (portable: macOS/Apple, arm64)
#   ./run-interop.sh <scenario-name> # run a single scenario by name
#   HARNESS_SEMANTICS=0 ./run-interop.sh        # establish-and-echo only (the pre-semantics harness)
#   HARNESS_SCENARIOS=s1 ./run-interop.sh       # run only the named semantics phase(s)
#   HARNESS_SEMANTICS_GATING=0 ./run-interop.sh # de-gate semantics everywhere (debugging; default is 1)
#   HARNESS_SEMANTICS_NON_GATING="x y" ./run-interop.sh  # override the named informational-lane holdouts
#   HARNESS_IDLE_MS=0 ./run-interop.sh          # skip the s9 consent-idle hold (saves ~10s per lane)
set -uo pipefail
cd "$(dirname "$0")"

# ── config from the single source of truth (also exported for compose ${VAR} substitution) ──
set -a
# shellcheck disable=SC1091
. ./harness.env
set +a

# IP family for this run — v4 (default) | dual | v6. Selects the compose overlays (below) + a family-skip
# (family_skipped) + the diagnostics bundle dir (diag/<family>/…) so v4/v6/dual captures never collide. On
# the untouched v4 matrix this stays "v4" and the harness is byte-identical to before.
IP_FAMILY="${IP_FAMILY:-v4}"

# Compose overlays for the family — EXPORTED so every `docker compose` call (compose-up-retry.sh, stack_down,
# exec, logs, cp) inherits it for free, no call-site edits. v4 = the untouched base; dual = base + the
# dual-stack overlay; v6 = base + dual-stack + the v4-disabling overlay. Colon-separated, resolved from this
# dir (both this script and compose-up-retry.sh cd here).
case "$IP_FAMILY" in
    v4)   COMPOSE_FILE="docker-compose.yml" ;;
    dual) COMPOSE_FILE="docker-compose.yml:compose.ipv6.yml" ;;
    v6)   COMPOSE_FILE="docker-compose.yml:compose.ipv6.yml:compose.v6only.yml" ;;
    *)    echo "::error::unknown IP_FAMILY='$IP_FAMILY' (want: v4|dual|v6)"; exit 2 ;;
esac
export COMPOSE_FILE
echo "[run] IP_FAMILY=$IP_FAMILY  COMPOSE_FILE=$COMPOSE_FILE"

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
# Routed-v6 (dual + v6) has no NAT66, so the pub-side services need explicit return routes to the peer ULA
# LAN subnets — two netns-sharing sidecars install them (see compose.ipv6.yml). Absent on the v4-only stack.
[ "$IP_FAMILY" != "v4" ] && INFRA="$INFRA coturn_route6 rendezvous_route6"

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

# Block until a peer service's container has exited and echo its exit code.
#
# NOT `docker compose wait`: that subcommand resolves the service against RUNNING containers only, so if the
# container has ALREADY exited by the time the call is issued it prints nothing, writes `no containers for
# project "<p>"` to stderr and exits 1 — yielding an EMPTY rc that reads as failure. Because the two peer
# waits are necessarily sequential (offerer first, then answerer), any scenario where the ANSWERER exits
# before/with the offerer lost its rc that way and failed a lane both peers had actually completed cleanly
# (`[harness] exit=0`, `close-summary: observed=Closed clean=true` in the very log we dump). This stayed
# latent while the answerer reliably outlived the offerer; the s6 graceful-shutdown phase made the two exits
# simultaneous, turning it into a nondeterministic red across full-cone / address-restricted.
#
# `docker wait <container-id>` has no such asymmetry: it blocks when the container is running and returns the
# recorded exit code IMMEDIATELY when it has already exited — the exited container still exists (nothing
# removes it until stack_down). `ps -a` is load-bearing: without it, ps only lists running containers and we
# would reacquire the same race one level down.
peer_exit_rc() {
    local cid
    cid=$(docker compose ps -a -q "$1" 2>/dev/null | tail -1)
    [ -n "$cid" ] || return 0   # no container at all → empty rc → caller fails the scenario, as it should
    docker wait "$cid" 2>/dev/null | grep -oE '[0-9]+$' | tail -1
}

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
#   b_impl (answerer)             ∈ native | pion | node | chrome | firefox | webkit
#   topo (NAT layering)           ∈ single | cgnat | hairpin | carrier-switch | foreign-restart |
#                                   interface-swap                                    (def: single)
# Covers each of the four NAT profiles, the symmetric→relay fallback, an explicit relay-only lane, an
# impaired data path (all native ⇄ native), the W7 Phase-2 interop lanes where the answerer is a real Pion
# (Go) peer or a real werift (pure-TypeScript, JS-engine) peer [2(a)] or a real headless browser — Chrome /
# Firefox / WebKit [2(b)], the JVM-offerer lanes:
# the pure-Kotlin engine on the JVM (socket-udp NIO datapath) ⇄ native / Pion / node / Chrome / Firefox / WebKit
# — proving the pure engine on the real wire from a managed runtime — PLUS two carrier-grade NAT (NAT444)
# topologies: `cgnat` (each CPE behind its OWN carrier NAT — a genuine double NAT, traversed via srflx or
# relay) and `hairpin` (both CPEs behind ONE shared carrier NAT — a single external identity, so ICE falls
# back to the coturn relay). `hairpin` PINS ice_policy=relay (like `relay-only`) so a green rc PROVES the
# relay was traversed — under `all` a stray direct/srflx path (an accidentally-hairpinning NAT) would
# establish and pass silently, deleting the lane's reason to exist; run_scenario also asserts the selected
# pair is a relay pair from the offerer's Connected trace. `firewall-relay6` is the v6-native analog: NOT
# policy-forced (ice_policy=all) but NETWORK-forced — the routed-v6 firewall drops WAN→LAN except from
# coturn (nat-setup.sh V6_FORCE_RELAY), so ICE must DISCOVER it has to fall back to the relay when direct/
# srflx v6 is blocked; it reuses the same selected-pair=Relayed assertion. It runs on v6/dual only (there is
# no v6 firewall on a v4 lane), while symmetric/mixed-sym/cgnat/hairpin run on v4 only (mapping artifacts —
# see family_skipped). `carrier-switch` is a THIRD topology dimension rather than a NAT layering: peer_a
# gets a SECOND NAT gateway (nat_a2) on its own LAN, and the harness flips its default route onto it
# mid-session (carrier_switch, below), so its public identity changes underneath a live session and ICE has
# to restart (RFC 8445 §9). Every `restart-*` lane plus `jvm-restart` runs it, and they are the only lanes
# with WEBRTC_ICE_RESTART on. It used to be OURS only — the reflectors answered round 0 and then never
# looked at the mailbox again — but each family now RE-ANSWERS a later round (issue #71), so the same
# property is asserted against Pion and all three browser engines. That is the point of the foreign restart
# lanes: the offerer's assertions are ours either way, but only a third-party answer can say whether a
# production stack replaces both ICE credentials and keeps its DTLS fingerprint (RFC 8842 §5.5) when
# somebody else's network moves.
#
# There is deliberately NO `restart-node`: werift re-answers correctly and then never restarts its
# connectivity checks on the answerer path, so its session does not survive a peer-initiated restart at all
# — see the harness README's carrier-switch section for the measurement. A lane for it could not finish
# (every lane's exit contract needs the s6 DONE handshake, and that needs a live association), so the
# finding is recorded rather than encoded as a lane that asserts almost nothing. The werift reflector still
# re-answers, like every other family, so the lane is a one-line addition if werift fixes it upstream.
#
# `foreign-restart` is the SAME carrier switch with the renegotiation running the other way (issue #87): the
# offerer writes a RESTART lifecycle word into the mailbox, the ANSWERER restarts ICE and re-offers, and our
# side has to DETECT that from the offer alone (RFC 8445 §9 — ufrag AND pwd both changed) and answer it. It
# is the direction s8 could never test, because s8's offers are ours: what a production stack's re-offer
# does differently — attribute ordering, `a=setup` on a re-offer, a restated bundle group — is exactly the
# risk. There is deliberately no `foreign-restart-node` either, and MEASURING that is one of the things this
# work was for: #86 attributed werift's broken restart to an answerer-path asymmetry (`connect()` is reached
# from setRemoteDescription only for an ANSWER, i.e. only when werift is the offerer), which predicted that
# werift could originate one. It cannot. It re-offers correctly and takes a fresh TURN allocation, and then
# sends ZERO connectivity checks on the new generation — exactly as it did as the answerer. The defect is not
# the asymmetry; it is that werift does not check a restarted generation in EITHER direction. Measurement in
# the README's carrier-switch section.
# `impaired-loss-delay` is NON-GATING (informational
# — see $NON_GATING + the header): its kernel-random loss can't be provably flake-free, so the deterministic
# DtlsSctpLossReproductionTest is the retained hard loss gate. Each expects BOTH peers to exit 0. The impl +
# topo columns default to native/native/single when omitted. The pion AND node/werift lanes force DTLS 1.2
# (both are 1.2-only); every other lane runs DTLS 1.3 (the default) — see run_scenario.
SCENARIOS="
full-cone            | full-cone          | full-cone          | all   | -                                                | native | native  | single
port-restricted      | port-restricted    | port-restricted    | all   | -                                                | native | native  | single
address-restricted   | address-restricted | address-restricted | all   | -                                                | native | native  | single
symmetric-relay      | symmetric          | symmetric          | all   | -                                                | native | native  | single
mixed-sym-port       | symmetric          | port-restricted    | all   | -                                                | native | native  | single
relay-only           | port-restricted    | port-restricted    | relay | -                                                | native | native  | single
firewall-relay6      | port-restricted    | port-restricted    | all   | -                                                | native | native  | single
impaired-loss-delay  | port-restricted    | port-restricted    | all   | loss 5% delay 20ms 5ms distribution normal      | native | native  | single
cgnat                | port-restricted    | port-restricted    | all   | -                                                | native | native  | cgnat
hairpin              | port-restricted    | port-restricted    | relay | -                                                | native | native  | hairpin
restart-native       | port-restricted    | port-restricted    | all   | -                                                | native | native  | carrier-switch
jvm-restart          | port-restricted    | port-restricted    | all   | -                                                | jvm    | native  | carrier-switch
restart-pion         | port-restricted    | port-restricted    | all   | -                                                | native | pion    | carrier-switch
restart-chrome       | port-restricted    | port-restricted    | all   | -                                                | native | chrome  | carrier-switch
restart-firefox      | port-restricted    | port-restricted    | all   | -                                                | native | firefox | carrier-switch
restart-webkit       | port-restricted    | port-restricted    | all   | -                                                | native | webkit  | carrier-switch
auto-restart-native  | port-restricted    | port-restricted    | all   | -                                                | native | native  | interface-swap
auto-restart-pion    | port-restricted    | port-restricted    | all   | -                                                | native | pion    | interface-swap
foreign-restart-native  | port-restricted | port-restricted    | all   | -                                                | native | native  | foreign-restart
foreign-restart-pion    | port-restricted | port-restricted    | all   | -                                                | native | pion    | foreign-restart
foreign-restart-chrome  | port-restricted | port-restricted    | all   | -                                                | native | chrome  | foreign-restart
foreign-restart-firefox | port-restricted | port-restricted    | all   | -                                                | native | firefox | foreign-restart
foreign-restart-webkit  | port-restricted | port-restricted    | all   | -                                                | native | webkit  | foreign-restart
pion-interop         | port-restricted    | port-restricted    | all   | -                                                | native | pion    | single
node-interop         | port-restricted    | port-restricted    | all   | -                                                | native | node    | single
chrome-interop       | port-restricted    | port-restricted    | all   | -                                                | native | chrome  | single
firefox-interop      | port-restricted    | port-restricted    | all   | -                                                | native | firefox | single
webkit-interop       | port-restricted    | port-restricted    | all   | -                                                | native | webkit  | single
jvm-native           | port-restricted    | port-restricted    | all   | -                                                | jvm    | native  | single
jvm-pion             | port-restricted    | port-restricted    | all   | -                                                | jvm    | pion    | single
jvm-node             | port-restricted    | port-restricted    | all   | -                                                | jvm    | node    | single
jvm-chrome           | port-restricted    | port-restricted    | all   | -                                                | jvm    | chrome  | single
jvm-firefox          | port-restricted    | port-restricted    | all   | -                                                | jvm    | firefox | single
jvm-webkit           | port-restricted    | port-restricted    | all   | -                                                | jvm    | webkit  | single
mdns-chrome          | -                  | -                  | all   | -                                                | native | chrome  | mdns
mdns-firefox         | -                  | -                  | all   | -                                                | native | firefox | mdns
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
# HARD loss gate (see the header). $HARNESS_NON_GATING appends caller-supplied lanes that are landing
# informational-first (a new interop lane before it's proven green across all families; a one-line follow-up
# flips it to gating once green). CI currently sets it for NOTHING — every lane gates. Space-padded so `case`
# matches whole words; the env list is space-separated names. Two cohorts have been promoted OUT of this list
# to GATING: mdns-chrome/mdns-firefox, once peer_mdns (WEBRTC_REQUIRE_MDNS=true) made rc=0 PROVE mDNS
# resolution rather than just obfuscation-ON interop (issue #48); and node-interop/jvm-node, once the SCTP
# INIT deadlock behind them was fixed (issue #43). They all now assert as hard as every other lane.
NON_GATING=" impaired-loss-delay ${HARNESS_NON_GATING:-} "

# ── data-channel SEMANTICS (docs/DC_SEMANTICS_INTEROP_DESIGN.md, Phase-1 close-out item #2) ──────────
# Every lane's offerer runs the phase sequence (s1 large/fragmented, s2 unordered, s3 partial-reliable,
# s4 multiplexed, s5 reverse, s7 per-channel close, s9 consent-idle, s8 ICE restart on the carrier-switch
# lanes, s6 graceful association close) over the SAME association it already establishes, and
# every answerer becomes a universal reflector that exits on the offerer's DONE. No new lanes: each
# existing lane gains the whole matrix. HARNESS_SEMANTICS=0 restores the pure establish-and-echo harness.
#
# GATING (decision D7): semantics landed NON-GATING-first, exactly like every new lane here — and are now
# PROMOTED. The default is gating; the promotion is PER LANE rather than one global flag, because the
# blocker was never our stack: across all 6 NAT-matrix jobs of run 30127793273 every lane of ours reported
# total=6 passed=6, and the only two holdouts were foreign-peer lanes. $SEMANTICS_NON_GATING carves those
# out; everything else now fails its lane on a failed phase.
#
# HARNESS_SEMANTICS_GATING=0 restores the old informational-everywhere behavior for a debugging run.
export PEER_SEMANTICS="${HARNESS_SEMANTICS:-1}"
export PEER_SCENARIOS="${HARNESS_SCENARIOS:-}"   # e.g. "s1,s3" to debug a single phase
sem_warned_names=""

# ── RFC 7675 consent freshness (s9/idle, issue #80) ─────────────────────────────────────────────────
# Until s9 there was no lane in which a session lived long enough for consent to matter: measured across a
# full local matrix, only `impaired-loss-delay` (20.7 s) and `pion-interop` (8.2 s) put even ONE check on
# the wire, and nothing came near the 30 s revocation window. So "does Chrome / Firefox / WebKit / Pion /
# werift answer the Binding requests we pace at them, and does the NAT mapping survive on nothing else"
# was simply never asked — which is the hole a consent-pacing defect (issue #73) shipped through.
#
# Rather than add 30 s of wall clock to every lane, COMPRESS the window: consent timing is a
# PeerConnectionConfig.iceConfig seam, so an ~8 s window is exercised by a ~10 s hold. It applies to the
# WHOLE run, not just s9 — every lane now also carries its establishment and its other phases under a
# consent clock an order of magnitude tighter than production, which is a free extra assertion.
# RFC 7675 §4.1's "MUST NOT below 4 s" is a deployment bound the core deliberately leaves to the caller
# (see IceConfig.consentInterval); this harness is a scenario, and the library's own default is the RFC's.
export PEER_CONSENT_INTERVAL_MS="${HARNESS_CONSENT_INTERVAL_MS:-2000}"
export PEER_CONSENT_TIMEOUT_MS="${HARNESS_CONSENT_TIMEOUT_MS:-8000}"
# The s9 hold. MUST exceed PEER_CONSENT_TIMEOUT_MS — the phase fails ITSELF if it does not, because a hold
# inside the window would watch nothing at all while still reporting a green phase. 0 turns s9 off.
export PEER_IDLE_MS="${HARNESS_IDLE_MS:-10000}"

# The sequence budget has to carry the s9 hold on top of everything else, or a lane's phases get cut off by
# the outer watchdog and the run reports an ungraded "semantics: TIMEOUT" instead of per-phase verdicts.
# run_scenario re-exports it per lane (the carrier-switch lanes get more, for s8's extra offer/answer
# round); a caller-supplied HARNESS_SEMANTICS_TIMEOUT_MS still wins everywhere.
export PEER_SEMANTICS_TIMEOUT_MS="${HARNESS_SEMANTICS_TIMEOUT_MS:-$((120000 + PEER_IDLE_MS))}"

# Lanes whose SEMANTICS stay informational while everything else gates. Space-padded for whole-word `case`.
# This is deliberately a list of NAMED, UNDERSTOOD holdouts, not a blanket switch — a lane may sit here only
# with a reason. It is now EMPTY: every lane's semantics gate. The last two holdouts have been promoted:
#   node-interop / jvm-node — werift used to never reach Connected on these lanes at all (state=Connecting
#     at 3m30s), so they printed no semantics summary to grade. Root cause (issue #43) was an SCTP INIT
#     deadlock: we chose the SCTP client role off the DTLS role, werift chooses it off the ICE role, so on
#     these pairings NEITHER peer sent the INIT. We now associate from BOTH roles and resolve the resulting
#     INIT collisions per RFC 4960 §5.2. Both lanes now report total=5 passed=5 failed=0 (5, not 6 — s5
#     reverse-direction is our-lanes-only) across all 6 arch × family jobs, the same shape as the Pion lanes.
#   pion-interop — its s2/s3/s4 failures were OUR RFC 8832 §6 violation (unordered user data overtaking the
#     DCEP OPEN, killing pion's accept loop). Fixed; gating it is what keeps it fixed.
SEMANTICS_NON_GATING=" ${HARNESS_SEMANTICS_NON_GATING-} "

# Resolve THIS lane's semantics gate. Exported per scenario (compose reads it at `up` time, and the stack is
# re-upped per scenario) so the peer itself exits non-zero on a failed phase only where we mean it to.
semantics_gate_for() {
    case "$SEMANTICS_NON_GATING" in *" $1 "*) echo 0; return ;; esac
    echo "${HARNESS_SEMANTICS_GATING:-1}"
}

# Grade one lane's semantics result off the offerer's summary line (the peer prints it; we never re-read
# the container log — same anti-truncation discipline as the relay assertion). Under gating the peer has
# already failed itself, so this only reports; ungated it warns. $2 is the offerer's captured log.
semantics_report() {
    local name="$1" log="$2" summary failed
    sem_missing=0
    [ "$PEER_SEMANTICS" = "1" ] || return 0
    summary=$(printf '%s\n' "$log" | grep -F 'semantics-summary:' | tail -1)
    if [ -z "$summary" ]; then
        # Under gating, silence is a failure mode of its own: a lane whose phases silently STOPPED RUNNING
        # would otherwise pass green forever, since the peer only exits non-zero on a phase that ran and
        # failed. Flagged here and consumed on the PASS path (a lane that also failed its rc check is
        # already recorded, so this can never double-count).
        if [ "$(semantics_gate_for "$name")" = "1" ]; then
            sem_missing=1
            return 0
        fi
        echo "::warning::⚠️ [$name] the offerer printed no semantics-summary (phases did not run) — NON-GATING"
        sem_warned_names="$sem_warned_names $name"
        return 0
    fi
    echo "[semantics] [$name] ${summary#*semantics-summary: }"
    failed=$(printf '%s\n' "$summary" | sed -n 's/.*failed=\([0-9][0-9]*\).*/\1/p')
    if [ -n "$failed" ] && [ "$failed" != "0" ]; then
        if [ "$PEER_SEMANTICS_REQUIRED" = "1" ]; then
            # Gating: the peer exited non-zero for exactly this, so the lane has already been recorded a
            # failure by the rc check — this line only names the phases.
            echo "::error::❌ [$name] $failed data-channel semantics phase(s) failed: $(printf '%s\n' "$summary" | sed -n 's/.*failed-phases=\[\(.*\)\].*/\1/p')"
        else
            echo "::warning::⚠️ [$name] $failed data-channel semantics phase(s) failed: $(printf '%s\n' "$summary" | sed -n 's/.*failed-phases=\[\(.*\)\].*/\1/p') — NON-GATING (this lane is a named holdout in \$SEMANTICS_NON_GATING), so NOT failing the run"
            sem_warned_names="$sem_warned_names $name"
        fi
    fi

    # Browser lanes only: assert the DCEP channel TYPES were honored end-to-end, read off the engine's own
    # `dc-negotiated:` lines. This is the half of the proof the offerer cannot see — our side knows what it
    # asked for in DATA_CHANNEL_OPEN, only the peer can report what it actually negotiated. (Pion and werift
    # print the same shape; the W3C property names are what make the browser assertion airtight, so the
    # grep is scoped there.) Informational under the same gate.
    case "$b_impl" in chrome|firefox|webkit) ;; *) return 0 ;; esac
    local b_log_local="$3" missing=""
    # Herestrings, NOT `printf | grep -q`: under `set -o pipefail` a `grep -q` that matches EARLY exits
    # before draining the pipe, printf dies of SIGPIPE (141), and pipefail hands that back as the pipeline's
    # status — so a MATCH reads as a failure. It only bites once the log outgrows the 64 KiB pipe buffer,
    # which the browser lanes (getStats timeline) now do. A herestring has no pipeline and no such trap.
    grep -qE 'dc-negotiated:.*label="s2/unordered".*ordered=false' <<< "$b_log_local" || missing="$missing s2/unordered(ordered=false)"
    grep -qE 'dc-negotiated:.*label="s3/rexmit".*maxRetransmits=0' <<< "$b_log_local" || missing="$missing s3/rexmit(maxRetransmits=0)"
    grep -qE 'dc-negotiated:.*label="s3/timed".*maxPacketLifeTime=[0-9]' <<< "$b_log_local" || missing="$missing s3/timed(maxPacketLifeTime)"
    # s7 (per-channel close), the same "only the peer can report it" half: the engine must say ITS
    # `s7/victim` channel closed mid-session, and must then accept `s7/reopen` on the very stream id the
    # closed channel had. Our offerer proves the id came back to it; only the browser can confirm it
    # honoured a fresh DCEP OPEN on that recycled id rather than treating it as the old, still-known stream.
    grep -qE 'dc close: *"s7/victim"' <<< "$b_log_local" || missing="$missing s7/victim(dc-close)"
    local victim_id reopen_id
    victim_id=$(sed -n 's/.*dc-negotiated:.*label="s7\/victim" id=\([0-9]*\).*/\1/p' <<< "$b_log_local" | head -1)
    reopen_id=$(sed -n 's/.*dc-negotiated:.*label="s7\/reopen" id=\([0-9]*\).*/\1/p' <<< "$b_log_local" | head -1)
    if [ -z "$victim_id" ] || [ "$victim_id" != "$reopen_id" ]; then
        missing="$missing s7/reopen(recycled-id: victim=${victim_id:-<none>} reopen=${reopen_id:-<none>})"
    fi
    if [ -n "$missing" ]; then
        echo "::warning::⚠️ [$name] the browser never reported these negotiated DCEP properties:$missing — NON-GATING"
        sem_warned_names="$sem_warned_names $name"
    else
        echo "[semantics] ✅ [$name] the browser reports our unordered + partial-reliable channel types as negotiated, its own s7/victim close, and s7/reopen on the recycled stream id $victim_id"
    fi
}

# Family-degenerate scenarios (space-padded, whole-word `case` match). The v4 mapping-artifacts (symmetric
# endpoint-dependent mapping, carrier double-NAT, hairpin) have NO v6 analog — over routed v6 the "NAT" is a
# pure filtering router, so they are v4-only. `firewall-relay6` is the inverse: it needs the routed-v6
# firewall to force relay-discovery, so it is v6/dual-only. family_skipped drops each outside its family.
# mdns-* is same-LAN v4-only (compose.mdns.yml defines only a v4 lan0); no v6 addresses, so skip off v4.
# (carrier-switch is v4-only for the same reason as the carrier lanes: nat_a2 is a v4 NAT with a v4 public
# identity, and "the peer's public address changed" is a v4 mapping statement. The v6 analog — a routed
# prefix moving — needs a second v6 router and is a follow-up, not a skip of an existing property.)
V4_ONLY_SCENARIOS=" symmetric-relay mixed-sym-port cgnat hairpin restart-native jvm-restart restart-pion restart-chrome restart-firefox restart-webkit auto-restart-native auto-restart-pion foreign-restart-native foreign-restart-pion foreign-restart-chrome foreign-restart-firefox foreign-restart-webkit mdns-chrome mdns-firefox "
V6_ONLY_SCENARIOS=" firewall-relay6 "
family_skipped() {
    local name=" $1 "
    if [ "$IP_FAMILY" = "v4" ]; then
        case "$V6_ONLY_SCENARIOS" in *"$name"*) return 0 ;; esac
    else
        case "$V4_ONLY_SCENARIOS" in *"$name"*) return 0 ;; esac
    fi
    return 1
}

# v6/dual lanes land NON-GATING first: working assumption is every new v6/dual lane flakes at least once, so
# a failure is captured + diagnosed (the diag bundle) but never reddens the required check — mirroring the
# impaired-lane precedent. v4 stays gating, byte-unchanged. Flip a proven-green family to gating with
# FAMILY_GATING=1 (a one-line follow-up per lane). Returns 0 when THIS run's family is informational.
family_nongating() { [ "$IP_FAMILY" != "v4" ] && [ "${FAMILY_GATING:-0}" != "1" ]; }

pass=0; fail=0; failed_names=""
warn=0; warned_names=""

# Record a scenario failure. GATING scenarios increment $fail (fail the run); NON_GATING scenarios (the
# kernel-random impaired lane, OR any v6/dual lane while FAMILY_GATING is off) are logged as an informational
# ::warning:: and increment $warn only — the run can still pass. $2 is the reason string.
record_fail() {
    local name="$1" reason="$2" why=""
    case "$NON_GATING" in *" $name "*)
        case "$name" in
            impaired-loss-delay) why="the deterministic DtlsSctpLossReproductionTest is the hard loss gate" ;;
            *)                   why="informational-first while the lane lands (a follow-up flips it to gating once green)" ;;
        esac
        ;;
    esac
    if [ -z "$why" ] && family_nongating; then why="$IP_FAMILY lanes land informational-first (set FAMILY_GATING=1 once green)"; fi
    if [ -n "$why" ]; then
        echo "::warning::⚠️ [$name] $reason — NON-GATING ($why), so NOT failing the run"
        warn=$((warn + 1)); warned_names="$warned_names $name"
    else
        echo "::error::❌ [$name] $reason"
        fail=$((fail + 1)); failed_names="$failed_names $name"
    fi
}

# ── mid-session carrier switch (topo=carrier-switch) ────────────────────────────────────────────────
# The line the offerer prints when it has reached s8 and is parked waiting to be moved onto its second
# carrier. It MUST match CARRIER_SWITCH_CUE in Semantics.kt — the two halves of one handshake.
CARRIER_SWITCH_CUE="s8/restart: awaiting the carrier switch"
# How many half-second polls to wait for that cue. A watchdog on an observed line, not a budget for the
# session: the offerer prints it only after phase 0 and s1–s7 have all run over the real path, so this has
# to cover a whole slow-lane semantics sequence. Never a reason a healthy lane waits longer.
CARRIER_SWITCH_POLLS=240

# Move the offerer onto its second carrier, then tell it the move happened. Backgrounded by run_scenario
# for the carrier-switch lanes only. Every step is observable: it waits for the peer's own cue (never a
# sleep), flips the default route with the same `docker compose exec` the NAT/netem plumbing already uses,
# and publishes ONE record into the shared rendezvous mailbox — which is both the only channel into a
# running peer and one the peer is already polling. A failure here is left to s8 to report: the peer's
# watchdog on the mailbox record is what turns "the harness never moved me" into a graded phase verdict,
# and a warning from a background job could otherwise be the only trace of it.
carrier_switch() {
    local name="$1" service="$2" i=0
    while [ "$i" -lt "$CARRIER_SWITCH_POLLS" ]; do
        case "$(docker compose logs --no-log-prefix "$service" 2>/dev/null)" in
            *"$CARRIER_SWITCH_CUE"*) break ;;
        esac
        i=$((i + 1)); sleep 0.5
    done
    if [ "$i" -ge "$CARRIER_SWITCH_POLLS" ]; then
        echo "::warning::[$name] the offerer never asked to be moved onto the second carrier — s8 grades it"
        return 0
    fi
    if ! docker compose exec -T "$service" ip route replace default via "$NAT_A2_LAN_IP" </dev/null; then
        echo "::warning::[$name] could not move $service onto the second carrier ($NAT_A2_LAN_IP) — s8 grades it"
        return 0
    fi
    echo "[carrier-switch] [$name] $service default route → nat_a2 ($NAT_A2_LAN_IP, public $NAT_A2_WAN_IP)"
    # Acknowledge into the mailbox slot the peer polls (`<session>/carrier`). python3 is in the rendezvous
    # image — the same call shape collect_diagnostics uses for /dump — so this needs no curl, no new
    # container and no second front door.
    docker compose exec -T rendezvous python3 -c \
        "import json,urllib.request as u; d=json.dumps({'key':'${SESSION}/carrier','id':0,'payload':'switched'}).encode(); \
         u.urlopen(u.Request('http://127.0.0.1:${RENDEZVOUS_HTTP_PORT}/put', d, {'Content-Type':'application/json'}))" </dev/null \
        || echo "::warning::[$name] could not publish the carrier-switch record — s8 will time out waiting for it"
}

# ── mid-session LOCAL ADDRESS swap (topo=interface-swap) ────────────────────────────────────────────
# The automatic-restart lane's one moving part (s11, issue #102), and the reason it is a separate topology
# rather than a flag on carrier_switch: that one flips the DEFAULT ROUTE, which changes peer A's public
# identity while every local address stays exactly where it was. IceRestartPolicy.OnNetworkChange asks a
# different question — "is the selected pair's local base still on a live interface" — and after a route
# flip the honest answer is yes, so the automatic policy correctly does nothing. To exercise it the LOCAL
# address has to go away.
#
# So: DELETE the address the session is riding, add peer A's second one, and point the default route at
# nat_a2 — one `sh -c`, in that order, which matters twice over.
#
# Delete FIRST, counter-intuitively. Adding the new address first and deleting the old one after is the
# obvious order and it silently destroys the container's networking: Linux flushes every SECONDARY address
# in a subnet when that subnet's PRIMARY is removed, unless `promote_secondaries` is set — and it is 0 by
# default, and the sysctl is read-only inside the container. Measured, not reasoned about: with add-then-
# delete the peer was left holding NO lan_a address at all, so it could not reach the rendezvous mailbox
# and s11 failed as "the harness never reported a carrier switch" — a message pointing at the orchestrator
# for a fault entirely in the peer's netns.
#
# Deleting the only address in a subnet also withdraws that subnet's connected route, and with it the
# default route through it — so re-adding the address and REPLACING the default are both required, in that
# order. The window with no address is sub-millisecond and inside one `sh -c`; the restart it triggers is
# re-gathered tens of milliseconds later (the monitor coalesces first), by which time the new address and
# route are long in place.
#
# The kernel emits real RTM_DELADDR/RTM_NEWADDR for this, which is the whole point — nothing here
# simulates a signal.
#
# Everything else is deliberately identical to carrier_switch: the same observed cue, the same rendezvous
# mailbox slot, the same "the phase grades it" failure discipline. The peer cannot tell the two apart, and
# should not be able to — it is supposed to find out from the network.
swap_interface() {
    local name="$1" service="$2" i=0
    while [ "$i" -lt "$CARRIER_SWITCH_POLLS" ]; do
        case "$(docker compose logs --no-log-prefix "$service" 2>/dev/null)" in
            *"$CARRIER_SWITCH_CUE"*) break ;;
        esac
        i=$((i + 1)); sleep 0.5
    done
    if [ "$i" -ge "$CARRIER_SWITCH_POLLS" ]; then
        echo "::warning::[$name] the offerer never asked to be moved — s11 grades it"
        return 0
    fi

    # The interface holding PEER_A_IP, resolved rather than assumed: compose promises no device name.
    # Single-quoted body so $2/$1 belong to awk, not to this function.
    local dev
    dev=$(docker compose exec -T "$service" sh -c 'ip -o -4 addr show | awk -v ip="'"$PEER_A_IP"'" '"'"'$4 ~ "^"ip"/" {print $2; exit}'"'"'' </dev/null | tr -d '\r')
    if [ -z "$dev" ]; then
        echo "::warning::[$name] could not find the interface holding $PEER_A_IP — s11 grades it"
        return 0
    fi

    if ! docker compose exec -T "$service" sh -c \
        "ip addr del ${PEER_A_IP}/24 dev $dev && ip addr add ${PEER_A2_IP}/24 dev $dev && ip route replace default via ${NAT_A2_LAN_IP}" </dev/null; then
        echo "::warning::[$name] could not swap $service onto $PEER_A2_IP via nat_a2 — s11 grades it"
        return 0
    fi
    echo "[interface-swap] [$name] $service $dev: $PEER_A_IP -> $PEER_A2_IP, default route -> nat_a2 ($NAT_A2_LAN_IP, public $NAT_A2_WAN_IP)"

    # Same mailbox slot the carrier lanes use — the peer is already polling it, and s11 waits on it for the
    # same reason s8 does: restarting before the address actually moved would prove nothing.
    docker compose exec -T rendezvous python3 -c \
        "import json,urllib.request as u; d=json.dumps({'key':'${SESSION}/carrier','id':0,'payload':'switched'}).encode(); \
         u.urlopen(u.Request('http://127.0.0.1:${RENDEZVOUS_HTTP_PORT}/put', d, {'Content-Type':'application/json'}))" </dev/null \
        || echo "::warning::[$name] could not publish the interface-swap record — s11 will time out waiting for it"
}


# ── capture-on-failure diagnostics (design §B) ──────────────────────────────────────────────────────
# The EXTRA NATs active in THIS scenario beyond the two CPEs — the carrier NATs (cgnat_*) of the NAT444 /
# hairpin lanes and peer A's second gateway (nat_a2) on the carrier-switch lane — derived from
# run_scenario's $infra (visible here by bash dynamic scope). Empty in the single-NAT lanes. They get the
# same treatment as nat_a/nat_b everywhere: packet capture, logs, firewall + conntrack state.
compose_active_carriers() { echo "${infra:-}" | tr ' ' '\n' | grep -E '^(cgnat|nat_a2)' || true; }

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

    # Per-container logs — ALL infra + both peers, not just the tee'd peer stdout — one file each. The
    # *_route6 sidecars are v6/dual-only (their `[route6] … routes installed` line is the proof the routed-v6
    # return routes actually landed); absent on v4, `docker compose logs` just yields an empty file there.
    for svc in coturn rendezvous nat_a nat_b coturn_route6 rendezvous_route6 ${a_service:-peer_a} ${b_service:-peer_b} $carriers; do
        docker compose logs --no-log-prefix "$svc" > "$dir/$svc.log" 2>/dev/null || true
    done

    # A capture that came back (nearly) empty is itself a finding, and a silent one is worse than useless:
    # a `relay-only` bundle once carried a coturn.log holding exactly ONE line — the entrypoint's own echo —
    # while the same container run by hand emits ~65 lines of startup alone. Reading that as "coturn had
    # nothing to say" is the wrong conclusion and it cost real time. The *_route6 sidecars are legitimately
    # absent on v4, so they are exempt rather than noisy.
    for svc in coturn rendezvous ${a_service:-peer_a} ${b_service:-peer_b}; do
        [ -f "$dir/$svc.log" ] || continue
        lines=$(wc -l < "$dir/$svc.log" 2>/dev/null || echo 0)
        if [ "$lines" -le 2 ]; then
            echo "[diag] WARNING: $svc.log captured only $lines line(s) — the log CAPTURE is suspect, not" \
                 "necessarily the service. Check the container is still up and that the service logs to stdout."
        fi
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
        echo "--- offerer selected ICE pair(s) ---"
        # Prefer the single captured offerer log ($a_log, visible by dynamic scope) over a fresh
        # `docker compose logs` read — same anti-truncation reasoning as the relay assertion. Unset only for
        # pre-connection failures (infra/netem), where "(none logged)" is the correct answer anyway.
        # Every live state is dumped, not just one: an s8 lane legitimately has two Connected pairs with a
        # Restarting between them, and which pair it moved from is half of that failure's diagnosis.
        printf '%s\n' "${a_log:-}" | grep -E '(Connected|Restarting)\(path=' || echo "(none logged)"
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

    # Per-lane semantics gate — compose reads this at `up` time and the stack is re-upped per scenario, so
    # the peer enforces phases (exits non-zero on a failed one) on exactly the lanes we promote.
    export PEER_SEMANTICS_REQUIRED
    PEER_SEMANTICS_REQUIRED=$(semantics_gate_for "$name")

    # DISTINCT per-lane, per-role seeds (scenario+family+role → a stable u32 via cksum) so no two lanes and
    # neither peer share entropy. Our peers read WEBRTC_SEED (=SEED_A offerer / SEED_B answerer, wired in
    # compose); it drives EVERY entropy source (ICE/DTLS/SCTP), so a logged seed reproduces exactly this
    # lane's flow as a seeded vnet fixture. The independent-stack answerers (pion/browsers) ignore it.
    export SEED_A SEED_B
    SEED_A=$(printf '%s' "${name}-${IP_FAMILY}-a" | cksum | cut -d' ' -f1)
    SEED_B=$(printf '%s' "${name}-${IP_FAMILY}-b" | cksum | cut -d' ' -f1)

    # firewall-relay6 (v6/dual only): the routed-v6 firewall — not policy — forces relay DISCOVERY. Tell the
    # NATs to drop WAN→LAN except from coturn (nat-setup.sh V6_FORCE_RELAY), and assert the selected pair is
    # a relay pair (like hairpin). V6_FORCE_RELAY MUST be reset each scenario (it may leak from this loop).
    if [ "$name" = "firewall-relay6" ]; then export V6_FORCE_RELAY=1; else unset V6_FORCE_RELAY; fi

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
        # werift is DTLS 1.2-only (record ProtocolVersion 0xFEFD; classic 6-flight handshake, no 1.3
        # flights — see node/peer.mjs), so like Pion it pins PEER_DTLS13=false on BOTH peers.
        node)    b_service="node";    profiles="$profiles node";    export PEER_DTLS13="false" ;;
        chrome)  b_service="chrome";  profiles="$profiles chrome";  export PEER_DTLS13="true" ;;
        firefox) b_service="firefox"; profiles="$profiles firefox"; export PEER_DTLS13="true" ;;
        webkit)  b_service="webkit";  profiles="$profiles webkit";  export PEER_DTLS13="true" ;;
        *)       b_service="peer_b";                                export PEER_DTLS13="true" ;;
    esac

    # s5 (reverse direction — the ANSWERER originates a data channel and the offerer reflects it) needs an
    # answerer that can originate, i.e. one of OURS. Every foreign family is a dumb reflector by design, so
    # the phase is enabled only on the native⇄native / jvm⇄native lanes and simply absent elsewhere.
    if [ "$b_impl" = "native" ]; then export PEER_REVERSE=1; else export PEER_REVERSE=0; fi

    # s8 (ICE restart across a mid-session carrier switch) needs a topology with a second carrier to be
    # moved onto, and nothing else: every answerer family re-answers a later round now (issue #71), so the
    # phase is no longer restricted to answerers of ours. Naming the carrier's public address is what lets
    # the phase assert WHERE the restart landed rather than only that the pair changed — and the carrier is
    # peer A's either way, so the assertion is identical whoever is answering.
    # Both restart topologies are the SAME network event — peer A moved onto its second carrier — and they
    # differ in exactly one thing: who asks for the new ICE generation. `carrier-switch` is s8 (we do);
    # `foreign-restart` is s10 (the answerer does, on the RESTART lifecycle word our offerer writes into the
    # mailbox — issue #87), which is the direction that tests OUR detection of somebody else's restart.
    # `interface-swap` is the THIRD initiator: neither peer asks. The harness deletes peer A's local
    # address, and IceRestartPolicy.OnNetworkChange — watching the PRODUCTION systemNetworkMonitor(),
    # netlink on Linux — is what has to notice and restart (s11, issue #102). PEER_A_IP_ALT is what makes
    # that survivable: the peer needs somewhere to re-gather once its configured address is gone.
    case "$topo" in
        carrier-switch|foreign-restart|interface-swap)
            export PEER_ICE_RESTART=1 PEER_RESTART_CARRIER="$NAT_A2_WAN_IP"
            case "$topo" in
                foreign-restart)  export PEER_RESTART_INITIATOR=peer ;;
                interface-swap)   export PEER_RESTART_INITIATOR=network; export PEER_A_IP_ALT="$PEER_A2_IP" ;;
                *)                export PEER_RESTART_INITIATOR=us ;;
            esac
            # s8/s10 each add an offer/answer round and an ICE reconvergence, separately watchdogged inside
            # the peer. The sequence budget has to leave room for the FAILURE path too, or a graded phase
            # verdict degrades into an ungraded "semantics: TIMEOUT" that says nothing about which half broke.
            export PEER_SEMANTICS_TIMEOUT_MS="${HARNESS_SEMANTICS_TIMEOUT_MS:-$((180000 + PEER_IDLE_MS))}"
            ;;
        *)
            export PEER_ICE_RESTART=0 PEER_RESTART_INITIATOR=us
            export PEER_SEMANTICS_TIMEOUT_MS="${HARNESS_SEMANTICS_TIMEOUT_MS:-$((120000 + PEER_IDLE_MS))}"
            # Unset, not left over: these are exported per scenario inside one loop, so a stale value would
            # arm an automatic restart on a lane whose phase list has no s11 to observe it.
            unset PEER_RESTART_CARRIER PEER_A_IP_ALT
            ;;
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
        carrier-switch|foreign-restart|interface-swap) # a SECOND gateway on peer A's own LAN, switched to mid-session
            # (not a layer above). Identical topology for both restart directions — see the PEER_ICE_RESTART
            # block above for what differs (who initiates), which is nothing the compose model knows about.
            unset NAT_A_CARRIER_GW NAT_B_CARRIER_GW
            profiles="$profiles carrier-switch"; infra="$infra nat_a2" ;;
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
    #
    # --no-recreate is LOAD-BEARING on the routed-v6 (dual/v6) lanes: without it, `compose up peer_a peer_b`
    # re-converges the whole project and RECREATES the peers' depends_on infra (rendezvous, nat_a, nat_b) —
    # giving rendezvous a fresh network namespace. That silently DROPS the return routes the rendezvous_route6
    # sidecar installed into the OLD namespace at infra-up (fd00:3x::/64 via the NAT WAN — the no-NAT66 return
    # path), and the sidecar does NOT re-run (it's still tail -f'ing, restart:on-failure never fires). The
    # rendezvous then has no route back to either peer LAN, so its offer/answer replies vanish (answerer stuck
    # descriptions=0; the browser's TCP SYN to :9998 goes UNREPLIED) and every routed-v6 lane fails at
    # SIGNALING before ICE even starts. The infra is already fully + correctly built for THIS scenario at
    # infra-up (profiles/seed/netem all set before compose-up-retry above), so there is nothing to recreate
    # here anyway — we only need the two peers created + started. v4 is unaffected (no return-route sidecars).
    docker compose up -d --no-build --no-recreate "$a_service" "$b_service"

    # The carrier-switch lane's one moving part: a background watcher that moves the offerer onto nat_a2
    # the moment it says it is ready (see carrier_switch). It has to be concurrent with the peers, because
    # the whole property is that the network changes MID-session — but it never races them: the peer parks
    # on the mailbox until the switch is acknowledged.
    local switch_pid=""
    case "$topo" in
        carrier-switch|foreign-restart)
            carrier_switch "$name" "$a_service" &
            switch_pid=$! ;;
        interface-swap)
            swap_interface "$name" "$a_service" &
            switch_pid=$! ;;
    esac

    # Block until each peer has exited and read its exit code (see peer_exit_rc — order-independent, unlike
    # `docker compose wait`).
    local rc_a rc_b
    rc_a=$(peer_exit_rc "$a_service")
    rc_b=$(peer_exit_rc "$b_service")
    # Reap the watcher (it has long since finished by the time both peers exit) so no `docker compose exec`
    # of a torn-down stack outlives the scenario.
    [ -n "$switch_pid" ] && wait "$switch_pid" 2>/dev/null

    # Capture each peer's full container log ONCE, now that both have exited (the waits above blocked on it).
    # The relay assertion below MUST grep this SAME captured text — NOT issue a second `docker compose logs`.
    # Re-reading the json-file log of a just-exited container is not guaranteed to return identical bytes on a
    # subsequent read (the log driver can hand back a truncated tail under CI load), which made the relay-
    # proving lanes (firewall-relay6 / hairpin) FLAKY: the dump here showed `Connected(…Relayed…)` while the
    # assertion's separate re-read of the same log missed it, failing a lane the ICE core had DETERMINISTICALLY
    # relayed (pass vs fail jobs carry a byte-identical selected pair + seed). One read → the assertion proves
    # exactly what we dumped.
    local a_log b_log
    a_log=$(docker compose logs --no-log-prefix "$a_service" 2>/dev/null)
    b_log=$(docker compose logs --no-log-prefix "$b_service" 2>/dev/null)

    echo "── $a_service (offerer) ──"; printf '%s\n' "$a_log"
    echo "── $b_service (answerer) ──"; printf '%s\n' "$b_log"

    # Grade the data-channel semantics phases from the captured logs — on PASS and FAIL alike, since a red
    # lane's phase verdicts are exactly what says WHICH semantic broke.
    semantics_report "$name" "$a_log" "$b_log"

    if [ "$rc_a" = "0" ] && [ "$rc_b" = "0" ]; then
        # Belt-and-suspenders for the RELAY-PROVING lanes (hairpin, firewall-relay6): a green rc only proves
        # the peers ESTABLISHED — NOT that the path was the coturn RELAY. hairpin pins ice_policy=relay and
        # firewall-relay6 blocks direct/srflx at the network (policy=all), but assert it independently from
        # the offerer's Connected-state trace so a future policy loosening — or an accidentally direct/srflx
        # pair — fails here instead of passing silently.
        #
        # Match a `Relayed` endpoint on EITHER side of the selected pair, not just `local=Relayed`: a relay
        # PAIR traverses the TURN relay iff either end is Relayed, and with policy=all (firewall-relay6) the
        # OFFERER can legitimately win the host side while the answerer holds the relay allocation — so the
        # offerer's trace reads `remote=Relayed(…)`. The old `local=Relayed` grep only held for hairpin, where
        # policy=relay forces BOTH sides onto relay candidates so the offerer's local is always Relayed.
        # Herestring, not `printf | grep -q`: see semantics_report — with pipefail, a matching `grep -q`
        # SIGPIPEs the printf on a log larger than the pipe buffer and the match reads as a MISS. The
        # semantics phases grew every offerer log well past that, so this assertion had to stop using a pipe.
        # `Connected(path=Known(pair=CandidatePair(…)))` — the state carries a sealed SelectedPath since the
        # ICE-restart work (a browser delegate reports SelectedPath.Opaque rather than a null pair), so the
        # rendering the assertion reads is `path=Known(pair=…)`, not the old `selectedPair=…`.
        if { [ "$topo" = "hairpin" ] || [ "$name" = "firewall-relay6" ]; } \
                && ! grep -qE 'Connected\(path=Known\(pair=CandidatePair\(.*Relayed' <<< "$a_log"; then
            fail_scenario "$name" "established but the selected ICE pair is NOT a relay pair (this lane must traverse the coturn TURN relay)"; return
        fi
        # s8's far half: the ANSWERER's own report that it re-answered our ICE-restart offer. The offerer's
        # phase already asserts what that answer CONTAINED (RFC 8842 §5.5 — both ICE credentials replaced,
        # the DTLS fingerprint kept) and that the session reconverged onto the new carrier; this asserts the
        # peer said it, in the peer's own log, which is the only place a third-party stack speaks for itself.
        # Same discipline as s7's `dc close:` grep, and every answerer family prints the identical token.
        # Herestring, not `printf | grep -q` — see the relay assertion above for why a pipe SIGPIPEs here.
        # Skipped when the semantics sequence is off or subset, since then s8 never ran to be reported on.
        if { [ "$topo" = "carrier-switch" ] || [ "$topo" = "interface-swap" ]; } && [ "${PEER_SEMANTICS:-1}" != "0" ] && [ -z "${PEER_SCENARIOS:-}" ] \
                && ! grep -q 're-answered round 1' <<< "$b_log"; then
            fail_scenario "$name" "both peers exited 0 but the answerer never reported re-answering our ICE-restart offer (s8/s11's far half: no 're-answered round 1' in its log)"; return
        fi
        # s11's NEAR half, and the lane's anti-vacuity guard (issue #102). Everything above this line is
        # equally true of a session that was restarted by an explicit restartIce() — so without this, a
        # regression that quietly re-armed the manual path, or a phase list that skipped s11 altogether,
        # would leave the lane green while proving nothing about the automatic one. The offerer prints this
        # token only from the s11 verdict, which is reachable only through IceRestartPhase.Automatic.
        if [ "$topo" = "interface-swap" ] && [ "${PEER_SEMANTICS:-1}" != "0" ] && [ -z "${PEER_SCENARIOS:-}" ] \
                && ! grep -q 'NOTHING called restartIce()' <<< "$a_log"; then
            fail_scenario "$name" "both peers exited 0 but the offerer never reported an AUTOMATIC restart (s11's near half: no 'NOTHING called restartIce()' in its log) — the lane cannot distinguish this from a manual restart"; return
        fi
        # s10's far half, the mirror of the above: on a foreign-initiated lane the ANSWERER is the one that
        # restarts, so its own log is the only place its stack says it acted on the RESTART lifecycle word.
        # Our offerer's phase asserts what the resulting offer CONTAINED (both ICE credentials replaced, the
        # DTLS fingerprint kept) and that our own answer opened a fresh generation — but a peer that
        # published a well-formed offer without its stack having restarted anything is exactly the failure
        # only the peer can rule out. Every answerer family prints the identical token.
        if [ "$topo" = "foreign-restart" ] && [ "${PEER_SEMANTICS:-1}" != "0" ] && [ -z "${PEER_SCENARIOS:-}" ] \
                && ! grep -q 'peer-initiated restart: re-offered round 0' <<< "$b_log"; then
            fail_scenario "$name" "both peers exited 0 but the answerer never reported restarting ICE on our cue (s10's far half: no 'peer-initiated restart: re-offered round 0' in its log)"; return
        fi
        if [ "$sem_missing" = "1" ]; then
            fail_scenario "$name" "both peers exited 0 but the offerer printed NO semantics-summary — the data-channel phases did not run on a lane that gates them"; return
        fi
        echo "✅ [$name] PASS (offerer rc=$rc_a answerer rc=$rc_b)"; pass=$((pass+1))
    else
        fail_scenario "$name" "FAIL (offerer rc=$rc_a answerer rc=$rc_b)"
    fi
}

# ── same-LAN mDNS lane (CO-2 Part 3) ─────────────────────────────────────────────────────────────────
# Topologically distinct from the NAT matrix: ONE shared bridge (lan0), NO NAT, NO netem, NO relay path.
# A native offerer (peer_mdns — OUR MulticastMdnsResolver under test) establishes against a browser
# answerer (chrome_mdns / firefox_mdns) that has mDNS obfuscation turned ON, so it emits `.local` host
# candidates our peer must resolve over multicast on the shared L2. Layers compose.mdns.yml and starts only
# coturn + rendezvous + the two peers — none of the NAT machinery (profiles/carriers/netem/captures) applies.
# Reuses the shared pass/warn tally, fail_scenario, and collect_diagnostics (its NAT-only probes best-effort
# degrade to empty files here). NON-GATING first (see $NON_GATING): a failure warns, never reddens the run.
run_mdns_scenario() {
    local name="$1" policy="${4:-all}" b_impl="${7:-chrome}"
    echo ""
    echo "═══ scenario: $name  (same-LAN mDNS, obfuscation ON, offerer=peer_mdns answerer=${b_impl}) ═══"

    # PEER_REVERSE=0: this lane's answerer is a browser, which can only reflect — never originate (s5).
    export ICE_POLICY="$policy" SESSION="$name" PEER_DTLS13="true" PEER_REVERSE=0

    # Per-lane semantics gate — see run_scenario.
    export PEER_SEMANTICS_REQUIRED
    PEER_SEMANTICS_REQUIRED=$(semantics_gate_for "$name")
    # Distinct per-lane seeds (see run_scenario). The browser answerer ignores WEBRTC_SEED.
    export SEED_A SEED_B
    SEED_A=$(printf '%s' "${name}-${IP_FAMILY}-a" | cksum | cut -d' ' -f1)
    SEED_B=$(printf '%s' "${name}-${IP_FAMILY}-b" | cksum | cut -d' ' -f1)

    # Layer the mdns overlay onto the family base for THIS scenario's compose calls, then restore so a later
    # scenario in the same run is unaffected. topo/a_service/b_service are locals collect_diagnostics reads.
    local saved_compose="$COMPOSE_FILE"
    export COMPOSE_FILE="${COMPOSE_FILE}:compose.mdns.yml"
    local topo="mdns" a_service="peer_mdns" b_service
    case "$b_impl" in
        firefox) b_service="firefox_mdns"; export COMPOSE_PROFILES="mdns,mdns-firefox" ;;
        *)       b_service="chrome_mdns";  export COMPOSE_PROFILES="mdns,mdns-chrome"  ;;
    esac

    local infra="coturn coturn_pcap rendezvous"
    stack_down
    if ! ./compose-up-retry.sh $infra; then
        fail_scenario "$name" "infra failed to come up"; export COMPOSE_FILE="$saved_compose"; return
    fi

    # Build + start both peers together (see run_scenario for the one-`up` ordering rationale). The browser
    # image is prebuilt + gha-cached in CI (HARNESS_NO_BROWSER_BUILD=1); locally we build it.
    docker compose build "$a_service"
    if [ "${HARNESS_NO_BROWSER_BUILD:-0}" = "1" ]; then : ; else docker compose build "$b_service"; fi
    docker compose up -d --no-build --no-recreate "$a_service" "$b_service"

    local rc_a rc_b
    rc_a=$(peer_exit_rc "$a_service")
    rc_b=$(peer_exit_rc "$b_service")

    local a_log b_log
    a_log=$(docker compose logs --no-log-prefix "$a_service" 2>/dev/null)
    b_log=$(docker compose logs --no-log-prefix "$b_service" 2>/dev/null)
    echo "── $a_service (offerer) ──"; printf '%s\n' "$a_log"
    echo "── $b_service (answerer) ──"; printf '%s\n' "$b_log"

    semantics_report "$name" "$a_log" "$b_log"   # see run_scenario — same grading on this lane

    if [ "$rc_a" = "0" ] && [ "$rc_b" = "0" ]; then
        # PASS gate part 1 = both peers exit 0. For THIS lane rc_a=0 already means more than establish+echo:
        # peer_mdns runs with WEBRTC_REQUIRE_MDNS=true, so it only exits 0 if our MulticastMdnsResolver
        # actually resolved the browser's obfuscated `<uuid>.local` over multicast (it keeps the poll/resolve
        # loops alive past the sub-second prflx connect). So the lane now PROVES mDNS resolution, not just
        # obfuscation-ON interop. We do NOT (and cannot) assert the resolved pair is SELECTED: mDNS is
        # link-local, so a resolved `.local` is the same directly-reachable IP prflx already won on — no
        # topology makes the mDNS pair win. See issue #48. Two hard assertions below corroborate rc_a=0:
        #   1. the browser SIGNALED an obfuscated `.local` and it REACHED us (our own forensics dump of the
        #      candidates we received — a strictly stronger source than the mailbox, which since #88 also
        #      carries `.local` candidates of OUR own and can no longer attribute one to the browser), and
        #   2. OUR resolver logged `mdns resolved …` on one.
        if ! grep -qE 'remote-cand\|.*\.local' <<< "$a_log"; then
            fail_scenario "$name" "established but the browser never signaled an obfuscated .local host candidate to us (mDNS obfuscation not exercised)"; export COMPOSE_FILE="$saved_compose"; return
        fi
        echo "[mdns] browser signaled an obfuscated .local host candidate"
        if ! grep -qi 'mdns resolved' <<< "$a_log"; then
            fail_scenario "$name" "established but our MulticastMdnsResolver never resolved the browser's .local (no 'mdns resolved' line — the resolver was not exercised)"; export COMPOSE_FILE="$saved_compose"; return
        fi
        echo "[mdns] ✅ our MulticastMdnsResolver resolved the browser's .local candidate"

        # ── the MIRROR direction (issue #88): a foreign peer resolves OUR `<uuid>.local` ──
        # Same discipline, opposite way round, and for the same reason: rc_a=0 already carries the first
        # half of it (WEBRTC_REQUIRE_MDNS_ANSWERED=true, so the peer only exits 0 if our responder answered
        # somebody's query for a name we minted). These two assertions corroborate it from the two logs:
        #   3. we PUBLISHED a name rather than an address (our own forensics record of what we signaled),
        #   4. our responder ANSWERED a query for one of those names, and
        #   5. the BROWSER's own log shows our `.local` reaching it and being accepted (it logs every
        #      candidate it is fed), so the name crossed the signaling as a name.
        #
        # What is deliberately NOT asserted, having been measured: a `remote-candidate: type=host` at our IP
        # in the browser's getStats(). It never appears on this topology, and correctly so — lan0 has no NAT,
        # so coturn reflects our own LAN address and our srflx candidate is 172.33.0.x:40000, the SAME
        # transport address as the host candidate behind the name. libwebrtc prunes the redundant pair, so
        # the resolved host candidate is real but unobservable. `mdns answered` is the load-bearing proof:
        # the browser can only have queried a name it read out of OUR candidate line.
        if ! grep -qE 'local-cand\|.*\.local' <<< "$a_log"; then
            fail_scenario "$name" "established but WE published no obfuscated .local host candidate (advertising was configured but never reached the wire)"; export COMPOSE_FILE="$saved_compose"; return
        fi
        echo "[mdns] we published our own host candidate as an obfuscated .local"
        if ! grep -qi 'mdns answered' <<< "$a_log"; then
            fail_scenario "$name" "established but our responder never answered a query for one of our .local names (no 'mdns answered' line — the browser never resolved ours)"; export COMPOSE_FILE="$saved_compose"; return
        fi
        echo "[mdns] our responder answered the browser's query for one of our .local names"
        if ! grep -qE 'remote candidate: candidate:.*\.local' <<< "$b_log"; then
            fail_scenario "$name" "our responder answered but the browser never saw an obfuscated .local of ours (the name did not cross the signaling)"; export COMPOSE_FILE="$saved_compose"; return
        fi
        if grep -qE 'addIceCandidate error' <<< "$b_log"; then
            fail_scenario "$name" "the browser REJECTED a candidate we signaled (see 'addIceCandidate error' in its log) — our obfuscated line is malformed to a real engine"; export COMPOSE_FILE="$saved_compose"; return
        fi
        echo "[mdns] ✅ the browser accepted OUR .local and resolved it (our responder answered its query)"
        if [ "$sem_missing" = "1" ]; then
            fail_scenario "$name" "both peers exited 0 but the offerer printed NO semantics-summary — the data-channel phases did not run on a lane that gates them"; export COMPOSE_FILE="$saved_compose"; return
        fi
        echo "✅ [$name] PASS (offerer rc=$rc_a answerer rc=$rc_b) — obfuscation-ON browser interop + mDNS resolution proven BOTH ways"; pass=$((pass+1))
    else
        fail_scenario "$name" "FAIL (offerer rc=$rc_a answerer rc=$rc_b)"
    fi
    export COMPOSE_FILE="$saved_compose"
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
    # Family-skip: a v4-only mapping-artifact on v6/dual, or the v6-native firewall-relay6 on v4.
    if family_skipped "$name"; then echo "── skip $name (family $IP_FAMILY)"; continue; fi
    # The same-LAN mDNS lane has its own NAT-free runner (shared bridge, no netem/relay/carrier machinery).
    if [ "$topo" = "mdns" ]; then
        run_mdns_scenario "$name" "$a" "$b" "$policy" "$netem" "$a_impl" "$b_impl" "$topo"
    else
        run_scenario "$name" "$a" "$b" "$policy" "$netem" "$a_impl" "$b_impl" "$topo"
    fi
done 3<<< "$SCENARIOS"

echo ""
echo "═══ summary: $pass passed, $fail failed${failed_names:+ (failed:$failed_names)}${warned_names:+, $warn non-gating failure(s):$warned_names (informational — deterministic DtlsSctpLossReproductionTest is the hard gate)}${sem_warned_names:+, data-channel semantics reported failures in:$sem_warned_names (informational — named holdouts in \$SEMANTICS_NON_GATING)} ═══"
# Exit non-zero iff a GATING scenario failed, or NOTHING ran at all. NON-GATING failures ($warn) never fail
# the run — the impaired lane's hard gate is the deterministic DtlsSctpLossReproductionTest, and v6/dual lanes
# land informational-first (FAMILY_GATING). A non-gating-ONLY run still counts as a successful run: e.g. a
# single-scenario browser job whose one v6 lane warns has pass=0 but MUST stay green (that is what
# "non-gating first" means). So require no gating fail AND that at least one scenario actually ran (passed OR
# warned) — the (pass+warn) term still guards the misconfigured "0 scenarios ran" case.
[ "$fail" -eq 0 ] && [ $((pass + warn)) -gt 0 ]
exit $?
