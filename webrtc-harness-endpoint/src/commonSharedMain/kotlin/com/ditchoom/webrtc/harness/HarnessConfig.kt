package com.ditchoom.webrtc.harness

import com.ditchoom.webrtc.ice.IceConfig
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Whether this peer creates the offer (ICE-controlling) or answers it (ICE-controlled). */
internal enum class Role { Offerer, Answerer }

/** Candidate policy: gather everything, or force the TURN relay path only (`relayOnly()`). */
internal enum class IcePolicy { All, RelayOnly }

/** An IP family. Derived from a bind address literal ([of]) — the harness only ever passes literals. */
internal enum class IpFamily {
    V4,
    V6,
    ;

    companion object {
        fun of(ip: String): IpFamily = if (':' in ip) V6 else V4
    }
}

/**
 * One IP family's local bind address plus the coturn (STUN/TURN) host reachable over it. The peer gathers a
 * host(+srflx)+relay candidate for EACH binding, so a dual-stack lane advertises both families (exercising
 * the RFC 6724 candidate-priority ordering) and a single-stack lane exactly one. [HarnessConfig.bindings] is
 * always non-empty — the primary family is the address in `WEBRTC_LOCAL_IP`.
 */
internal data class FamilyBinding(
    val family: IpFamily,
    val localIp: String,
    val stunHost: String,
    val turnHost: String,
)

/**
 * Whether an ICE-restart phase runs, **who initiates it**, and what the restarted session has to land on.
 *
 * A sealed choice rather than a flag beside a nullable address and a direction boolean: those fields can
 * also spell "the phase is off, but here is the carrier it must land on" or "nobody initiates", neither of
 * which is a run anyone can have. Each case here is exactly one run.
 */
internal sealed interface IceRestartPhase {
    /** No restart phase runs — every lane with only one carrier to sit behind. */
    data object Off : IceRestartPhase

    /** WE initiate the restart (s8) and assert only that it reconverged on a DIFFERENT pair. */
    data object AnyNewPath : IceRestartPhase

    /**
     * WE initiate the restart (s8), and it additionally asserts the new pair's local address is [carrierIp]
     * — the public address of the carrier the orchestrator moved us onto mid-session
     * (`topo=carrier-switch`). Without this the phase would pass on any pair change at all, including one
     * that reconverged on the carrier we left.
     */
    data class ExpectCarrier(
        val carrierIp: String,
    ) : IceRestartPhase

    /**
     * The **PEER** initiates the restart (s10, issue #87): the harness moves us onto [carrierIp], we ask the
     * answerer for a fresh ICE generation with the [Slot.PeerRestart] lifecycle word, and the restart offer
     * comes back at us. Same carrier assertion as [ExpectCarrier] — the carrier is peer A's either way — but
     * the property under test is the opposite one: that WE detect and answer somebody else's restart.
     *
     * Deliberately exclusive with the two above: a lane restarts in one direction. Both would need two
     * carriers to move between, and the second restart would have to prove its reconvergence against a pair
     * the first one had just changed.
     */
    data class ForeignInitiated(
        val carrierIp: String,
    ) : IceRestartPhase
}

/**
 * Whether the s9 consent-idle phase runs, and for how long the session is held open (issue #80).
 *
 * A sealed choice rather than a `Duration` whose zero doubles as "off": the two mean genuinely different
 * runs, and a duration of zero is also what a mistyped env var produces — which would silently turn the one
 * phase whose whole content is *elapsed time* into a no-op that still reports PASS.
 */
internal sealed interface ConsentIdlePhase {
    /** s9 does not run. */
    data object Off : ConsentIdlePhase

    /** s9 runs, holding the association open for [duration] with no application data crossing it. */
    data class Hold(
        val duration: Duration,
    ) : ConsentIdlePhase
}

/**
 * The peer's whole configuration, read from `WEBRTC_*` environment variables the compose harness sets.
 * Pure data; no seams here — the seams (clock/random/binder) are constructed in [runPeer] from this.
 */
internal data class HarnessConfig(
    val role: Role,
    val session: String,
    /** The per-family local binds (≥1); the peer gathers host+relay for each. See [FamilyBinding]. */
    val bindings: List<FamilyBinding>,
    val localPort: Int,
    val relayPort: Int,
    val stunPort: Int,
    val turnPort: Int,
    val turnUser: String,
    val turnPass: String,
    val rendezvousHost: String,
    val rendezvousPort: Int,
    val icePolicy: IcePolicy,
    val timeout: Duration,
    val seed: Long,
    /**
     * Negotiate up to DTLS 1.3 (the production default). Set `WEBRTC_DTLS13=false` for the Pion interop
     * lane: Pion's released v3 speaks DTLS 1.2 only, so our side must pin 1.2 to talk to it (the version
     * would otherwise negotiate up to 1.3 with another of our peers). Our 1.2 fallback is W4-tested.
     */
    val enableDtls13: Boolean,
    /**
     * Same-LAN mDNS lane only (`WEBRTC_REQUIRE_MDNS=true`): the peer's success additionally REQUIRES that
     * our [MulticastMdnsResolver] resolved at least one of the browser's obfuscated `<uuid>.local` host
     * candidates over multicast. Off (production/every other lane) mDNS is best-effort and never gates.
     *
     * Why this exists: on a no-NAT shared L2 segment ICE peer-reflexive wins the pair in ~200ms and the
     * offerer would otherwise exit before it even polls the browser's trickled `.local` — so the resolver,
     * though wired, never fires and the lane can't PROVE resolution. mDNS resolution can never be the
     * *selected* pair here (it is link-local, so the resolved host is the same directly-reachable IP prflx
     * already won on); the achievable proof is "we resolved a real browser's `.local` → valid host
     * candidate". This flag keeps the poll/resolver loops alive (watchdog-bounded) until that happens.
     * Tracks issue #48.
     */
    val requireMdns: Boolean,
    /**
     * Same-LAN mDNS lane only (`WEBRTC_MDNS_ADVERTISE=true`): publish our own host candidates as
     * `<uuid>.local` names (RFC 8828 privacy) and answer the peer's multicast queries for them, instead of
     * signaling literal LAN addresses. Off everywhere else — the NAT lanes put the peers on separate LANs,
     * where a link-local query can never cross, so a name would simply cost the peer the host candidate.
     *
     * When on, the SAME [MulticastMdnsEndpoint] serves both halves. That is not a convenience: a responder
     * has to hold port 5353, and a second socket on it would take a hash-chosen share of the unicast replies
     * to our own queries. Tracks issue #88.
     */
    val advertiseMdns: Boolean,
    /**
     * Same-LAN mDNS lane only (`WEBRTC_REQUIRE_MDNS_ANSWERED=true`): the mirror of [requireMdns] for the
     * direction #88 added. The peer's success additionally REQUIRES that our responder actually **answered**
     * a foreign peer's query for one of the names we minted — the only thing that proves a browser could
     * resolve *our* `.local`, as opposed to merely tolerating it.
     *
     * It needs its own gate for the same reason [requireMdns] does: establishment proves nothing here.
     * RFC 8445 §7.3.1.3 peer-reflexive learning finds the path from our own checks on a flat segment whether
     * or not a single name was ever resolved, so a lane that only asserted "connected" would pass with the
     * responder deleted.
     */
    val requireMdnsAnswered: Boolean,
    /**
     * Run the data-channel SEMANTICS phase sequence after phase 0's ping/pong (see [Semantics.kt] and
     * docs/DC_SEMANTICS_INTEROP_DESIGN.md). Off by default so any other invocation keeps the historical
     * establish-and-echo contract exactly; `run-interop.sh` turns it on for every lane.
     *
     * It also changes the ANSWERER's exit condition: instead of lingering a few seconds after echoing
     * `pong` (which would kill the association mid-sequence), it reflects every channel until the offerer's
     * explicit `DONE` handshake.
     */
    val semantics: Boolean,
    /**
     * Optional SUBSET of the offerer's compiled-in phase list, by short id (`WEBRTC_SCENARIOS="s1,s2"`) —
     * a debugging knob, not a lane matrix. Empty = run them all. The list is never signalled to the peer:
     * the reflector is scenario-agnostic by design, so there is nothing to tell it.
     */
    val scenarios: Set<String>,
    /**
     * Whether a failed semantics phase makes the process exit non-zero. Off while the semantics phases land
     * NON-GATING-first (decision D7): the phases still run and still report, and `run-interop.sh` surfaces
     * a failure as an informational `::warning::` until a one-line follow-up flips this on.
     */
    val semanticsRequired: Boolean,
    /**
     * Run the reverse-direction phase, in which the ANSWERER originates a data channel and the offerer
     * reflects it (decision D4). Only meaningful when BOTH endpoints are ours — a foreign peer is a dumb
     * reflector and never originates — so `run-interop.sh` sets it for the native⇄native / jvm⇄native lanes.
     */
    val reverseChannel: Boolean,
    /**
     * The watchdog for the whole semantics sequence, on top of [timeout] (which bounds establishment). A
     * bound so a wedged phase cannot hang CI, not a wall-clock budget — every phase asserts observable
     * state and finishes in milliseconds on a clean path (directive #4).
     */
    val semanticsTimeout: Duration,
    /**
     * Run the ICE-restart phase, in which the OFFERER restarts ICE mid-session (RFC 8445 §9) after the
     * harness has moved it onto a second carrier, and both sides carry a second offer/answer round. Like
     * [reverseChannel] it needs an answerer of ours — a foreign reflector never re-answers — so
     * `run-interop.sh` sets it only for the native⇄native / jvm⇄native `carrier-switch` lanes.
     */
    val iceRestart: IceRestartPhase,
    /**
     * RFC 7675 §4.1 consent timing, injected into `PeerConnectionConfig.iceConfig` — the seam that lets a
     * lane exercise consent *revocation* without adding the RFC's own 30 s window to every CI run.
     *
     * §4.1 says an implementation MUST NOT configure a period below 4 s. That is a deployment bound the
     * sans-io core deliberately cannot enforce (it is a caller-injected seam precisely so a scenario can
     * compress the schedule and still assert observable state), and this harness is a scenario. Unset —
     * every invocation that is not `run-interop.sh` — leaves the production RFC defaults in place.
     */
    val consentInterval: Duration,
    val consentTimeout: Duration,
    /**
     * Run the consent-idle phase, in which the offerer holds the session open, sending nothing, for longer
     * than [consentTimeout] — so a peer that does not answer our RFC 7675 checks revokes and the phase
     * fails. See `phaseConsentIdle`. Unlike s5/s8 this needs nothing of the answerer but silence, so it
     * runs on the foreign lanes too, which is the whole point of it.
     */
    val consentIdle: ConsentIdlePhase,
) {
    /** Whether phase [id] (`s1`, `s2`, …) is in this run's subset — everything runs when none was named. */
    fun runsScenario(id: String): Boolean = scenarios.isEmpty() || id in scenarios

    /**
     * How many rounds this run signals on the `offer`/`answer` slots — the ones WE originate. One normally;
     * two when s8 re-offers with a fresh ICE generation. It bounds the mailbox polling on BOTH sides, so a
     * lane that cannot restart keeps exactly the single-round poll sequence it has always had. A
     * peer-originated restart (s10) adds no round here: it rides its own slots (see [Slot.PeerOffer]).
     */
    val negotiationRounds: Int
        get() =
            when (iceRestart) {
                IceRestartPhase.Off, is IceRestartPhase.ForeignInitiated -> 1
                IceRestartPhase.AnyNewPath, is IceRestartPhase.ExpectCarrier -> 2
            }

    /**
     * How many rounds this run signals on the `peer-offer`/`peer-answer` slots — the ones the PEER
     * originates (s10). Exactly one on a foreign-restart lane and none anywhere else, which is what keeps
     * every other lane's poll sequence byte-identical to what it has always been.
     */
    val peerNegotiationRounds: Int
        get() =
            when (iceRestart) {
                IceRestartPhase.Off, IceRestartPhase.AnyNewPath, is IceRestartPhase.ExpectCarrier -> 0
                is IceRestartPhase.ForeignInitiated -> 1
            }

    companion object {
        fun fromEnv(): HarnessConfig {
            val role = if (envRequired("WEBRTC_ROLE").equals("offerer", ignoreCase = true)) Role.Offerer else Role.Answerer
            val localPort = env("WEBRTC_LOCAL_PORT")?.toIntOrNull() ?: 40000
            val stunHost = env("WEBRTC_STUN_HOST") ?: "coturn"
            val turnHost = env("WEBRTC_TURN_HOST") ?: "coturn"
            // The primary family = the address in WEBRTC_LOCAL_IP (v4 on a v4/dual lane, v6 on a v6-only
            // lane). A dual-stack lane injects WEBRTC_LOCAL_IP6 (+ the v6 coturn) for a SECOND binding, so
            // the peer gathers both families; a single-stack lane leaves it unset and gathers exactly one.
            val bindings =
                buildList {
                    val primaryIp = envRequired("WEBRTC_LOCAL_IP")
                    add(FamilyBinding(IpFamily.of(primaryIp), primaryIp, stunHost, turnHost))
                    env("WEBRTC_LOCAL_IP6")?.let { ip6 ->
                        add(FamilyBinding(IpFamily.V6, ip6, env("WEBRTC_STUN_HOST6") ?: stunHost, env("WEBRTC_TURN_HOST6") ?: turnHost))
                    }
                }
            return HarnessConfig(
                role = role,
                session = env("WEBRTC_SESSION") ?: "harness",
                bindings = bindings,
                localPort = localPort,
                relayPort = env("WEBRTC_RELAY_PORT")?.toIntOrNull() ?: (localPort + 1),
                stunPort = env("WEBRTC_STUN_PORT")?.toIntOrNull() ?: 3478,
                turnPort = env("WEBRTC_TURN_PORT")?.toIntOrNull() ?: 3478,
                turnUser = env("WEBRTC_TURN_USER") ?: "webrtc",
                turnPass = env("WEBRTC_TURN_PASS") ?: "webrtc",
                rendezvousHost = env("WEBRTC_RENDEZVOUS_HOST") ?: "rendezvous",
                rendezvousPort = env("WEBRTC_RENDEZVOUS_PORT")?.toIntOrNull() ?: 9999,
                icePolicy = if (env("WEBRTC_ICE_POLICY").equals("relay", ignoreCase = true)) IcePolicy.RelayOnly else IcePolicy.All,
                timeout = (env("WEBRTC_TIMEOUT_MS")?.toLongOrNull() ?: 45_000L).milliseconds,
                // Distinct default seeds per role so the two peers never collide ufrag/tie-breaker; override
                // with WEBRTC_SEED. This is entropy for a driver, not a core, so a fixed seed is fine.
                seed = env("WEBRTC_SEED")?.toLongOrNull() ?: if (role == Role.Offerer) 1L else 2L,
                // Default true (production); the Pion lane sets WEBRTC_DTLS13=false. Any value other than
                // an explicit "false" keeps 1.3 on.
                enableDtls13 = env("WEBRTC_DTLS13")?.equals("false", ignoreCase = true) != true,
                // Off everywhere except the same-LAN mDNS lane, whose compose overlay sets it explicitly.
                requireMdns = env("WEBRTC_REQUIRE_MDNS")?.equals("true", ignoreCase = true) == true,
                // Off everywhere except the same-LAN mDNS lane: obfuscating a host candidate a peer cannot
                // resolve (a different LAN) would cost it the candidate for nothing (issue #88).
                advertiseMdns = env("WEBRTC_MDNS_ADVERTISE")?.equals("true", ignoreCase = true) == true,
                requireMdnsAnswered = env("WEBRTC_REQUIRE_MDNS_ANSWERED")?.equals("true", ignoreCase = true) == true,
                // Semantics: off unless explicitly enabled, so an unmodified invocation keeps the exact
                // historical establish-and-echo contract. run-interop.sh enables it for every lane.
                semantics = env("WEBRTC_SEMANTICS").isTruthy(),
                scenarios = env("WEBRTC_SCENARIOS")?.split(',', ' ')?.mapNotNull { it.trim().takeIf(String::isNotEmpty) }?.toSet().orEmpty(),
                semanticsRequired = env("WEBRTC_SEMANTICS_REQUIRED").isTruthy(),
                reverseChannel = env("WEBRTC_REVERSE").isTruthy(),
                semanticsTimeout = (env("WEBRTC_SEMANTICS_TIMEOUT_MS")?.toLongOrNull() ?: 120_000L).milliseconds,
                // Off unless the lane both enables the phase and (optionally) names the carrier the switch
                // moves us onto — the carrier-switch lanes name it, so the phase can prove WHERE the
                // restart landed rather than only that something changed.
                iceRestart =
                    when {
                        !env("WEBRTC_ICE_RESTART").isTruthy() -> IceRestartPhase.Off
                        // WEBRTC_RESTART_INITIATOR names WHO restarts: `peer` is s10 (issue #87), anything
                        // else — including absent — is s8, the direction every restart lane has run so far.
                        // The peer direction needs the carrier named: without it the phase could not say
                        // where the restart landed, and there is no reason to run it blind when the lane it
                        // runs on always has one.
                        env("WEBRTC_RESTART_INITIATOR").equals("peer", ignoreCase = true) ->
                            env("WEBRTC_RESTART_CARRIER")
                                ?.let { IceRestartPhase.ForeignInitiated(it) }
                                ?: error("WEBRTC_RESTART_INITIATOR=peer requires WEBRTC_RESTART_CARRIER")
                        else ->
                            env("WEBRTC_RESTART_CARRIER")
                                ?.let { IceRestartPhase.ExpectCarrier(it) }
                                ?: IceRestartPhase.AnyNewPath
                    },
                // Unset = the library's own RFC 7675 defaults (5 s / 30 s). run-interop.sh compresses them
                // so a lane can outlive a whole revocation window in seconds rather than half a minute.
                consentInterval = env("WEBRTC_CONSENT_INTERVAL_MS")?.toLongOrNull()?.milliseconds ?: RFC_CONSENT.consentInterval,
                consentTimeout = env("WEBRTC_CONSENT_TIMEOUT_MS")?.toLongOrNull()?.milliseconds ?: RFC_CONSENT.consentTimeout,
                // A hold of zero (or a missing/mistyped var) is Off, not a zero-length hold: see
                // [ConsentIdlePhase].
                consentIdle =
                    (env("WEBRTC_IDLE_MS")?.toLongOrNull() ?: 0L)
                        .takeIf { it > 0L }
                        ?.let { ConsentIdlePhase.Hold(it.milliseconds) }
                        ?: ConsentIdlePhase.Off,
            )
        }

        /**
         * The library's own RFC 7675 §4.1 defaults, READ OFF [IceConfig] rather than restated as numbers
         * here. An unset env var must mean "production", and a copied 30_000 would go on saying so long
         * after the library changed its mind.
         */
        private val RFC_CONSENT = IceConfig()

        /** `1` / `true` (any case) enable a flag; anything else — including absent — leaves it off. */
        private fun String?.isTruthy(): Boolean = this == "1" || this.equals("true", ignoreCase = true)

        private fun env(name: String): String? = readEnv(name)?.takeIf { it.isNotBlank() }

        private fun envRequired(name: String): String = env(name) ?: error("missing required env var: $name")
    }
}
