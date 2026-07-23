package com.ditchoom.webrtc.harness

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
) {
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
            )
        }

        private fun env(name: String): String? = readEnv(name)?.takeIf { it.isNotBlank() }

        private fun envRequired(name: String): String = env(name) ?: error("missing required env var: $name")
    }
}
