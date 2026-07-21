package com.ditchoom.webrtc.harness

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** Whether this peer creates the offer (ICE-controlling) or answers it (ICE-controlled). */
internal enum class Role { Offerer, Answerer }

/** Candidate policy: gather everything, or force the TURN relay path only (`relayOnly()`). */
internal enum class IcePolicy { All, RelayOnly }

/**
 * The peer's whole configuration, read from `WEBRTC_*` environment variables the compose harness sets.
 * Pure data; no seams here — the seams (clock/random/binder) are constructed in [runPeer] from this.
 */
internal data class HarnessConfig(
    val role: Role,
    val session: String,
    val localIp: String,
    val localPort: Int,
    val relayPort: Int,
    val stunHost: String,
    val stunPort: Int,
    val turnHost: String,
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
            return HarnessConfig(
                role = role,
                session = env("WEBRTC_SESSION") ?: "harness",
                localIp = envRequired("WEBRTC_LOCAL_IP"),
                localPort = localPort,
                relayPort = env("WEBRTC_RELAY_PORT")?.toIntOrNull() ?: (localPort + 1),
                stunHost = env("WEBRTC_STUN_HOST") ?: "coturn",
                stunPort = env("WEBRTC_STUN_PORT")?.toIntOrNull() ?: 3478,
                turnHost = env("WEBRTC_TURN_HOST") ?: "coturn",
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
