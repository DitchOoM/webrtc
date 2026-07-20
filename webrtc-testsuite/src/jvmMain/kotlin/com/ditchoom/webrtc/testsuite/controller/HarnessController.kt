package com.ditchoom.webrtc.testsuite.controller

import com.ditchoom.webrtc.testsuite.harness.NatType
import com.ditchoom.webrtc.testsuite.harness.NetworkImpairment

/**
 * The JVM-side control-plane bridge between the deterministic in-memory [withWebRtcHarness]
 * [com.ditchoom.webrtc.testsuite.harness.withWebRtcHarness] DSL and the **L2 container harness**
 * (`test-harness/run-interop.sh`), the webrtc analogue of socket's `HarnessController`.
 *
 * Socket's controller is an HTTP server the container stack runs; the webrtc harness has no such live
 * control plane in the *published* path — the vnet is entirely in-process (RFC §7 "Consumer" tier). So
 * this controller is a **pure, side-effect-free translator**: it maps a typed DSL scenario to the exact
 * `NAT_*_PROFILE` / `ICE_POLICY` / netem vocabulary `run-interop.sh` consumes ([describe]), so a JVM CI
 * lane can assert that an in-memory scenario and its real-kernel L2 counterpart line up (same NAT
 * behavior, same relay policy, same impairment) instead of drifting apart. It does **not** launch
 * docker — bringing the L2 stack up remains the bash harness's job.
 */
public object HarnessController {
    /**
     * The `run-interop.sh` NAT profile name for [type] (`port-restricted` / `address-restricted` /
     * `full-cone` / `symmetric`), or `null` for [NatType.None] (no NAT container in the L2 stack).
     */
    public fun natProfileName(type: NatType): String? =
        when (type) {
            NatType.None -> null
            NatType.FullCone -> "full-cone"
            NatType.AddressRestrictedCone -> "address-restricted"
            NatType.PortRestrictedCone -> "port-restricted"
            NatType.Symmetric -> "symmetric"
        }

    /** Translate a DSL scenario into the L2 container-harness environment (`run-interop.sh`). */
    public fun describe(
        natType: NatType,
        relayOnly: Boolean,
        impairment: NetworkImpairment? = null,
    ): L2ScenarioDescriptor {
        val profile = natProfileName(natType)
        return L2ScenarioDescriptor(
            natAProfile = profile,
            natBProfile = profile,
            icePolicy = if (relayOnly) IcePolicy.Relay else IcePolicy.All,
            netem = impairment?.let(::netemArgs),
        )
    }

    // The `tc qdisc ... netem` argument string run-interop.sh applies on the impaired lane.
    private fun netemArgs(impairment: NetworkImpairment): String {
        val parts = mutableListOf<String>()
        val delayMs = impairment.midpointDelayMillis()
        val jitterMs = impairment.jitterMillis()
        if (delayMs > 0) {
            parts += "delay ${delayMs}ms"
            if (jitterMs > 0) parts += "${jitterMs}ms distribution normal"
        }
        if (impairment.loss > 0.0) parts += "loss ${(impairment.loss * 100).roundedPercent()}%"
        if (impairment.duplicate > 0.0) parts += "duplicate ${(impairment.duplicate * 100).roundedPercent()}%"
        return parts.joinToString(" ").ifEmpty { "-" }
    }

    private fun NetworkImpairment.midpointDelayMillis(): Long = ((minDelay + maxDelay).inWholeMilliseconds) / 2

    private fun NetworkImpairment.jitterMillis(): Long = (maxDelay - minDelay).inWholeMilliseconds / 2

    private fun Double.roundedPercent(): String {
        val rounded = (this * 10).toLong() / 10.0
        return if (rounded % 1.0 == 0.0) rounded.toLong().toString() else rounded.toString()
    }
}

/** The ICE transport policy `run-interop.sh` understands: `all` candidates, or `relay`-only. */
public enum class IcePolicy(
    public val wireName: String,
) {
    All("all"),
    Relay("relay"),
}

/**
 * The L2 container-harness environment for a scenario, as `run-interop.sh` consumes it:
 * `NAT_A_PROFILE` / `NAT_B_PROFILE` (`null` = no NAT container), `ICE_POLICY`, and an optional netem
 * argument string ([netem], `null` = clean link).
 */
public data class L2ScenarioDescriptor(
    public val natAProfile: String?,
    public val natBProfile: String?,
    public val icePolicy: IcePolicy,
    public val netem: String?,
)
