package com.ditchoom.webrtc.ice

/**
 * How a peer connection gathers local ICE candidates — the seam over "which sockets to bind"
 * (ARCHITECTURE §5.2: gathering rides an injected driver). A test supplies host addresses over the vnet
 * (`{ it.gatherHost("10.0.0.1", 5000) }`); the production policy is `systemIceGathering()`, which
 * enumerates interfaces and adds srflx/relay from the configured [IceServer]s.
 *
 * It runs **once per ICE generation** — when negotiation starts, and again on every ICE restart (RFC 8445
 * §9), which exists precisely because the interfaces may have changed underneath the session. A policy
 * that pins fixed ports must therefore hand out a fresh one each call: the outgoing generation's sockets
 * stay bound until the new generation nominates, and an OS will not re-bind an address still in use.
 *
 * Declared here rather than in `webrtc` because the only thing that can implement it in production is
 * built on `socket-udp`, which by ARCHITECTURE §11.6 may appear in exactly one place — this module's
 * `socketMain`. `com.ditchoom.webrtc.IceGatheringPolicy` remains as a typealias.
 */
public fun interface IceGatheringPolicy {
    /** Gather candidates on [driver] (host/srflx/relay) — each gathered candidate trickles out. */
    public suspend fun gather(driver: IceAgentDriver)
}
