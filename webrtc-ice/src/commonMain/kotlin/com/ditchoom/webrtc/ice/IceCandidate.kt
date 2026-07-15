package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.jvm.JvmInline

/**
 * An ICE component (RFC 8445 §2.2). A data channel uses a single component (RTP, id 1); RTCP would be
 * id 2 under media. Wrapped so a component id can never be confused with a priority or a port.
 */
@JvmInline
public value class ComponentId(
    public val value: Int,
) {
    init {
        require(value in 1..MAX) { "component id is 1..$MAX (RFC 8445 §5.1.1.1), got $value" }
    }

    public companion object {
        private const val MAX = 256

        /** The sole component of a data channel (and the RTP component of a media stream). */
        public val Rtp: ComponentId = ComponentId(1)
    }
}

/**
 * The four ICE candidate kinds (RFC 8445 §5.1.1). [preference] is the RFC-recommended type preference
 * (§5.1.2.2) that dominates a candidate's priority: a host candidate is always preferred to reflexive,
 * reflexive to relayed — the relay is the last resort because it costs a round-trip through a server.
 */
public enum class CandidateType(
    public val preference: Int,
    public val token: String,
) {
    // RFC 8445 §5.1.2.2 recommended type preferences (host > prflx > srflx > relay).
    Host(126, "host"),
    PeerReflexive(110, "prflx"),
    ServerReflexive(100, "srflx"),
    Relayed(0, "relay"),
}

/** The candidate transport protocol. Phase 1 is UDP-only (RFC 8445 assumes UDP for data channels). */
public enum class IceTransport(
    public val token: String,
) {
    Udp("udp"),
}

/**
 * A candidate's **foundation** (RFC 8445 §5.1.1.3): two candidates share a foundation iff they have the
 * same type, same base IP, same STUN/TURN server (if any), and same transport. Foundations drive the
 * *frozen* algorithm — pairs with a foundation already being checked stay frozen so redundant checks
 * across parallel media streams are avoided. Wrapped so it is never a bare `String` at an API boundary.
 */
@JvmInline
public value class Foundation(
    public val value: String,
) {
    public companion object {
        /**
         * The foundation for a candidate of [type] on [baseIp], gathered via [serverIp] (null for host),
         * over [transport] — a stable content-derived identifier, equal exactly when RFC 8445 §5.1.1.3
         * says two candidates share a foundation.
         */
        public fun of(
            type: CandidateType,
            baseIp: String,
            serverIp: String?,
            transport: IceTransport,
        ): Foundation = Foundation("${type.token}:$baseIp:${serverIp ?: "-"}:${transport.token}")
    }
}

/**
 * One ICE candidate (RFC 8445 §5.1.1) — a single, array-free value an agent can keep for the life of a
 * session (it holds no datagram slice). [address] is where a peer sends to reach this candidate;
 * [base] is the local socket the agent sends *from* when using it (equal to [address] for a host
 * candidate, the local host for srflx/prflx, the relayed address for a relay candidate).
 * [relatedAddress] is the srflx/relay "raddr" (RFC 8445 §5.1.1.4), diagnostic only.
 */
public data class IceCandidate(
    public val type: CandidateType,
    public val transport: IceTransport,
    public val address: TransportAddress,
    public val base: TransportAddress,
    public val foundation: Foundation,
    public val component: ComponentId,
    public val priority: Long,
    public val relatedAddress: TransportAddress? = null,
) {
    public companion object {
        private const val TYPE_PREF_SHIFT = 24
        private const val LOCAL_PREF_SHIFT = 8
        private const val COMPONENT_BASE = 256
        private const val MAX_LOCAL_PREFERENCE = 65535

        /**
         * The RFC 8445 §5.1.2.1 priority: `2^24·typePref + 2^8·localPref + (256 − componentId)`.
         * [localPreference] (0..65535) breaks ties between candidates of the same type — e.g. preferring
         * one interface (IPv6 over IPv4, Wi-Fi over cellular). The result is a 32-bit value carried in a
         * 64-bit [Long] so pair-priority arithmetic (RFC 8445 §6.1.2.3) never overflows.
         */
        public fun computePriority(
            type: CandidateType,
            component: ComponentId,
            localPreference: Int = MAX_LOCAL_PREFERENCE,
        ): Long {
            require(localPreference in 0..MAX_LOCAL_PREFERENCE) { "local preference is 0..$MAX_LOCAL_PREFERENCE" }
            return (type.preference.toLong() shl TYPE_PREF_SHIFT) +
                (localPreference.toLong() shl LOCAL_PREF_SHIFT) +
                (COMPONENT_BASE - component.value)
        }

        /**
         * A host candidate for [address] (its own base), with the RFC priority filled in. The common
         * path for a gathered local interface address.
         */
        public fun host(
            address: TransportAddress,
            component: ComponentId = ComponentId.Rtp,
            transport: IceTransport = IceTransport.Udp,
            localPreference: Int = MAX_LOCAL_PREFERENCE,
        ): IceCandidate =
            IceCandidate(
                type = CandidateType.Host,
                transport = transport,
                address = address,
                base = address,
                foundation = Foundation.of(CandidateType.Host, address.ip(), serverIp = null, transport = transport),
                component = component,
                priority = computePriority(CandidateType.Host, component, localPreference),
            )
    }
}

/** The IP literal of a [TransportAddress] (IPv4 dotted-quad or the IPv6 form) — used in foundations. */
internal fun TransportAddress.ip(): String = ip.toString()
