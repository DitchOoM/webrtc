package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.jvm.JvmInline

/**
 * An ICE component (RFC 8445 §2.2). WebRTC uses exactly two — RTP (id 1) and, under media with no
 * rtcp-mux, RTCP (id 2) — so it is an **enum**, not an `Int` with a range check: an illegal component
 * id is simply unrepresentable (the wire value rides in [value]).
 */
public enum class ComponentId(
    public val value: Int,
) {
    Rtp(1),
    Rtcp(2),
}

/**
 * The four ICE candidate kinds (RFC 8445 §5.1.1). [preference] is the RFC-recommended type preference
 * (§5.1.2.2) that dominates a candidate's priority: a host candidate is always preferred to reflexive,
 * reflexive to relayed. The kind is the discriminant of the [IceCandidate] sealed hierarchy.
 */
public enum class CandidateType(
    public val preference: Int,
    public val token: String,
) {
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
 * same type, same base IP, same STUN/TURN server (if any), and same transport. Wrapped so it is never a
 * bare `String` at an API boundary.
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
 * One ICE candidate (RFC 8445 §5.1.1) — a **sealed hierarchy per type**, so each variant carries only
 * the fields valid for it and an illegal combination (a host candidate with a relay's related-address)
 * is unrepresentable, not merely guarded. Common to all: [address] (where a peer sends to reach it),
 * [base] (the local socket we send *from*), [foundation], [component], [priority], and the [type]
 * discriminant. Every candidate is array-free and outlives a datagram (it holds no slice).
 */
public sealed interface IceCandidate {
    public val transport: IceTransport
    public val address: TransportAddress
    public val base: TransportAddress
    public val foundation: Foundation
    public val component: ComponentId
    public val priority: Long
    public val type: CandidateType

    /** A **host** candidate (RFC 8445 §5.1.1.1): a local interface address; its base is itself. */
    public data class Host(
        override val address: TransportAddress,
        override val component: ComponentId,
        override val transport: IceTransport,
        override val foundation: Foundation,
        override val priority: Long,
    ) : IceCandidate {
        override val base: TransportAddress get() = address
        override val type: CandidateType get() = CandidateType.Host
    }

    /**
     * A **server-reflexive** candidate (RFC 8445 §5.1.1.2): our external mapping learned from a STUN
     * server. [address] is the mapped address, [base] the local host we sent from, and [relatedAddress]
     * (the "raddr", §5.1.1.4) is required — a srflx candidate always has one.
     */
    public data class ServerReflexive(
        override val address: TransportAddress,
        override val base: TransportAddress,
        override val component: ComponentId,
        override val transport: IceTransport,
        override val foundation: Foundation,
        override val priority: Long,
        public val relatedAddress: TransportAddress,
    ) : IceCandidate {
        override val type: CandidateType get() = CandidateType.ServerReflexive
    }

    /**
     * A **peer-reflexive** candidate (RFC 8445 §5.1.1.2 / §7.3.1.3): a mapping discovered from an
     * inbound connectivity check rather than a STUN server. Same shape as [ServerReflexive] but a
     * distinct type, because its provenance and priority preference differ.
     */
    public data class PeerReflexive(
        override val address: TransportAddress,
        override val base: TransportAddress,
        override val component: ComponentId,
        override val transport: IceTransport,
        override val foundation: Foundation,
        override val priority: Long,
        public val relatedAddress: TransportAddress,
    ) : IceCandidate {
        override val type: CandidateType get() = CandidateType.PeerReflexive
    }

    /**
     * A **relayed** candidate (RFC 8445 §5.1.1.2, RFC 8656): a TURN relayed transport address. Its base
     * is the relayed address itself; [relatedAddress] is the mapped address the allocation was made from.
     */
    public data class Relayed(
        override val address: TransportAddress,
        override val component: ComponentId,
        override val transport: IceTransport,
        override val foundation: Foundation,
        override val priority: Long,
        public val relatedAddress: TransportAddress,
    ) : IceCandidate {
        override val base: TransportAddress get() = address
        override val type: CandidateType get() = CandidateType.Relayed
    }

    public companion object {
        private const val TYPE_PREF_SHIFT = 24
        private const val LOCAL_PREF_SHIFT = 8
        private const val COMPONENT_BASE = 256
        private const val MAX_LOCAL_PREFERENCE = 65535

        /**
         * The RFC 8445 §5.1.2.1 priority: `2^24·typePref + 2^8·localPref + (256 − componentId)`.
         * [localPreference] (0..65535) breaks ties between candidates of the same type. The result is a
         * 32-bit value carried in a 64-bit [Long] so pair-priority arithmetic (§6.1.2.3) never overflows.
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

        /** A [Host] candidate for [address] (its own base), with the RFC priority filled in. */
        public fun host(
            address: TransportAddress,
            component: ComponentId = ComponentId.Rtp,
            transport: IceTransport = IceTransport.Udp,
            localPreference: Int = MAX_LOCAL_PREFERENCE,
        ): Host =
            Host(
                address = address,
                component = component,
                transport = transport,
                foundation = Foundation.of(CandidateType.Host, address.ip(), serverIp = null, transport = transport),
                priority = computePriority(CandidateType.Host, component, localPreference),
            )
    }
}

/** The IP literal of a [TransportAddress] (IPv4 dotted-quad or the IPv6 form) — used in foundations. */
internal fun TransportAddress.ip(): String = ip.toString()

/**
 * The per-candidate `localPreference` policy (RFC 8445 §5.1.2.2) — the tie-break *within* a candidate
 * type. §5.1.2.2 says this SHOULD prefer IPv6 and be unique per same-type candidate, deferring the
 * family/scope ordering to RFC 8421 → RFC 6724's precedence table.
 *
 * This is a **seam by design** (injectable-ready, kept `internal` for now — see
 * `docs/IPV6_DUAL_STACK_DESIGN.md`): a future `IceConfig` field can swap in family- or interface-steering
 * without touching the gather sites, but no public candidate-priority knob is exposed today (browsers
 * deliberately don't expose one). [Default] implements the RFC 6724 precedence ladder; the low byte
 * carries an [interfaceIndex] so a multi-homed host's same-family candidates get **distinct** preferences.
 */
internal fun interface CandidatePreferencePolicy {
    /** The 0..65535 local preference for a candidate whose base is [ip], gathered on interface [interfaceIndex]. */
    fun localPreference(
        ip: IpAddress,
        interfaceIndex: Int,
    ): Int

    companion object {
        /**
         * RFC 6724 precedence ordering, IPv6-GUA > IPv4 > IPv6-ULA > IPv6-link-local, classified by pure
         * [ULong] shifts on the address (no arrays — directive #1). The family rides the high byte
         * (dominates); the low byte `0xFF − interfaceIndex` keeps same-family multi-homed candidates
         * distinct and deterministic (first-gathered ranks highest).
         */
        val Default =
            CandidatePreferencePolicy { ip, interfaceIndex ->
                val familyPref =
                    when (ip) {
                        is IpAddress.V4 -> FAMILY_PREF_V4
                        is IpAddress.V6 ->
                            when {
                                (ip.hi shr GUA_SHIFT) == GUA_PREFIX -> FAMILY_PREF_V6_GUA // 2000::/3
                                (ip.hi shr ULA_SHIFT) == ULA_PREFIX -> FAMILY_PREF_V6_ULA // fc00::/7
                                (ip.hi shr LINK_LOCAL_SHIFT) == LINK_LOCAL_PREFIX -> FAMILY_PREF_V6_LINK_LOCAL // fe80::/10
                                else -> FAMILY_PREF_V6_GUA // loopback/unspecified/other → treat as globally routable
                            }
                    }
                (familyPref shl INTERFACE_BITS) or (INTERFACE_MASK - (interfaceIndex and INTERFACE_MASK))
            }

        private const val FAMILY_PREF_V6_GUA = 40
        private const val FAMILY_PREF_V4 = 35
        private const val FAMILY_PREF_V6_ULA = 3
        private const val FAMILY_PREF_V6_LINK_LOCAL = 1
        private const val INTERFACE_BITS = 8
        private const val INTERFACE_MASK = 0xFF
        private const val GUA_SHIFT = 61
        private const val GUA_PREFIX = 1uL // 2000::/3 → top 3 bits == 0b001
        private const val ULA_SHIFT = 57
        private const val ULA_PREFIX = 0x7EuL // fc00::/7 → top 7 bits == 0b1111110
        private const val LINK_LOCAL_SHIFT = 54
        private const val LINK_LOCAL_PREFIX = 0x3FAuL // fe80::/10 → top 10 bits == 0b1111111010
    }
}
