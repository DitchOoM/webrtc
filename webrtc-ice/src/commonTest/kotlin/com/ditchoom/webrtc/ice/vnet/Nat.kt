@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress

/**
 * How a NAT assigns the **external mapping** for an outbound datagram (RFC 4787 §4.1). The mapping
 * granularity is what a peer's srflx candidate can and cannot predict: a cone NAT reuses one external
 * port for every destination (so a srflx address learned via STUN is reachable by anyone), whereas a
 * symmetric NAT allocates a fresh port per destination (so a srflx address is useless to a third
 * party — the reason symmetric↔symmetric can only meet on a relay).
 */
internal enum class Mapping {
    /** One external port per internal source, shared across all destinations (RFC 4787 EIM). */
    EndpointIndependent,

    /** One external port per (internal source, destination IP). */
    AddressDependent,

    /** A fresh external port per (internal source, destination IP **and** port) — symmetric. */
    AddressAndPortDependent,
}

/**
 * Which return datagrams a NAT lets back in through an existing mapping (RFC 4787 §5). Filtering is
 * orthogonal to [Mapping]: it decides whether an inbound packet from a remote endpoint is delivered to
 * the internal host, based on whether — and how specifically — the host has previously sent out to
 * that remote.
 */
internal enum class Filtering {
    /** Any remote may use the mapping once it exists (RFC 4787 EIF) — full-cone behavior. */
    EndpointIndependent,

    /** Only a remote **IP** the host has sent to may reply (address-restricted cone). */
    AddressDependent,

    /** Only the exact remote **IP:port** the host has sent to may reply (port-restricted / symmetric). */
    AddressAndPortDependent,
}

/**
 * A NAT behavior profile (RFC 4787): a [Mapping] × [Filtering] pair (plus optional hairpinning). The
 * four canonical profiles are the named constants — the classic taxonomy (RFC 3489 cone/symmetric)
 * expressed in RFC 4787's precise two-axis vocabulary, which is what actually determines ICE outcomes.
 */
internal data class NatProfile(
    val mapping: Mapping,
    val filtering: Filtering,
    /** Whether two hosts behind this NAT can reach each other via its external address (RFC 4787 §6). */
    val hairpin: Boolean = true,
) {
    companion object {
        /** Endpoint-independent mapping + filtering: the most permissive NAT (RFC 3489 "full cone"). */
        val FullCone = NatProfile(Mapping.EndpointIndependent, Filtering.EndpointIndependent)

        /** EIM + address-dependent filtering (RFC 3489 "address-restricted cone"). */
        val AddressRestrictedCone = NatProfile(Mapping.EndpointIndependent, Filtering.AddressDependent)

        /** EIM + address-and-port-dependent filtering (RFC 3489 "port-restricted cone"). */
        val PortRestrictedCone = NatProfile(Mapping.EndpointIndependent, Filtering.AddressAndPortDependent)

        /** Per-destination mapping + strict filtering (RFC 3489 "symmetric") — defeats srflx. */
        val Symmetric = NatProfile(Mapping.AddressAndPortDependent, Filtering.AddressAndPortDependent)
    }
}

/**
 * One NAT box, translating between a private segment (hosts whose IP starts with [privatePrefix]) and
 * the public internet via [publicIp], per [profile]. Pure and deterministic: external ports come from
 * a monotonic counter (real NATs randomize; the vnet wants replay), and every mapping/filter decision
 * is a table lookup on the virtual clock. Not thread-safe by design — the vnet is single-threaded
 * under `runTest`.
 */
internal class NatBox(
    val publicIp: String,
    val privatePrefix: String,
    val profile: NatProfile,
    firstPort: Int = FIRST_EPHEMERAL_PORT,
) {
    private var nextPort = firstPort
    private val externalPortByKey = HashMap<String, Int>()
    private val internalByExternalPort = HashMap<Int, SocketAddress>()
    private val permittedRemotes = HashMap<Int, MutableSet<String>>()

    /** True iff [address] is a host on this NAT's private segment. */
    fun owns(address: SocketAddress): Boolean = address.ip.startsWith(privatePrefix)

    /** True iff [address] is one of this NAT's live external mapped transport addresses. */
    fun hasExternalPort(address: SocketAddress): Boolean = address.ip == publicIp && address.port in internalByExternalPort

    /**
     * The external transport address an outbound datagram [internal]→[destination] leaves from. Creates
     * the mapping on first use (per the [Mapping] granularity) and records the return permission (per
     * the [Filtering] granularity), so a later [mapInbound] from [destination] is admitted.
     */
    fun mapOutbound(
        internal: SocketAddress,
        destination: SocketAddress,
    ): SocketAddress {
        val key =
            when (profile.mapping) {
                Mapping.EndpointIndependent -> internal.toString()
                Mapping.AddressDependent -> "$internal->${destination.ip}"
                Mapping.AddressAndPortDependent -> "$internal->${destination.ip}:${destination.port}"
            }
        val port =
            externalPortByKey.getOrPut(key) {
                val assigned = nextPort++
                internalByExternalPort[assigned] = internal
                assigned
            }
        permittedRemotes.getOrPut(port) { HashSet() }.add(filterKey(destination))
        return vnetAddress(publicIp, port)
    }

    /**
     * The internal host an inbound datagram from [remote] to external [external] is delivered to, or
     * null if no such mapping exists or the [Filtering] rule rejects [remote] (it has never been sent
     * to through this mapping). Rejection is a silent drop, exactly as a real NAT discards it.
     */
    fun mapInbound(
        remote: SocketAddress,
        external: SocketAddress,
    ): SocketAddress? {
        val internal = internalByExternalPort[external.port] ?: return null
        val permitted = permittedRemotes[external.port] ?: return null
        val admitted =
            when (profile.filtering) {
                Filtering.EndpointIndependent -> permitted.isNotEmpty()
                Filtering.AddressDependent -> remote.ip in permitted
                Filtering.AddressAndPortDependent -> "${remote.ip}:${remote.port}" in permitted
            }
        return if (admitted) internal else null
    }

    private fun filterKey(destination: SocketAddress): String =
        when (profile.filtering) {
            Filtering.EndpointIndependent -> WILDCARD
            Filtering.AddressDependent -> destination.ip
            Filtering.AddressAndPortDependent -> "${destination.ip}:${destination.port}"
        }

    companion object {
        /** IANA ephemeral range floor (RFC 6335) — where the deterministic port counter starts. */
        const val FIRST_EPHEMERAL_PORT = 49152
        private const val WILDCARD = "*"
    }
}

/**
 * The internetwork [Fabric] that layers a set of [NatBox]es over a flat public segment. It classifies
 * every datagram and routes it faithfully:
 *
 *  - **outbound** from a private host → its NAT rewrites the source to the external mapping;
 *  - **intra-LAN** between two hosts on the same segment → delivered directly (no NAT);
 *  - **inbound** to a NAT's external port → filtered, then translated to the internal host;
 *  - **cross-private** to a *different* segment's private address → **unreachable** (dropped): there is
 *    no route between two private LANs except through the public internet, which is exactly what forces
 *    symmetric↔symmetric peers onto a relay;
 *  - **public** (a STUN/TURN server) → delivered on the public segment with the translated source.
 *
 * Wrap this in [Impairment] to add loss/reorder/dup/delay — impairment sits outside NAT so each
 * datagram is impaired once end-to-end, then translated.
 */
internal class Nat(
    private val boxes: List<NatBox>,
) : Fabric {
    override fun forward(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
        net: Vnet,
    ) {
        val outBox = boxes.firstOrNull { it.owns(from) }
        val observedSource = outBox?.mapOutbound(from, to) ?: from

        // Intra-LAN: same private segment, delivered directly with the real private source.
        if (outBox != null && outBox.owns(to)) {
            net.deliver(to, from, payload)
            return
        }

        val inBox = boxes.firstOrNull { it.hasExternalPort(to) }
        if (inBox != null) {
            if (inBox === outBox && !inBox.profile.hairpin) return
            val internalDest = inBox.mapInbound(observedSource, to) ?: return
            net.deliver(internalDest, observedSource, payload)
            return
        }

        // A different segment's private address has no public route — the relay-forcing drop.
        if (boxes.any { it.owns(to) }) return

        // A public address (server): delivered with the (possibly translated) source.
        net.deliver(to, observedSource, payload)
    }
}
