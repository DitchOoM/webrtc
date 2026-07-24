@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress

/*
 * Routed-IPv6 fabrics — the virtual-network analogue of the harness's IPv6 lanes, which do NOT NAT66.
 * Over routed IPv6 there is no address translation: a host keeps its ULA/GUA source address and the
 * "NAT" box is a pure filtering router (the RFC 4787 §5 filtering half, without the §4 mapping half —
 * NatBox is the v4 story, this file is the v6 story). These fabrics let the deterministic commonTest
 * suite reproduce, under `runTest` virtual time on every platform (Apple/iOS/Node included), the exact
 * traversal outcomes the Linux-only Docker L2 matrix proves over real routed IPv6:
 *
 *  - RoutedFilter — a stateful filtering router (full-cone / address- / port-restricted). Hole-punching
 *    still connects two peers directly over v6, exactly as the harness full-cone / port-restricted lanes
 *    do on the v6 family (no relay needed — the return path opens once each side has sent out).
 *  - RoutedFirewall — the harness firewall-relay6 lane's V6_FORCE_RELAY rule: an administrative firewall
 *    that drops every WAN→LAN datagram except from the STUN/TURN server, so direct and server-reflexive
 *    checks are silently dropped and ICE must discover it has to fall back to the relay (network-forced,
 *    unlike policy-forced relay-only or mapping-defeated symmetric→relay).
 *  - FamilyFabric — dispatches by the destination's address family so one vnet can carry a broken/filtered
 *    v6 path and a working v4 path at once (the dual-stack happy-eyeballs fallback).
 *
 * All three wrap a base [Fabric] (default [DirectFabric]) and never rewrite an address — routing is by
 * literal, so a fixture reads its topology straight off the peers' real IPs.
 */

// A stable map key for a transport address (v6 IPs contain ':', so join with a separator that can't collide).
private fun SocketAddress.filterId(): String = "$ip#$port"

/**
 * A **stateful routed filtering router** (RFC 4787 §5), no NAT. An inbound datagram to a LAN host is
 * admitted only if that host has previously sent outbound to the source, at the granularity of
 * [filtering] — the v6 analogue of [NatBox]'s filter, minus the address rewrite. Endpoint-independent
 * filtering opens the host to anyone once it has sent a single packet; address- and port-dependent
 * filtering restrict the return path to the contacted IP / IP:port. Traffic that does not target a LAN
 * host (host→server, server→server) is unfiltered. Because both peers punch, a two-peer echo connects
 * **directly** over v6 under every [filtering] mode — the relay is never needed here (that is
 * [RoutedFirewall]'s job).
 */
internal class RoutedFilter(
    private val lanPrefixes: List<String>,
    private val filtering: Filtering,
    private val base: Fabric = DirectFabric,
) : Fabric {
    // For each LAN host (by transport address), the set of remotes it has sent to — the opened return paths.
    private val opened = HashMap<String, MutableSet<String>>()

    override fun forward(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
        net: Vnet,
    ) {
        val fromLan = lanPrefixes.any { from.ip.startsWith(it) }
        val toLan = lanPrefixes.any { to.ip.startsWith(it) }
        val intraLan = lanPrefixes.any { from.ip.startsWith(it) && to.ip.startsWith(it) }

        // An outbound packet from a LAN host opens the return path per the filtering granularity.
        if (fromLan) opened.getOrPut(from.filterId()) { HashSet() }.add(returnKey(to))

        // Filter inbound to a LAN host from off-LAN (a different segment / the public internet);
        // intra-LAN and non-LAN destinations pass unfiltered.
        if (toLan && !intraLan) {
            val permits = opened[to.filterId()] ?: return // never sent out → nothing is open, drop
            val admitted =
                when (filtering) {
                    Filtering.EndpointIndependent -> permits.isNotEmpty()
                    Filtering.AddressDependent -> from.ip in permits
                    Filtering.AddressAndPortDependent -> from.filterId() in permits
                }
            if (!admitted) return
        }
        base.forward(from, to, payload, net)
    }

    // What an outbound datagram to [destination] opens, keyed to match [returnKey]'s inbound check.
    private fun returnKey(destination: SocketAddress): String =
        when (filtering) {
            Filtering.EndpointIndependent -> WILDCARD
            Filtering.AddressDependent -> destination.ip
            Filtering.AddressAndPortDependent -> destination.filterId()
        }

    private companion object {
        const val WILDCARD = "*"
    }
}

/**
 * The harness `firewall-relay6` lane, as a fabric: an administrative firewall (the `V6_FORCE_RELAY`
 * ip6tables rule) that drops every datagram destined to a [lanPrefixes] host unless its source is an
 * [allowedSources] infra address (the STUN/TURN server). Unlike [RoutedFilter] this is **not** stateful
 * — a peer's reply is dropped even after the target has punched — so direct and server-reflexive
 * host↔host checks can never complete and ICE is *forced to discover* the relay. The relay path itself
 * is unaffected: the client reaches the TURN server (a non-LAN destination), and relayed traffic
 * arrives from the server's IP, which is allow-listed.
 */
internal class RoutedFirewall(
    private val lanPrefixes: List<String>,
    private val allowedSources: Set<String>,
    private val base: Fabric = DirectFabric,
) : Fabric {
    override fun forward(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
        net: Vnet,
    ) {
        val toLan = lanPrefixes.any { to.ip.startsWith(it) }
        val intraLan = lanPrefixes.any { from.ip.startsWith(it) && to.ip.startsWith(it) }
        if (toLan && !intraLan && from.ip !in allowedSources) return // WAN→LAN drop except from infra
        base.forward(from, to, payload, net)
    }
}

/**
 * Routes each datagram to a per-family sub-[Fabric] by the destination's address family, so a single
 * [Vnet] can model a dual-stack host whose IPv6 path is broken/filtered while its IPv4 path works (or
 * vice-versa) — the substrate for the happy-eyeballs fallback fixtures. Selection is on the literal
 * (a ':' in the destination IP ⇒ IPv6), matching how the rest of the vnet works entirely in literals.
 */
internal class FamilyFabric(
    private val v4: Fabric,
    private val v6: Fabric,
) : Fabric {
    override fun forward(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
        net: Vnet,
    ) {
        val fabric = if (':' in to.ip) v6 else v4
        fabric.forward(from, to, payload, net)
    }
}
