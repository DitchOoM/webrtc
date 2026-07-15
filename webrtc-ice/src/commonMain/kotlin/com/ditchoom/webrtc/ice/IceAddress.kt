@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress

/**
 * Bridges the two address vocabularies ICE straddles at its I/O edge: buffer-flow's [SocketAddress]
 * (host literal + port, what the [DatagramChannel][com.ditchoom.buffer.flow.DatagramChannel] seam and
 * the gathering drivers speak) and webrtc-stun's array-free [TransportAddress] (an [IpAddress] + port,
 * what the sans-io core and every STUN/TURN attribute carry). The **core never touches these** — it is
 * pure [TransportAddress]; only the driver converts, exactly once, per datagram at the boundary.
 *
 * Phase-1 gathering is IPv4 (RFC §1.1); an IPv6 literal is converted structurally where the platform
 * hands one back, but the vnet fixtures are v4. IPv6 host-string parsing is a follow-up (the dotted
 * literal fast path below covers v4 and the socket layer resolves the rest).
 */
internal fun SocketAddress.toTransportAddress(): TransportAddress {
    val octets = host.split(".")
    require(octets.size == IPV4_OCTETS) { "phase-1 ICE gathering is IPv4 (RFC §1.1); got host=$host" }
    val bits = octets.fold(0u) { acc, octet -> (acc shl Byte.SIZE_BITS) or octet.toUInt() }
    return TransportAddress(IpAddress.V4(bits), port.toUShort())
}

/** The buffer-flow [SocketAddress] for a STUN/TURN [TransportAddress]. IPv4 (see [toTransportAddress]). */
internal fun TransportAddress.toSocketAddress(): SocketAddress =
    when (val addr = ip) {
        is IpAddress.V4 -> SocketAddress.ofLiteral(addr.toString(), port.toInt()) // IpAddress.V4.toString() is dotted-quad
        is IpAddress.V6 -> error("phase-1 ICE gathering is IPv4 (RFC §1.1); got an IPv6 transport address")
    }

private const val IPV4_OCTETS = 4
