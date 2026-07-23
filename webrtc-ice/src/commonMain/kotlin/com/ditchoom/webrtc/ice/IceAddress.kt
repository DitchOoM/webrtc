@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.AddressFamily
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
 * Dual-stack (RFC 8445): the family is the socket's own [SocketAddress.family] discriminant, so a v4
 * literal takes the dotted-quad fast path and a v6 literal is parsed by the array-free
 * [IpAddress.V6.parse] — the same two [ULong]s the STUN wire codec already carries. The host string
 * always came from [SocketAddress.ofLiteral] (gathering) or an inbound datagram's observed peer, so it
 * is a well-formed literal; a parse failure here is a genuine socket-layer invariant break, not input.
 */
internal fun SocketAddress.toTransportAddress(): TransportAddress =
    when (family) {
        AddressFamily.IPv4 -> {
            val octets = host.split(".")
            require(octets.size == IPV4_OCTETS) { "malformed IPv4 literal: host=$host" }
            // Validate each octet is a 0..255 number so a stray non-v4 literal is a clear rejection, not an
            // uncaught NumberFormatException in the send hot path.
            val bits =
                octets.fold(0u) { acc, octet ->
                    val value = octet.toUIntOrNull()
                    require(value != null && value <= MAX_OCTET) { "not an IPv4 literal: $host" }
                    (acc shl Byte.SIZE_BITS) or value
                }
            TransportAddress(IpAddress.V4(bits), port.toUShort())
        }
        AddressFamily.IPv6 -> {
            val v6 = IpAddress.V6.parse(host) ?: error("malformed IPv6 literal from the socket layer: host=$host")
            TransportAddress(v6, port.toUShort())
        }
    }

/**
 * The buffer-flow [SocketAddress] for a STUN/TURN [TransportAddress]. A v6 address renders through
 * [IpAddress.V6.toString] (canonical RFC 5952, **unbracketed**) so `ofLiteral`'s parser accepts it —
 * `SocketAddress.toString()` would wrap it in `[…]`, which the parser rejects, so we must not use it.
 */
internal fun TransportAddress.toSocketAddress(): SocketAddress =
    when (val addr = ip) {
        is IpAddress.V4 -> SocketAddress.ofLiteral(addr.toString(), port.toInt()) // IpAddress.V4.toString() is dotted-quad
        is IpAddress.V6 -> SocketAddress.ofLiteral(addr.toString(), port.toInt()) // IpAddress.V6.toString() is bare RFC 5952
    }

private const val IPV4_OCTETS = 4
private const val MAX_OCTET = 255u
