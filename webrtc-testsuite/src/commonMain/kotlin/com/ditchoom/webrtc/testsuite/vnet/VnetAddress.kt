@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress

/**
 * The address vocabulary the virtual network straddles at its I/O edge: buffer-flow's [SocketAddress]
 * (host literal + port — the [com.ditchoom.buffer.flow.DatagramChannel] seam) and webrtc-stun's
 * array-free [TransportAddress] (an [IpAddress] + port — every STUN/TURN attribute).
 *
 * **Why these live here and not in `webrtc-ice`:** the production `SocketAddress`↔`TransportAddress`
 * bridge (`com.ditchoom.webrtc.ice.toTransportAddress` / `toSocketAddress`) is `internal` to
 * `webrtc-ice`, so a published `commonMain` testsuite cannot call it. These are a faithful copy of that
 * bridge (IPv4, RFC §1.1), kept private to the vnet. See the module KDoc in [Vnet] for the promotion
 * finding this duplication documents.
 */
internal fun SocketAddress.toTransportAddress(): TransportAddress {
    val octets = host.split(".")
    require(octets.size == IPV4_OCTETS) { "phase-1 vnet addressing is IPv4 (RFC §1.1); got host=$host" }
    val bits =
        octets.fold(0u) { acc, octet ->
            val value = octet.toUIntOrNull()
            require(value != null && value <= MAX_OCTET) { "not an IPv4 literal: $host" }
            (acc shl Byte.SIZE_BITS) or value
        }
    return TransportAddress(IpAddress.V4(bits), port.toUShort())
}

/** The buffer-flow [SocketAddress] for a STUN/TURN [TransportAddress]. IPv4 (see [toTransportAddress]). */
internal fun TransportAddress.toSocketAddress(): SocketAddress =
    when (val addr = ip) {
        is IpAddress.V4 -> SocketAddress.ofLiteral(addr.toString(), port.toInt()) // IpAddress.V4.toString() is dotted-quad
        is IpAddress.V6 -> error("phase-1 vnet addressing is IPv4 (RFC §1.1); got an IPv6 transport address")
    }

/** The IP literal of a [SocketAddress] (the vnet works entirely in literals — no resolution). */
internal val SocketAddress.ip: String get() = host

/** Build a literal IPv4/IPv6 [SocketAddress] for a virtual host — the vnet literal-candidate fast path. */
internal fun vnetAddress(
    ip: String,
    port: Int,
): SocketAddress = SocketAddress.ofLiteral(ip, port)

/** A read-ready buffer of [text]'s UTF-8 bytes — a STUN short-term-credential key or attribute value. */
internal fun utf8Buffer(text: String): ReadBuffer {
    val buffer = BufferFactory.Default.allocate(maxOf(1, text.encodeToByteArray().size), ByteOrder.BIG_ENDIAN)
    buffer.writeString(text, Charset.UTF8)
    buffer.resetForRead()
    return buffer
}

private const val IPV4_OCTETS = 4
private const val MAX_OCTET = 255u
