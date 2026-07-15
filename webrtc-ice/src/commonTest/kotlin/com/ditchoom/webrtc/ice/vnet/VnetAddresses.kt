@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

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
 * Bridges the two address vocabularies the vnet straddles: buffer-flow's [SocketAddress] (a host
 * literal + port, what the [DatagramChannel][com.ditchoom.buffer.flow.DatagramChannel] seam speaks)
 * and webrtc-stun's [TransportAddress] (an array-free [IpAddress] + port, what STUN/TURN attributes
 * carry). The vnet fixtures are IPv4, so these are IPv4-only; an IPv6 literal is a test-authoring bug.
 */
internal fun SocketAddress.toTransportAddress(): TransportAddress {
    val octets = host.split(".")
    require(octets.size == IPV4_OCTETS) { "vnet addresses are IPv4 literals, got $host" }
    val bits = octets.fold(0u) { acc, octet -> (acc shl Byte.SIZE_BITS) or octet.toUInt() }
    return TransportAddress(IpAddress.V4(bits), port.toUShort())
}

/** The vnet [SocketAddress] for a STUN/TURN [TransportAddress]. IPv4-only (see [toTransportAddress]). */
internal fun TransportAddress.toSocketAddress(): SocketAddress =
    when (val addr = ip) {
        is IpAddress.V4 -> vnetAddress(addr.toString(), port.toInt()) // IpAddress.V4.toString() is dotted-quad
        is IpAddress.V6 -> error("the vnet is IPv4-only; got an IPv6 transport address")
    }

/** A read-ready buffer of [text]'s UTF-8 bytes — a STUN short-term-credential key or attribute value. */
internal fun utf8Buffer(text: String): ReadBuffer {
    val buffer = BufferFactory.Default.allocate(text.encodeToByteArray().size, ByteOrder.BIG_ENDIAN)
    buffer.writeString(text, Charset.UTF8)
    buffer.resetForRead()
    return buffer
}

private const val IPV4_OCTETS = 4
