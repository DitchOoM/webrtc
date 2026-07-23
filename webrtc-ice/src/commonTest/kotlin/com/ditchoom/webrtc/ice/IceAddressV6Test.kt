@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.AddressFamily
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The v6 address bridge at ICE's I/O edge ([toTransportAddress] / [toSocketAddress]) — the two internal
 * converters un-fenced for dual-stack (design note step 3). The key invariant: a v6 [TransportAddress]
 * round-trips through a bare (unbracketed) [SocketAddress] literal without a throw, so every gather/send
 * path works for v6 exactly as it does for v4.
 */
class IceAddressV6Test {
    @Test
    fun v6_socket_literal_converts_to_transport_address() {
        val transport = SocketAddress.ofLiteral("2001:db8::1", 5000).toTransportAddress()
        assertEquals(TransportAddress(IpAddress.V6(0x20010db800000000uL, 1uL), 5000u), transport)
    }

    @Test
    fun v6_transport_address_round_trips_through_socket_address() {
        val original = TransportAddress(IpAddress.V6.parse("2001:db8:a::9")!!, 6000u)
        val socket = original.toSocketAddress()
        assertEquals(AddressFamily.IPv6, socket.family, "the socket literal is v6")
        assertEquals(original, socket.toTransportAddress(), "round-trips equal, no bracket contamination")
    }

    @Test
    fun v6_socket_address_literal_is_unbracketed() {
        // toSocketAddress must render via IpAddress.V6.toString() (bare), not SocketAddress.toString() ([..]).
        val socket = TransportAddress(IpAddress.V6.parse("2001:db8::1")!!, 5000u).toSocketAddress()
        assertTrue('[' !in socket.host && ']' !in socket.host, "host literal is bare: ${socket.host}")
        assertEquals("2001:db8::1", socket.host)
    }

    @Test
    fun embedded_v4_mapped_v6_resolves() {
        val transport = SocketAddress.ofLiteral("::ffff:1.2.3.4", 7000).toTransportAddress()
        assertEquals(TransportAddress(IpAddress.V6(0uL, 0x0000ffff01020304uL), 7000u), transport)
    }

    @Test
    fun v4_path_is_unchanged() {
        val transport = SocketAddress.ofLiteral("10.0.0.1", 4000).toTransportAddress()
        assertEquals(TransportAddress(IpAddress.V4(0x0A000001u), 4000u), transport)
    }
}
