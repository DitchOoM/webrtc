package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * T0 for the RFC 8839 §5.1 `candidate` codec: round-trip fidelity per candidate kind, tolerance of the
 * optional `candidate:` prefix, browser-shaped inputs, and typed-reject (null) on malformed / unsupported
 * lines — the trickle boundary must never throw.
 */
class IceCandidateLineTest {
    private fun addr(
        ip: String,
        port: Int,
    ): TransportAddress {
        val octets = ip.split('.').map { it.toUInt() }
        val bits = octets.fold(0u) { acc, o -> (acc shl 8) or o }
        return TransportAddress(IpAddress.V4(bits), port.toUShort())
    }

    @Test
    fun host_round_trips() {
        val host = IceCandidate.host(addr("10.0.0.1", 4000))
        val line = IceCandidateLine.format(host)
        assertTrue(line.startsWith("candidate:"))
        assertTrue(line.contains("typ host"))
        assertEquals(host, IceCandidateLine.parse(line))
    }

    @Test
    fun srflx_round_trips_with_raddr() {
        val srflx =
            IceCandidate.ServerReflexive(
                address = addr("203.0.113.5", 50000),
                base = addr("10.0.0.1", 4000),
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.ServerReflexive, "10.0.0.1", "198.51.100.1", IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp),
                relatedAddress = addr("10.0.0.1", 4000),
            )
        val line = IceCandidateLine.format(srflx)
        assertTrue(line.contains("typ srflx"))
        assertTrue(line.contains("raddr 10.0.0.1 rport 4000"))
        assertEquals(srflx, IceCandidateLine.parse(line))
    }

    @Test
    fun relay_round_trips() {
        val relay =
            IceCandidate.Relayed(
                address = addr("192.0.2.9", 60000),
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.Relayed, "192.0.2.9", "192.0.2.1", IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp),
                relatedAddress = addr("203.0.113.5", 50000),
            )
        assertEquals(relay, IceCandidateLine.parse(IceCandidateLine.format(relay)))
    }

    @Test
    fun accepts_prefixless_value_and_a_browser_shaped_line() {
        val host = IceCandidate.host(addr("10.0.0.1", 4000))
        val value = IceCandidateLine.format(host).removePrefix("candidate:")
        assertEquals(host, IceCandidateLine.parse(value)) // SDP attribute value has no "candidate:" prefix

        // A numeric-foundation, browser-style host line parses (the foundation is any token).
        val browser = "candidate:842163049 1 udp 2122260223 10.0.0.7 55000 typ host"
        val parsed = IceCandidateLine.parse(browser)
        assertTrue(parsed is IceCandidate.Host)
        assertEquals("842163049", parsed.foundation.value)
    }

    @Test
    fun malformed_and_unsupported_lines_reject_to_null() {
        assertNull(IceCandidateLine.parse("")) // empty
        assertNull(IceCandidateLine.parse("candidate:f 1 udp 100 10.0.0.1 4000")) // missing "typ <type>"
        assertNull(IceCandidateLine.parse("candidate:f 1 tcp 100 10.0.0.1 4000 typ host tcptype passive")) // TCP: phase-1 UDP only
        assertNull(IceCandidateLine.parse("candidate:f 1 udp x 10.0.0.1 4000 typ host")) // non-numeric priority
        assertNull(IceCandidateLine.parse("candidate:f 9 udp 100 10.0.0.1 4000 typ host")) // unknown component
        assertNull(IceCandidateLine.parse("candidate:f 1 udp 100 not.an.ip.addr 4000 typ host")) // non-v4 literal
        assertNull(IceCandidateLine.parse("candidate:f 1 udp 100 10.0.0.1 4000 typ srflx")) // srflx without raddr
    }
}
