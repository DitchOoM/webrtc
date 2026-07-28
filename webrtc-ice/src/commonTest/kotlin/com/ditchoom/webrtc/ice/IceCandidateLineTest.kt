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
        assertNull(IceCandidateLine.parse("candidate:f 1 udp 100 not.an.ip.addr 4000 typ host")) // non-IP literal
        assertNull(IceCandidateLine.parse("candidate:f 1 udp 100 2001:db8::1::2 4000 typ host")) // malformed v6 literal
        assertNull(IceCandidateLine.parse("candidate:f 1 udp 100 10.0.0.1 4000 typ srflx")) // srflx without raddr
    }

    private fun v6Addr(
        ip: String,
        port: Int,
    ): TransportAddress = TransportAddress(IpAddress.V6.parse(ip)!!, port.toUShort())

    @Test
    fun ipv6_host_round_trips_unbracketed() {
        val host = IceCandidate.host(v6Addr("2001:db8::1", 4000))
        val line = IceCandidateLine.format(host)
        // RFC 8839 §5.1: the connection-address is the raw literal — no brackets on the wire.
        assertTrue(line.contains("2001:db8::1 4000"), "unbracketed v6 connection-address: $line")
        assertTrue(host.address.ip is IpAddress.V6)
        assertEquals(host, IceCandidateLine.parse(line))
    }

    @Test
    fun ipv6_srflx_round_trips_with_v6_raddr() {
        val srflx =
            IceCandidate.ServerReflexive(
                address = v6Addr("2001:db8:a::5", 50000),
                base = v6Addr("2001:db8:a::1", 4000),
                component = ComponentId.Rtp,
                transport = IceTransport.Udp,
                foundation = Foundation.of(CandidateType.ServerReflexive, "2001:db8:a::1", "2001:db8:ffff::1", IceTransport.Udp),
                priority = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp),
                relatedAddress = v6Addr("2001:db8:a::1", 4000),
            )
        val line = IceCandidateLine.format(srflx)
        assertTrue(line.contains("raddr 2001:db8:a::1 rport 4000"), "v6 raddr tail: $line")
        val parsed = IceCandidateLine.parse(line)
        assertEquals(srflx, parsed)
        assertTrue((parsed as IceCandidate.ServerReflexive).relatedAddress.ip is IpAddress.V6)
    }

    // ---- RFC 8838 §3.1: the generation tag on the line ----------------------------------------------

    @Test
    fun a_line_carries_no_generation_unless_one_is_asked_for() {
        // The compatibility floor. Every peer that predates the tag emits and expects exactly this line,
        // so the default has to be byte-identical to what this codec produced before the tag existed.
        val host = IceCandidate.host(addr("10.0.0.1", 4000))
        assertEquals("candidate:${host.foundation.value} 1 udp ${host.priority} 10.0.0.1 4000 typ host", IceCandidateLine.format(host))
        assertEquals(CandidateGeneration.Untagged, parsedGeneration(IceCandidateLine.format(host)))
    }

    @Test
    fun the_generation_tag_round_trips_as_a_ufrag_extension_attribute() {
        val host = IceCandidate.host(addr("10.0.0.1", 4000))
        val line = IceCandidateLine.format(host, CandidateGeneration.Tagged(Ufrag("4ZcD")))
        assertTrue(line.endsWith(" ufrag 4ZcD"), "the tag rides as an RFC 8839 §5.1 extension attribute: $line")
        assertEquals(host, IceCandidateLine.parse(line), "and does not disturb the candidate itself")
        assertEquals(CandidateGeneration.Tagged(Ufrag("4ZcD")), parsedGeneration(line))
    }

    @Test
    fun the_tag_survives_the_raddr_tail_and_other_extension_attributes() {
        // A libwebrtc-shaped line: raddr/rport, then `generation`, `ufrag` and `network-cost` in the
        // extension tail. The tag has to be found past all of it, or a Chrome candidate arrives untagged.
        val line =
            "candidate:842163049 1 udp 1677729535 203.0.113.5 50633 typ srflx raddr 10.0.0.7 rport 55000 " +
                "generation 0 ufrag EWlB network-cost 999"
        assertEquals(CandidateGeneration.Tagged(Ufrag("EWlB")), parsedGeneration(line))
        assertTrue(IceCandidateLine.parse(line) is IceCandidate.ServerReflexive, "the candidate still parses: $line")
    }

    @Test
    fun an_extension_attribute_whose_value_is_ufrag_is_not_a_tag() {
        // The trap a bare indexOf("ufrag") falls into. Extension-attribute values are arbitrary text, so
        // one that happens to read "ufrag" would be mistaken for the attribute name and the token after it
        // for a generation — routing a perfectly good candidate into the hold buffer, where it would wait
        // for a generation nobody will ever signal.
        val line = "candidate:f 1 udp 100 10.0.0.1 4000 typ host network-id ufrag"
        assertEquals(CandidateGeneration.Untagged, parsedGeneration(line))

        // …and the same word appearing as a *value* before a real tag must not shadow it.
        val shadowed = "candidate:f 1 udp 100 10.0.0.1 4000 typ host network-id ufrag ufrag abcd"
        assertEquals(CandidateGeneration.Tagged(Ufrag("abcd")), parsedGeneration(shadowed))
    }

    @Test
    fun a_value_less_or_empty_ufrag_attribute_is_untagged_not_a_reject() {
        // A malformed optional attribute is not a reason to throw a usable candidate away (T0): the typed
        // answer for "the tag is unreadable" is "there is no tag", which routes to the current generation.
        val trailing = "candidate:f 1 udp 100 10.0.0.1 4000 typ host ufrag"
        assertEquals(CandidateGeneration.Untagged, parsedGeneration(trailing))
        assertTrue(IceCandidateLine.parse(trailing) is IceCandidate.Host, "and the candidate still parses")
    }

    @Test
    fun an_mdns_host_candidate_carries_its_generation_too() {
        // The `.local` path resolves asynchronously, so it is the one most likely to arrive late — which
        // makes it the one that most needs to say which generation it belongs to.
        val line = "candidate:1 1 udp 2122260223 abcd-ef01.local 55000 typ host ufrag 4ZcD"
        val parsed = IceCandidateLine.parseLine(line)
        assertTrue(parsed is CandidateParse.MdnsHost)
        assertEquals(CandidateGeneration.Tagged(Ufrag("4ZcD")), parsed.generation)
    }

    private fun parsedGeneration(line: String): CandidateGeneration =
        when (val parsed = IceCandidateLine.parseLine(line)) {
            is CandidateParse.Parsed -> parsed.generation
            is CandidateParse.MdnsHost -> parsed.generation
            CandidateParse.Reject -> error("expected a parseable candidate line: $line")
        }
}
