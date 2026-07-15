package com.ditchoom.webrtc.ice

import com.ditchoom.webrtc.stun.IpAddress
import com.ditchoom.webrtc.stun.TransportAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * RFC 8445 arithmetic conformance for the type model — the formulas the whole checklist ordering rests
 * on. Pure and instant (no coroutines): candidate priority (§5.1.2.1), pair priority (§6.1.2.3), and
 * foundation equivalence (§5.1.1.3). These are the invariants a fuzz shrinker leans on, so they get a
 * dedicated guard rather than only being exercised transitively by the connectivity fixtures.
 */
class IcePriorityTest {
    @Test
    fun candidate_priority_matches_rfc_8445_formula() {
        // §5.1.2.1: 2^24·typePref + 2^8·localPref + (256 − component). Host, localPref 65535, component 1.
        assertEquals(2130706431L, IceCandidate.computePriority(CandidateType.Host, ComponentId.Rtp), "host priority")
        assertEquals(1694498815L, IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp), "srflx priority")
        assertEquals(1862270975L, IceCandidate.computePriority(CandidateType.PeerReflexive, ComponentId.Rtp), "prflx priority")
        assertEquals(16777215L, IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp), "relay priority")
    }

    @Test
    fun priority_ordering_is_host_gt_prflx_gt_srflx_gt_relay() {
        val host = IceCandidate.computePriority(CandidateType.Host, ComponentId.Rtp)
        val prflx = IceCandidate.computePriority(CandidateType.PeerReflexive, ComponentId.Rtp)
        val srflx = IceCandidate.computePriority(CandidateType.ServerReflexive, ComponentId.Rtp)
        val relay = IceCandidate.computePriority(CandidateType.Relayed, ComponentId.Rtp)
        assertTrue(host > prflx && prflx > srflx && srflx > relay, "RFC 8445 §5.1.2.2 type-preference order")
    }

    @Test
    fun local_preference_breaks_ties_within_a_type() {
        val preferred = IceCandidate.computePriority(CandidateType.Host, ComponentId.Rtp, localPreference = 65535)
        val secondary = IceCandidate.computePriority(CandidateType.Host, ComponentId.Rtp, localPreference = 100)
        assertTrue(preferred > secondary, "higher local preference wins among same-type candidates")
    }

    @Test
    fun pair_priority_matches_rfc_8445_formula() {
        // §6.1.2.3: 2^32·min(G,D) + 2·max(G,D) + (G>D ? 1 : 0), G = controlling agent's priority.
        val local = candidate(CandidateType.Host, "10.0.0.1")
        val remote = candidate(CandidateType.ServerReflexive, "203.0.113.5")
        val pair = CandidatePair(local, remote)

        val g = local.priority.toULong() // local is controlling
        val d = remote.priority.toULong()
        val expected = (minOf(g, d) shl 32) + (2uL * maxOf(g, d)) + (if (g > d) 1uL else 0uL)
        assertEquals(expected, pair.priority(IceRole.Controlling), "controlling-agent pair priority")

        // The two agents compute the SAME pair priority from opposite roles (RFC 8445 §6.1.2.3 symmetry).
        assertEquals(
            pair.priority(IceRole.Controlling),
            CandidatePair(remote, local).priority(IceRole.Controlled),
            "pair priority is role-symmetric",
        )
    }

    @Test
    fun foundations_are_equal_iff_type_base_and_server_match() {
        val a = Foundation.of(CandidateType.ServerReflexive, "10.0.0.1", serverIp = "203.0.113.2", transport = IceTransport.Udp)
        val sameServer = Foundation.of(CandidateType.ServerReflexive, "10.0.0.1", serverIp = "203.0.113.2", transport = IceTransport.Udp)
        val otherServer = Foundation.of(CandidateType.ServerReflexive, "10.0.0.1", serverIp = "203.0.113.9", transport = IceTransport.Udp)
        assertEquals(a, sameServer, "same (type, base, server, transport) ⇒ same foundation")
        assertNotEquals(a, otherServer, "a different server ⇒ a different foundation")
    }

    private fun candidate(
        type: CandidateType,
        ip: String,
    ): IceCandidate {
        val octets = ip.split(".").map { it.toUInt() }
        val bits = octets.fold(0u) { acc, octet -> (acc shl 8) or octet }
        val address = TransportAddress(IpAddress.V4(bits), 5000u)
        val foundation = Foundation.of(type, ip, serverIp = null, transport = IceTransport.Udp)
        val priority = IceCandidate.computePriority(type, ComponentId.Rtp)
        return when (type) {
            CandidateType.Host -> IceCandidate.Host(address, ComponentId.Rtp, IceTransport.Udp, foundation, priority)
            CandidateType.ServerReflexive ->
                IceCandidate.ServerReflexive(
                    address,
                    address,
                    ComponentId.Rtp,
                    IceTransport.Udp,
                    foundation,
                    priority,
                    address,
                )
            CandidateType.PeerReflexive ->
                IceCandidate.PeerReflexive(
                    address,
                    address,
                    ComponentId.Rtp,
                    IceTransport.Udp,
                    foundation,
                    priority,
                    address,
                )
            CandidateType.Relayed -> IceCandidate.Relayed(address, ComponentId.Rtp, IceTransport.Udp, foundation, priority, address)
        }
    }
}
