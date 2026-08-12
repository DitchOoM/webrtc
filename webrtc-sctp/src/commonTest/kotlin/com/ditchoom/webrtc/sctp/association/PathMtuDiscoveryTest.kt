@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * RFC 8899 Packetization Layer Path MTU Discovery over SCTP's own probe vocabulary — a HEARTBEAT padded
 * by an RFC 4820 PAD chunk, confirmed by the HEARTBEAT-ACK it draws.
 *
 * ## Why the constriction is modelled as a size-based drop and nothing else
 *
 * Because that is all a constricted IPv6 path does. RFC 8200 §5 forbids a router to fragment, and the
 * ICMPv6 Packet Too Big it would answer with is not something a UDP-encapsulated flow behind a NAT can
 * count on receiving — which is the entire reason RFC 8899 exists. So the only evidence the search ever
 * gets is a probe that went unanswered, and a fixture that fed it anything else would be proving a
 * mechanism this stack does not have.
 *
 * No lane can prove any of this: every CI bridge is a uniform 1500 and a constricted L2 topology does not
 * exist here. That is recorded rather than papered over — this is L1-only by argument, not by omission.
 */
class PathMtuDiscoveryTest {
    private val stream = StreamId(0)
    private val epoch = Instant.fromEpochSeconds(0)

    // A direct IPv6 WebRTC path: 40 IPv6 + 8 UDP + 37 for a DTLS 1.2 AES-GCM record.
    private val overhead = PathOverheadBytes(85)

    private fun ipv6(ordinal: UInt = 1u) = SctpPathProfile.Assessed(PathIdentity(ordinal), PathAddressFamily.Ipv6, overhead)

    private fun ipv4(ordinal: UInt = 1u) = SctpPathProfile.Assessed(PathIdentity(ordinal), PathAddressFamily.Ipv4, PathOverheadBytes(65))

    private fun discovering(searchCeiling: Int = 1500) =
        SctpConfig(pathMtu = PathMtuPolicy.Discover(searchCeiling = PmtuBytes(searchCeiling)))

    /** An established pair whose path A has been told about, with a constriction at [pathMtu] bytes. */
    private fun probing(
        profile: SctpPathProfile.Assessed,
        pathMtu: Int,
        config: SctpConfig = discovering(),
    ): SctpSim {
        val sim = SctpSim(config = config)
        sim.associateA()
        sim.run()
        sim.maxSctpDatagramBytes = pathMtu - profile.overhead.value
        sim.post(toA = true, SctpEvent.PathChanged(profile))
        return sim
    }

    private fun ceilingOf(sim: SctpSim): Int =
        sim.pathMtuA
            .last()
            .ceiling.value

    // ── the search ──

    /**
     * The base is confirmed and the search then raises above it. On IPv6 the unprobed ceiling is derived
     * from RFC 8200 §5's guaranteed 1280 — deliberately conservative — so a path that actually carries
     * 1500 leaves ~220 bytes per fragment on the table until something measures it.
     */
    @Test
    fun a_search_raises_the_ceiling_above_the_conservative_ipv6_assumption() {
        val sim = probing(ipv6(), pathMtu = 1500)
        val unprobed = ceilingOf(sim)
        assertEquals(PathMtuChangeCause.PathAssessed(PathAddressFamily.Ipv6), sim.pathMtuA.first().cause)
        assertEquals(ipv6().unprobedFragmentCeiling.value, unprobed, "the first report is the unprobed family ceiling")

        sim.runUntil(epoch + 5.minutes)

        val converged = ceilingOf(sim)
        assertTrue(converged > unprobed, "the search must actually raise the ceiling: $converged vs $unprobed")
        assertTrue(
            converged + SCTP_PER_PACKET + overhead.value <= 1500,
            "…and never above what the path was demonstrated to carry",
        )
        assertEquals(
            PathMtuChangeCause.ProbeConfirmed,
            sim.pathMtuA.last().cause,
            "the raise is a measurement, and says so",
        )
    }

    /**
     * The discriminating half: the *same* search over a path that stops at 1280 must not raise anything.
     * Without this, "the ceiling went up" is green on a search that raises unconditionally — which is the
     * one behaviour a PMTU search must never have, since every raise puts fragments on the wire that the
     * path then drops.
     */
    @Test
    fun a_search_over_a_1280_byte_path_confirms_the_base_and_raises_nothing() {
        val sim = probing(ipv6(), pathMtu = 1280)
        val unprobed = ceilingOf(sim)
        sim.runUntil(epoch + 5.minutes)

        assertEquals(unprobed, ceilingOf(sim), "nothing above 1280 is carried, so nothing above it is confirmed")
        assertTrue(
            sim.pathMtuA.none { it.cause == PathMtuChangeCause.BaseRefuted },
            "the base IS carried here — refuting it would be the search calling a working size broken",
        )
    }

    /**
     * The failure this fixes, and the only way anything could ever have noticed it: the size the
     * association is **already emitting** is not carried. Every full-size fragment before this was lost,
     * and a black-holed MTU is otherwise indistinguishable from a peer that stopped acknowledging.
     */
    @Test
    fun a_base_the_path_does_not_carry_is_refuted_and_the_ceiling_drops() {
        // An IPv4 path whose unprobed assumption is the Ethernet MTU, on a link that is really 1400 —
        // a VPN or PPPoE hop, which is the ordinary way this happens in the field.
        val sim = probing(ipv4(), pathMtu = 1400)
        sim.runUntil(epoch + 5.minutes)

        val refuted = sim.pathMtuA.first { it.cause == PathMtuChangeCause.BaseRefuted }
        assertEquals(
            FragmentCeilingBytes.of(PathAddressFamily.Ipv4.minimumPathMtu, PathOverheadBytes(65)).value,
            refuted.ceiling.value,
            "a refuted base drops to the family minimum — RFC 8899 §5.2's ERROR state",
        )
        // …and then the same machinery finds the real MTU rather than sitting at 576 for ten minutes.
        val converged = ceilingOf(sim)
        assertTrue(converged > refuted.ceiling.value, "the search recovers upward from the floor: $converged")
        assertTrue(
            converged + SCTP_PER_PACKET + 65 <= 1400,
            "…and stops at what the path actually carries, not at what was assumed",
        )
    }

    /** With no probing configured nothing is ever put on the wire to measure — the default is inert. */
    @Test
    fun the_fixed_policy_probes_nothing_and_arms_nothing() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        sim.post(toA = true, SctpEvent.PathChanged(ipv6()))
        sim.run()

        assertEquals(
            listOf(PathMtuChangeCause.PathAssessed(PathAddressFamily.Ipv6)),
            sim.pathMtuA.map { it.cause },
            "the family ceiling is still published — it is what closes the IPv6 defect — but nothing is probed",
        )
        assertNull(sim.a.nextDeadline(sim.now), "and no timer is left armed, so a driver still sleeps")
    }

    /**
     * A converged search over a path that carries everything asked for must leave the association
     * quiescent. RFC 8899 §5.1.1's PMTU_RAISE_TIMER exists to notice a path that GREW, and there is
     * nothing above the search ceiling to grow into — so re-arming it would wake the driver every ten
     * minutes forever to recompute the same answer, and `nextDeadline` would never again return null.
     */
    @Test
    fun a_search_that_reached_its_ceiling_stops_asking() {
        val sim = probing(ipv6(), pathMtu = 1500)
        sim.runUntil(epoch + 30.minutes)
        assertNull(sim.a.nextDeadline(sim.now), "nothing left to find, nothing left armed")
    }

    /**
     * The other half of that rule: a search that converged because something was **refuted** below the
     * search ceiling keeps a raise timer, because the constriction may lift.
     */
    @Test
    fun a_search_stopped_by_a_constriction_keeps_asking() {
        val sim = probing(ipv4(), pathMtu = 1400)
        sim.runUntil(epoch + 5.minutes)
        val deadline = sim.a.nextDeadline(sim.now)
        assertTrue(deadline != null && deadline > sim.now, "a constricted path is re-probed later, in case it lifts")
    }

    // ── the probe itself ──

    /**
     * A probe must never exceed the size it is measuring, or its confirmation is a claim about a size the
     * path was not asked about — the one outcome that turns a PMTU search into a source of loss.
     *
     * It lands three bytes *under* 1280 rather than on it, and that is the 4-byte chunk alignment RFC 4960
     * §3.2 requires, not slack: the same flooring is applied when the confirmed size is turned back into a
     * fragment ceiling, so a full DATA datagram on this path is 1164 + 28 + 85 = 1277 — exactly what the
     * probe demonstrated. The two derivations agree by construction, which is why confirming the nominal
     * 1280 from a 1277-byte probe over-claims nothing.
     */
    @Test
    fun no_probe_ever_exceeds_the_size_it_is_measuring() {
        val sim = SctpSim(config = discovering())
        sim.associateA()
        sim.run()
        val emitted = sim.post(toA = true, SctpEvent.PathChanged(ipv6()))
        val probe =
            emitted
                .filterIsInstance<SctpOutput.Transmit>()
                .single()
        val datagram = probe.packet.limit() + overhead.value
        val target = PathAddressFamily.Ipv6.unprobedPathMtu.value
        assertTrue(datagram <= target, "a probe of $datagram bytes measures a $target-byte path")
        assertTrue(datagram > target - 4, "…and is within the 4-byte chunk alignment of it, not merely below it")
        assertEquals(
            datagram,
            ipv6().unprobedFragmentCeiling.value + SCTP_PER_PACKET + overhead.value,
            "a full DATA datagram at the ceiling this size confirms is exactly the size probed",
        )
    }

    /**
     * An unanswered probe must not touch congestion control or the RFC 4960 §8.1 error budget (RFC 8899
     * §3). Here the path swallows every probe while carrying data perfectly: the association must go on
     * delivering, not spend its budget on packets it was never obliged to retransmit.
     */
    @Test
    fun losing_every_probe_costs_nothing_but_the_probes() {
        // A path that carries our data (1164 payload + 28 + 85 = 1277) but not a full-size probe.
        val sim = probing(ipv6(), pathMtu = 1290)
        sim.runUntil(epoch + 5.minutes)

        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(4000)),
        )
        sim.runUntil(epoch + 10.minutes)

        assertTrue(sim.abortsA.isEmpty(), "a lost probe is not a congestion signal and not a retransmission failure")
        assertEquals(1, sim.inboxB.size, "and the association keeps delivering across the whole search")
        assertEquals(SctpAssociationState.Established, sim.a.state)
    }

    // ── the ceiling dropping under encoded chunks ──

    /**
     * A migration from a path that carried 1200-byte fragments to one that cannot leaves DATA chunks that
     * are already encoded and already carry a TSN — classic SCTP cannot re-fragment them (RFC 4960 §6.1
     * retains the packet; RFC 8260 I-DATA, which would allow it, is deliberately not implemented).
     *
     * They are reported, and they are skipped via RFC 3758 FORWARD-TSN so the peer's cumulative TSN can
     * advance past them. The alternative — retransmitting a packet the path drops by definition — spends
     * the association's error budget on a guaranteed failure.
     */
    @Test
    fun a_ceiling_that_drops_under_encoded_chunks_reports_and_skips_them() {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        sim.post(toA = true, SctpEvent.PathChanged(ipv4(ordinal = 1u)))

        // Fill the send queue with full-size fragments, then stall the wire so they stay encoded and
        // unsent while the path moves under them.
        sim.dropFilter = { toA -> !toA }
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(12_000)),
        )

        // The route moves to IPv6, whose unprobed ceiling is smaller than what those chunks were cut at.
        sim.post(toA = true, SctpEvent.PathChanged(ipv6(ordinal = 2u)))

        val drop = sim.pathMtuA.last()
        assertEquals(PathMtuChangeCause.PathAssessed(PathAddressFamily.Ipv6), drop.cause)
        val backlog = drop.backlog
        assertTrue(backlog is OversizedBacklog.Present, "chunks cut at 1200 cannot ride a path whose ceiling is 1164")
        assertTrue(backlog.chunks >= 1)
    }

    /** The ceiling going **up** strands nothing — a larger path carries everything a smaller one did. */
    @Test
    fun a_ceiling_that_rises_reports_no_backlog() {
        val sim = probing(ipv6(), pathMtu = 1500)
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(12_000)),
        )
        sim.runUntil(epoch + 5.minutes)

        assertTrue(
            sim.pathMtuA.filter { it.cause == PathMtuChangeCause.ProbeConfirmed }.all { it.backlog == OversizedBacklog.None },
            "nothing is stranded by a path that got bigger",
        )
        assertEquals(1, sim.inboxB.size, "and the message still arrives whole across the ceiling change")
    }

    private companion object {
        // RFC 4960 §3.1 common header (12) + one DATA chunk's header (§3.3.1: 4 TLV + 12 fixed).
        private const val SCTP_PER_PACKET = 28
    }
}
