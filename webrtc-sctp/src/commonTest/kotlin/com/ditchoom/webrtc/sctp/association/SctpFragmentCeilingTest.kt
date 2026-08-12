@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime

/**
 * The IPv6 fragmentation defect, and the fix for it (directive #5 fixture).
 *
 * `SctpConfig.maxPayloadBytes` defaults to 1200, which is a payload sized for a 1500-byte link and says
 * nothing about the link actually underneath. On IPv6 the resulting datagram is
 * `1200 + 28 (SCTP) + 37 (DTLS 1.2) + 8 (UDP) + 40 (IPv6) = 1313` bytes — over RFC 8200 §5's guaranteed
 * 1280 — and an IPv6 router **MUST NOT** fragment it, so on any 1280-MTU path every full-size fragment is
 * dropped. IPv4 never showed this because a router MAY fragment (RFC 791 §2.3) and every CI bridge is
 * 1500 anyway.
 *
 * ## The second assertion is the point
 *
 * "Datagrams fit in 1280" passes on an association that sent nothing, and would also have passed before
 * the fix on any lane whose messages happened to be small. The **discriminating pair** is the same
 * message over the same association with no path profile: it must overrun, by exactly the 1313 bytes the
 * defect predicts. That is what makes the first assertion a statement about the ceiling rather than about
 * the traffic.
 */
class SctpFragmentCeilingTest {
    private val stream = StreamId(0)

    // The lower-layer headers a direct IPv6 WebRTC path pays: 40 IPv6 + 8 UDP + 37 for a DTLS 1.2
    // AES-GCM record (13-byte header + 8-byte explicit nonce + 16-byte tag).
    private val ipv6Overhead = PathOverheadBytes(85)
    private val ipv4Overhead = PathOverheadBytes(65) // 20 IPv4 + 8 UDP + 37 DTLS

    private fun assessed(
        family: PathAddressFamily,
        overhead: PathOverheadBytes,
    ) = SctpPathProfile.Assessed(PathIdentity(1u), family, overhead)

    /**
     * The largest SCTP datagram the sender put on the wire for one 8 KiB message. Read from the *first*
     * flight, which is cwnd-limited to four full-size fragments — enough that the ceiling shows, and taken
     * before any SACK so the measurement cannot be confused by a retransmit.
     */
    private fun largestDatagram(profile: SctpPathProfile.Assessed?): Int {
        val sim = SctpSim()
        sim.associateA()
        sim.run()
        if (profile != null) sim.post(toA = true, SctpEvent.PathChanged(profile))
        val outputs =
            sim.post(
                toA = true,
                SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(8 * 1024)),
            )
        val sizes =
            outputs
                .filterIsInstance<SctpOutput.Transmit>()
                .map { it.packet.limit() }
        assertTrue(sizes.isNotEmpty(), "the send must actually reach the wire, or there is nothing to measure")
        return sizes.max()
    }

    @Test
    fun an_ipv6_path_keeps_every_datagram_inside_the_guaranteed_minimum() {
        val ipDatagram = largestDatagram(assessed(PathAddressFamily.Ipv6, ipv6Overhead)) + ipv6Overhead.value
        assertTrue(
            ipDatagram <= IPV6_MINIMUM,
            "an IPv6 datagram of $ipDatagram bytes is over RFC 8200 §5's guaranteed $IPV6_MINIMUM",
        )
    }

    @Test
    fun without_a_path_profile_the_same_message_overruns_it() {
        val ipDatagram = largestDatagram(profile = null) + ipv6Overhead.value
        assertEquals(1313, ipDatagram, "the defect, measured: 1200 payload + 28 SCTP + 85 below it")
        assertTrue(ipDatagram > IPV6_MINIMUM, "which is what an IPv6 path drops")
    }

    /**
     * An IPv4 assessment must leave the configured ceiling alone. IPv4's *guaranteed* minimum is 576, and
     * applying that as the unprobed ceiling would fragment every v4 message into ~480-byte pieces — a
     * unilateral regression no other stack has, on a family where an over-estimate is fragmented rather
     * than dropped. See [PathAddressFamily.unprobedPathMtu].
     */
    @Test
    fun an_ipv4_path_leaves_the_configured_ceiling_alone() {
        assertEquals(
            largestDatagram(profile = null),
            largestDatagram(assessed(PathAddressFamily.Ipv4, ipv4Overhead)),
        )
    }

    /** A caller that asked for small fragments keeps them: a path assessment may only lower the ceiling. */
    @Test
    fun a_path_assessment_never_raises_the_configured_ceiling() {
        val sim = SctpSim(config = SctpConfig(maxPayloadBytes = 100))
        sim.associateA()
        sim.run()
        sim.post(toA = true, SctpEvent.PathChanged(assessed(PathAddressFamily.Ipv4, ipv4Overhead)))
        sim.post(
            toA = true,
            SctpEvent.SendMessage(SctpSendOptions(stream, PayloadProtocolId.WebRtcBinary), payload(1050, seed = 3)),
        )
        sim.run()

        assertEquals(
            payload(1050, seed = 3).bytes(),
            sim.inboxB
                .single()
                .payload
                .bytes(),
            "an 11-fragment message at the configured 100-byte ceiling still reassembles",
        )
    }

    /** The derivation itself: four-byte aligned, and never above what the datagram budget leaves. */
    @Test
    fun the_derived_ceiling_fits_the_family_minimum_and_is_four_byte_aligned() {
        for (overhead in listOf(0, 1, 65, 85, 101, 133, 192)) {
            for (family in listOf(PathAddressFamily.Ipv4, PathAddressFamily.Ipv6)) {
                val ceiling = assessed(family, PathOverheadBytes(overhead)).unprobedFragmentCeiling
                assertEquals(0, ceiling.value % 4, "ceilings are 4-byte aligned (RFC 4960 §3.2 chunk padding)")
                assertTrue(
                    ceiling.value + SCTP_PER_PACKET + overhead <= family.unprobedPathMtu.value,
                    "a full fragment plus its headers must fit the unprobed datagram budget",
                )
            }
        }
    }

    private companion object {
        private const val IPV6_MINIMUM = 1280

        // RFC 4960 §3.1 common header (12) + one DATA chunk's header (§3.3.1: 4 TLV + 12 fixed).
        private const val SCTP_PER_PACKET = 28
    }
}
