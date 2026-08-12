package com.ditchoom.webrtc.sctp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The four outcomes a `Boolean` collapsed to two.
 *
 * Two of the four were genuinely indistinguishable before: a corrupt datagram (routine, discard silently
 * per RFC 4960 §6.8) and a question asked about a packet that was never on a wire (a caller mistake that
 * cannot happen to received traffic) both returned `false`. They want opposite responses, and no call
 * site could tell them apart.
 *
 * The other half of this fixture is about a variant nothing produces yet. [ChecksumVerdict.AcceptedZero]
 * is declared ahead of RFC 9653's implementation so Track H adds a producer rather than reshaping a
 * sealed hierarchy the public API already depends on — which means its projection through
 * [ChecksumVerdict.accepted] is load-bearing *now*, and is asserted here rather than when it first has a
 * caller.
 */
class ChecksumVerdictTest {
    private fun built(): SctpPacket =
        SctpPacketBuilder(5000u, 5000u, VerificationTag(0xDEADBEEFu))
            .apply { add(SctpChunk.CookieAck) }
            .build()

    private fun decoded(mutate: (MutableList<Int>) -> Unit = {}): SctpPacket {
        val wire = built().encode().toIntList().toMutableList()
        mutate(wire)
        val buffer = bufferOf(*wire.toIntArray())
        return assertIs<SctpDecodeResult.Success>(SctpPacket.decode(buffer)).packet
    }

    @Test
    fun a_packet_whose_crc_matches_the_wire_is_verified() {
        val verdict = decoded().validateChecksum()

        assertEquals(ChecksumVerdict.Verified, verdict)
        assertTrue(verdict.accepted, "a verified packet must be processed")
    }

    /**
     * Corrupting the checksum field itself rather than the payload: either would do, but this proves the
     * comparison actually reads the stored word instead of only recomputing over the body and comparing
     * with itself — a self-consistent check that would accept every packet.
     */
    @Test
    fun a_corrupt_packet_is_a_mismatch_and_is_refused() {
        val verdict = decoded { it[8] = it[8] xor 0xFF }.validateChecksum()

        assertEquals(ChecksumVerdict.Mismatch, verdict)
        assertFalse(verdict.accepted, "RFC 4960 §6.8 requires a checksum mismatch be discarded")
    }

    /**
     * The distinction the Boolean could not carry. A locally-built packet has no wire bytes at all, so
     * asking about its checksum is a category error rather than a failed check — and unlike a mismatch it
     * can never describe something a peer sent, so the two must never be handled by one arm.
     */
    @Test
    fun a_locally_built_packet_is_not_from_the_wire_rather_than_a_mismatch() {
        val verdict = built().validateChecksum()

        assertEquals(ChecksumVerdict.NotFromWire, verdict)
        assertFalse(verdict.accepted, "there is nothing to accept; this packet was never received")
    }

    /**
     * `accepted` is defined on the type precisely so nobody writes `verdict == Verified` at a call site.
     * When RFC 9653 lands, that equality would silently discard every zero-checksum peer's traffic while
     * reading as correct — so the projection is pinned here, before there is any traffic to lose.
     */
    @Test
    fun the_zero_checksum_verdict_is_accepted_even_though_nothing_produces_it_yet() {
        assertTrue(
            ChecksumVerdict.AcceptedZero.accepted,
            "RFC 9653 §4 accepts a zero checksum on the transport's own integrity guarantee",
        )
        assertTrue(
            ChecksumVerdict.AcceptedZero != ChecksumVerdict.Verified,
            "the two acceptances stay distinguishable; only their projection agrees",
        )
    }

    /**
     * The Boolean overload is kept for source compatibility, so it has to keep meaning what every existing
     * caller assumed — including the association's receive path, where a wrong answer drops traffic
     * indistinguishably from a peer going quiet.
     */
    @Test
    fun the_boolean_overload_is_exactly_the_accepted_projection() {
        assertTrue(decoded().verifyChecksum(), "a good packet verified before and must verify now")
        assertFalse(decoded { it[8] = it[8] xor 0xFF }.verifyChecksum(), "a corrupt packet must still fail")
        assertFalse(built().verifyChecksum(), "a built packet answered false before and must still")
    }
}
