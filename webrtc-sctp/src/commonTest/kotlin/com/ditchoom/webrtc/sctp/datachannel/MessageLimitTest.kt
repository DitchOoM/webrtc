package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * The two ceilings in this area, pinned apart.
 *
 * `ReceiveMessageLimit.Default` (256 KiB, what *we* advertise) and `PeerMessageLimit.ASSUMED_DEFAULT_BYTES`
 * (64 KiB, RFC 8831 §6.6 — what we must assume of a peer that advertised nothing) are both "the
 * max-message-size default", and getting them the wrong way round is a silent overrun of every peer that
 * never claimed more than 64 KiB. Pion advertises nothing, so that peer is in the interop matrix rather
 * than hypothetical. Asserting they are **different**, in one place, is what makes a future edit that
 * collapses them a red test rather than an interop bug.
 *
 * The construction fixtures below are about the RFC 8841 §6 inversion: `0` on the wire is the *largest*
 * answer the attribute can give, so a ceiling type that can hold `0` can hold the value that refuses
 * every message including the empty one. Neither type can.
 */
class MessageLimitTest {
    @Test
    fun the_advertised_default_and_the_assumed_default_are_different_numbers() {
        val ours = assertBytes(ReceiveMessageLimit.Default)
        assertEquals(262_144L, ours, "what we advertise is the JSEP/browser 256 KiB")
        assertEquals(65_536L, PeerMessageLimit.ASSUMED_DEFAULT_BYTES, "what RFC 8831 §6.6 assumes of silence is 64 KiB")
        assertNotEquals(
            ours,
            PeerMessageLimit.ASSUMED_DEFAULT_BYTES,
            "what we promise and what we assume of a silent peer are different promises by different endpoints",
        )
    }

    @Test
    fun an_unconfigured_association_receives_up_to_the_advertised_default() {
        assertEquals(ReceiveMessageLimit.Default, SctpConfig().receiveMessageLimit)
    }

    @Test
    fun a_receive_ceiling_of_zero_is_unconstructible() {
        assertFailsWith<IllegalArgumentException> { ReceiveMessageLimit.Bytes(0) }
        assertFailsWith<IllegalArgumentException> { ReceiveMessageLimit.Bytes(-1) }
        assertEquals(1L, assertBytes(ReceiveMessageLimit.Bytes(1)), "one byte is the smallest real ceiling")
    }

    @Test
    fun an_advertised_peer_ceiling_of_zero_is_unconstructible() {
        assertFailsWith<IllegalArgumentException> { PeerMessageLimit.Advertised(0) }
        assertFailsWith<IllegalArgumentException> { PeerMessageLimit.Advertised(-1) }
        assertEquals(1L, PeerMessageLimit.Advertised(1).bytes)
    }

    // `Unlimited` and `Advertised(ASSUMED_DEFAULT_BYTES)` are not the same value, and neither is
    // `AssumedDefault` — the third is what a peer that said nothing gets, and telling it from a peer that
    // wrote 65536 down is what makes the two refusal reasons in the send gate mean different things.
    @Test
    fun the_four_peer_cases_are_four_distinct_values() {
        val all =
            listOf(
                PeerMessageLimit.NotYetNegotiated,
                PeerMessageLimit.AssumedDefault,
                PeerMessageLimit.Unlimited,
                PeerMessageLimit.Advertised(PeerMessageLimit.ASSUMED_DEFAULT_BYTES),
            )
        assertEquals(all.size, all.toSet().size, "no two of the four peer cases compare equal")
    }

    private fun assertBytes(limit: ReceiveMessageLimit): Long =
        when (limit) {
            ReceiveMessageLimit.Unbounded -> throw AssertionError("expected a stated ceiling, got Unbounded")
            is ReceiveMessageLimit.Bytes -> limit.value
        }
}
