@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The two orderings [SctpConfig] cannot express in its types, asserted at the only place that can hold
 * them: construction.
 *
 * Both inverted configs are ordinary values — every field is independently valid, and it is the
 * *relation* between two of them that is wrong. That is what makes them worth a fixture rather than a
 * comment: neither failure surfaces as a failure. An inverted water mark hangs a sender with the
 * association still open and nothing on the wire to blame, and an inverted RTO pair silently defeats the
 * RFC 4960 §6.3.3 backoff while continuing to work perfectly on an uncongested link.
 *
 * These are `require`, so the assertion is that construction throws — the value must never exist, because
 * every consumer downstream of it reads two fields that already disagree.
 */
class SctpConfigOrderingTest {
    @Test
    fun a_low_water_mark_above_the_high_one_is_refused() {
        val failure =
            assertFailsWith<IllegalArgumentException> {
                SctpConfig(sendBufferHighWaterBytes = 64 * 1024, sendBufferLowWaterBytes = 128 * 1024)
            }
        assertTrue(
            failure.message?.contains("sendBufferLowWaterBytes") == true,
            "the refusal must name the knob to change; got: ${failure.message}",
        )
    }

    @Test
    fun an_rto_floor_above_the_ceiling_is_refused() {
        val failure =
            assertFailsWith<IllegalArgumentException> {
                SctpConfig(rtoMin = 30.seconds, rtoMax = 5.seconds)
            }
        assertTrue(
            failure.message?.contains("rtoMin") == true,
            "the refusal must name the knob to change; got: ${failure.message}",
        )
    }

    /**
     * Equality is the boundary case and it is legal on both: a fixed RTO (`rtoMin == rtoMax`) is a
     * legitimate test configuration for compressing a schedule, and water marks that meet simply mean no
     * hysteresis band — a sender resumes at the instant it would park. Neither is the inversion the
     * `require` exists to catch, so neither may be swept up by it.
     */
    @Test
    fun the_boundary_where_the_two_are_equal_is_legal() {
        val fixedRto = SctpConfig(rtoMin = 2.seconds, rtoMax = 2.seconds)
        assertEquals(fixedRto.rtoMin, fixedRto.rtoMax, "a fixed RTO must stay constructible")

        val noHysteresis = SctpConfig(sendBufferHighWaterBytes = 256 * 1024, sendBufferLowWaterBytes = 256 * 1024)
        assertEquals(
            noHysteresis.sendBufferHighWaterBytes,
            noHysteresis.sendBufferLowWaterBytes,
            "meeting water marks mean no hysteresis band, which is a choice rather than an error",
        )
    }

    /**
     * The defaults are the configuration almost every consumer gets, and they are the one instance of
     * this relation nobody reviews — so assert they satisfy the invariant they now impose on everyone
     * else. A default that could not construct itself would be caught by the first test to touch SCTP,
     * but it would be reported as whatever that test was about.
     */
    @Test
    fun the_shipped_defaults_satisfy_both_orderings() {
        val defaults = SctpConfig()
        assertTrue(
            defaults.sendBufferLowWaterBytes <= defaults.sendBufferHighWaterBytes,
            "the default water marks are inverted",
        )
        assertTrue(defaults.rtoMin <= defaults.rtoMax, "the default RTO bounds are inverted")
    }

    /**
     * `copy()` re-runs `init`, which is the half of this that is easy to lose: a data class lets a caller
     * derive a new config from a valid one, and lowering only the ceiling is exactly how a valid pair
     * becomes an inverted one in practice — the caller is thinking about one knob, not the relation.
     */
    @Test
    fun a_copy_that_inverts_a_pair_is_refused_too() {
        val valid = SctpConfig(rtoMin = 1.seconds, rtoMax = 60.seconds)
        assertFailsWith<IllegalArgumentException>("copy() must re-check, or the invariant is one hop deep") {
            valid.copy(rtoMax = 500.milliseconds)
        }
    }
}
