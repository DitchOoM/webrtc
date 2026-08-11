@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The RTT sample must be measured from the instant a chunk reached the **wire**, never from the instant
 * the application enqueued it (directive #5 fixture).
 *
 * A fragment waits in `pendingSend` for as long as cwnd and the peer's receive window say it must, so on
 * any bulk transfer the gap between enqueue and first transmission is queueing delay — often far larger
 * than the path RTT. Folding it into the sample inflates SRTT, which inflates RTO, which makes every
 * subsequent loss recovery slow. The regression this pins measured `now - firstSentAt`, where
 * `firstSentAt` was stamped in `onSendMessage` (the enqueue path) rather than in `trySend`.
 *
 * Deterministic and clock-free: every instant is supplied, so this asserts a computed value rather than
 * a wall-clock budget (directive #4).
 */
class RetransmissionQueueRttTest {
    private val t0 = Instant.fromEpochSeconds(100)
    private val queueDelay = 900.milliseconds
    private val pathRtt = 40.milliseconds

    private fun chunk(
        tsn: Tsn,
        enqueuedAt: Instant,
        reliability: SctpReliability = SctpReliability.Reliable,
    ) = OutstandingData(
        tsn = tsn,
        streamId = StreamId(0),
        ssn = StreamSequenceNumber(0u),
        flags = DataChunkFlags(0x03u), // B|E — one complete message
        bytes = 100,
        packet = BufferFactory.managed().allocate(16, ByteOrder.BIG_ENDIAN),
        reliability = reliability,
        enqueuedAt = enqueuedAt,
    )

    /** The bug: a chunk that queued for 900 ms on a 40 ms path must sample 40 ms, not 940 ms. */
    @Test
    fun rtt_sample_excludes_time_spent_queued_before_transmission() {
        val queue = RetransmissionQueue(SctpConfig(), Tsn(1u))
        val data = chunk(Tsn(1u), enqueuedAt = t0)

        val transmittedAt = t0 + queueDelay
        queue.onSent(data, transmittedAt)
        val outcome =
            queue.onSack(
                Tsn(1u),
                advertisedReceiverWindow = 1_000_000u,
                gapAckBlocks = emptyList(),
                now = transmittedAt + pathRtt,
            )

        assertEquals(pathRtt, outcome.rttSample, "RTT must be measured from transmission, not from enqueue")
    }

    /** Karn's algorithm (RFC 4960 §6.3.1 C5): a retransmitted chunk's ack is ambiguous — no sample. */
    @Test
    fun retransmitted_chunk_yields_no_rtt_sample() {
        val queue = RetransmissionQueue(SctpConfig(), Tsn(1u))
        val data = chunk(Tsn(1u), enqueuedAt = t0)
        queue.onSent(data, t0)

        queue.markRetransmitted(data)
        val outcome = queue.onSack(Tsn(1u), advertisedReceiverWindow = 1_000_000u, gapAckBlocks = emptyList(), now = t0 + pathRtt)

        assertNull(outcome.rttSample, "a retransmitted chunk cannot be attributed to one transmission")
    }

    /**
     * The state the old `lastSentAt: Instant = firstSentAt` seeding made representable: a chunk that never
     * reached the wire still carried an instant, so anything reading it got a plausible — and wholly
     * invented — sample. [RttOrigin.Untransmitted] carries no instant, so there is nothing to read.
     */
    @Test
    fun an_untransmitted_chunk_carries_no_transmission_instant() {
        val data = chunk(Tsn(1u), enqueuedAt = t0)
        assertTrue(data.rttOrigin is RttOrigin.Untransmitted, "a chunk begins with no transmission instant")
    }

    /**
     * The other half of the split: `maxPacketLifeTime` is measured from `send()` (W3C), so abandonment
     * *must* keep counting the queueing delay the RTT sample excludes. One instant cannot serve both,
     * which is why [OutstandingData.enqueuedAt] and [OutstandingData.rttOrigin] are separate.
     */
    @Test
    fun lifetime_abandonment_still_counts_from_enqueue() {
        val queue = RetransmissionQueue(SctpConfig(), Tsn(1u))
        val budget = 500.milliseconds
        val data = chunk(Tsn(1u), enqueuedAt = t0, reliability = SctpReliability.MaxLifetime(budget))

        // Transmitted late — after the lifetime budget already expired while it sat queued.
        queue.onSent(data, t0 + queueDelay)
        val abandoned = queue.abandonExpired(now = t0 + queueDelay)

        assertEquals(
            listOf(StreamId(0) to StreamSequenceNumber(0u)),
            abandoned,
            "a message that spent its whole lifetime queued is abandoned",
        )
    }
}
