@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.association.SctpConfig
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **DCEP open under loss (WS-1).** [DataChannelStackTest] proves a *reliable* channel delivers all its data
 * through 30 % loss; this drills the step *before* any data flows — the **DCEP handshake itself** (RFC 8832:
 * DATA_CHANNEL_OPEN → DATA_CHANNEL_ACK) — across a wide seed sweep at 5/10/20 % per-datagram loss.
 *
 * The OPEN and its ACK are ordinary SCTP DATA chunks, so they ride the association's reliable retransmission
 * path; when either is dropped, the channel must still open on retransmission rather than the acceptor
 * hanging in `acceptBidirectional()` forever. The observable is exactly that: the server-side channel
 * materializes (carrying the label the OPEN advertised). Loss is seeded per datagram (directive #2) so each
 * seed is a replayable scenario; the watchdog is `runTest` virtual time, never a wall-clock budget
 * (directive #4).
 */
class DcepOpenUnderLossTest {
    private val epoch = Instant.fromEpochSeconds(0)
    private val timeout = 120.seconds

    @Test
    fun dcep_open_completes_under_loss_across_seeds() {
        for (loss in listOf(0.05, 0.10, 0.20)) {
            for (s in 0 until SEEDS_PER_RATE) {
                runOne(loss = loss, seed = s.toLong())
            }
        }
    }

    private fun runOne(
        loss: Double,
        seed: Long,
    ) = runTest {
        val clock: () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
        // Delay so the retransmission path is actually exercised (not collapsed into one instant), seeded so
        // the whole scenario replays bit-for-bit.
        val pair = MemoryTransportPair(backgroundScope, lossRate = loss, delay = 10.milliseconds, seed = seed)
        val config = SctpConfig()
        val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock, SctpRole.Client, config, Random(seed xor 0x0111))
        val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock, SctpRole.Server, config, Random(seed xor 0x0222))
        client.start()
        server.start()

        val diag = "loss=$loss seed=$seed"
        // open() completing means the client's OPEN was ACKed through the loss; acceptBidirectional()
        // returning means the server saw the OPEN — together, the full DCEP handshake survived.
        val channel = withTimeoutOrNull(timeout) { client.open(DataChannelConfig(label = "dcep-$seed")) }
        assertNotNull(channel, "client DCEP open completed under loss ($diag)")
        val incoming = withTimeoutOrNull(timeout) { server.acceptBidirectional() }
        assertNotNull(incoming, "server accepted the channel — DCEP OPEN/ACK survived loss ($diag)")
        assertEquals("dcep-$seed", (incoming as DataChannelConnection).config.label, "label survived the lossy OPEN ($diag)")

        client.shutdown()
    }

    private companion object {
        const val SEEDS_PER_RATE = 16
    }
}
