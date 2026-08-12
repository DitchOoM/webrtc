@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.association.OutgoingStreamCapacity
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.StreamAddOutcome
import com.ditchoom.webrtc.sctp.association.StreamCount
import com.ditchoom.webrtc.sctp.association.StreamGrowthPolicy
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

/**
 * [StreamGrowthPolicy] at the data-channel layer: an open that runs out of negotiated stream ids either
 * fails immediately or waits for an RFC 6525 §4.5 exchange to make room.
 *
 * The waiting half is the one worth a fixture. It is the only place in this stack where a consumer call
 * is parked on a *protocol round trip* rather than on the send buffer, so both endings have to be
 * reachable — the open resuming with an id it could not have had, and the open failing when the peer
 * will not grant one. An implementation that parked and never resumed would look identical to a slow
 * peer, which is the failure mode this repo has recorded for every unbounded suspension.
 */
class StreamGrowthPolicyTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    /**
     * Four negotiated streams give the client ids 0 and 2. The third open has none, asks for four more,
     * and comes back with id 4 — an id that did not exist when `open()` was called.
     */
    @Test
    fun an_open_with_no_id_left_waits_for_the_streams_it_needs_and_then_gets_one() =
        runTest {
            val config =
                SctpConfig(
                    outboundStreams = 4u,
                    inboundStreams = 4u,
                    streamGrowth = StreamGrowthPolicy.AddStreams(StreamCount(4u)),
                )
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config, Random(1))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config, Random(2))
            client.start()
            server.start()

            client.open(DataChannelConfig(label = "one"))
            client.open(DataChannelConfig(label = "two"))
            assertEquals(
                OutgoingStreamCapacity.Negotiated(StreamCount(4u)),
                client.negotiatedOutgoingCapacity,
                "the handshake settled four streams and both existing ids fit in them",
            )

            val third = client.open(DataChannelConfig(label = "three")) as DataChannelConnection
            assertEquals(4L, third.id, "id 4 exists only because the peer granted the streams")
            assertEquals(
                OutgoingStreamCapacity.Negotiated(StreamCount(8u)),
                client.negotiatedOutgoingCapacity,
                "…and the ceiling moved to say so",
            )

            // The channel is real on both sides, not merely constructed: the peer had to raise its own
            // inbound count to match, or the DCEP OPEN on stream 4 would draw an Invalid Stream Identifier
            // ERROR and the third accept below would never complete.
            val labels = List(3) { (server.acceptBidirectional() as DataChannelConnection).config.label }
            assertEquals(listOf("one", "two", "three"), labels, "all three arrive at the peer, in order")
        }

    /**
     * The refusal half. The configured increment is larger than the 16-bit count field can hold on top of
     * what is already negotiated, so the association refuses it locally — the same shape as a peer saying
     * no, and the only one a two-endpoint fixture can produce deterministically without a scripted peer.
     */
    @Test
    fun an_open_waiting_on_streams_the_peer_will_not_add_fails_with_the_reason() =
        runTest {
            val config =
                SctpConfig(
                    outboundStreams = 4u,
                    inboundStreams = 4u,
                    // 4 + 65535 does not fit a u16, so the ask is refused before it reaches the wire.
                    streamGrowth = StreamGrowthPolicy.AddStreams(StreamCount.Max),
                )
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, config, Random(3))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, config, Random(4))
            client.start()
            server.start()

            client.open(DataChannelConfig(label = "one"))
            client.open(DataChannelConfig(label = "two"))

            val refused =
                assertFailsWith<DataChannelOpenRefusedException> {
                    client.open(DataChannelConfig(label = "three"))
                }
            val refusal = assertIs<DataChannelOpenRefusal.PeerWouldNotAddStreams>(refused.refusal)
            assertEquals(StreamAddOutcome.NotAdded.WouldOverflow, refusal.refusal)
            assertEquals(
                OutgoingStreamCapacity.Negotiated(StreamCount(4u)),
                client.negotiatedOutgoingCapacity,
                "and nothing was granted",
            )
        }
}
