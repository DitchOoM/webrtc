@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.StreamCount
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

/**
 * Out-of-band (negotiated) data channels — RFC 8832 §5's other way of agreeing a stream id, where the
 * application names it on both peers and no DATA_CHANNEL_OPEN is ever sent.
 *
 * The interesting part is not the channel; it is what the id has to be protected from. An id the
 * application named is reachable by two other mechanisms that know nothing about it — this endpoint's
 * automatic cursor, and the peer's own DCEP OPEN — and both could take it, because both asked the routing
 * map, which does not contain a channel that has been reserved but not yet dispatched.
 */
class NegotiatedChannelTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    private class Peers(
        val client: SctpDataChannelStack,
        val server: SctpDataChannelStack,
    )

    private fun TestScope.peers(
        scope: CoroutineScope,
        config: SctpConfig = SctpConfig(),
    ): Peers {
        val transports = MemoryTransportPair(scope)
        val client = SctpDataChannelStack(transports.clientTransport, scope, clock(), SctpRole.Client, config, Random(1))
        val server = SctpDataChannelStack(transports.serverTransport, scope, clock(), SctpRole.Server, config, Random(2))
        client.start()
        server.start()
        return Peers(client, server)
    }

    private fun negotiated(
        id: Int,
        label: String,
    ) = DataChannelConfig(label = label, identity = ChannelIdentity.Negotiated(StreamId(id)))

    /**
     * Exact ids, not merely distinct ones. Reserving 0 and 2 must push the automatic cursor to 4, 6, 8 —
     * an implementation that handed a reserved id out and let the collision surface later would still
     * produce three distinct channels here, and "they differ" would pass.
     */
    @Test
    fun a_reserved_id_is_structurally_unreachable_by_the_automatic_cursor() =
        runTest {
            val peers = peers(backgroundScope)
            peers.client.open(negotiated(0, "out-of-band-0"))
            peers.client.open(negotiated(2, "out-of-band-2"))

            val automatic =
                List(3) { (peers.client.open(DataChannelConfig(label = "in-band-$it")) as DataChannelConnection).id }
            assertEquals(listOf(4L, 6L, 8L), automatic, "the cursor stepped over both reservations")
            peers.client.streamIdLedger.checkInvariants()
        }

    /**
     * A peer's DCEP OPEN cannot take over an id reserved out of band. The reservation is in the ledger and
     * **not** in the routing map, which is exactly the window the old two-predicate test could not see:
     * `streamIsPeerParity(id) && id !in channels` is true for it, so the stray OPEN would register an
     * in-band channel, publish it on `accept`, and the application's own open would then fail as "in use"
     * for a reason nothing reported.
     *
     * The client reserves stream 1 — the **server's** parity, and therefore the first id the server's own
     * cursor hands out — so the collision needs no contrivance: an ordinary `open()` on the peer produces
     * it.
     */
    @Test
    fun a_peers_open_cannot_take_an_id_the_application_reserved() =
        runTest {
            val peers = peers(backgroundScope)
            val ours = peers.client.open(negotiated(1, "ours")) as DataChannelConnection
            assertEquals(1L, ours.id)

            val theirs = peers.server.open(DataChannelConfig(label = "theirs")) as DataChannelConnection
            assertEquals(1L, theirs.id, "the server's cursor starts at the very id the client reserved")

            // Ordered delivery on stream 1 is what makes this a synchronisation point rather than a guess:
            // the DCEP OPEN went out first, so a message that arrives proves the client already processed
            // it. Without this the assertions below could simply be looking too early.
            theirs.send("after-the-open")
            assertEquals(
                "after-the-open",
                ours
                    .receive()
                    .first()
                    .expectText()
                    .toString(),
            )

            assertEquals(
                1,
                peers.client.declinedInboundOpens(InboundOpenDecline.ReservedOutOfBand),
                "the peer's OPEN on stream 1 was declined by reason, not admitted",
            )
            val state = assertIs<StreamIdState.Claimed>(peers.client.streamIdLedger.stateOf(StreamId(1)))
            assertEquals(ChannelProvenance.OutOfBand, state.origin, "and the id still belongs to the application")
        }

    /** Both endpoints name the same id and carry data on it, with no DCEP exchange anywhere. */
    @Test
    fun two_negotiated_halves_carry_data_without_any_dcep_exchange() =
        runTest {
            val peers = peers(backgroundScope)
            val here = peers.client.open(negotiated(0, "shared"))
            val there = peers.server.open(negotiated(0, "shared"))

            here.send("client to server")
            assertEquals(
                "client to server",
                there
                    .receive()
                    .first()
                    .expectText()
                    .toString(),
            )
            there.send("server to client")
            assertEquals(
                "server to client",
                here
                    .receive()
                    .first()
                    .expectText()
                    .toString(),
            )
        }

    /** A second open on a reserved id is refused at the reservation, by what the id is doing. */
    @Test
    fun reserving_an_id_twice_is_refused_at_the_reservation() =
        runTest {
            val peers = peers(backgroundScope)
            peers.client.open(negotiated(0, "first"))
            val refused = assertFailsWith<DataChannelOpenRefusedException> { peers.client.open(negotiated(0, "second")) }
            assertEquals(DataChannelOpenRefusal.StreamIdInUse(StreamId(0)), refused.refusal)
        }

    /**
     * The range check the reservation deliberately does not make. It cannot run at reserve time — there
     * may be no association yet, and therefore no negotiated count — so it runs at dispatch, and the
     * reservation has to be **given back** or the id is spent for the life of the association on an open
     * that never happened.
     */
    @Test
    fun a_reserved_id_outside_the_negotiated_range_is_refused_and_the_id_is_given_back() =
        runTest {
            val peers = peers(backgroundScope, SctpConfig(outboundStreams = 4u, inboundStreams = 4u))
            val refused = assertFailsWith<DataChannelOpenRefusedException> { peers.client.open(negotiated(9, "too-far")) }
            val refusal = assertIs<DataChannelOpenRefusal.StreamIdOutsideNegotiatedRange>(refused.refusal)
            assertEquals(StreamId(9), refusal.id)
            assertEquals(StreamCount(4u), refusal.capacity)

            assertNull(peers.client.streamIdLedger.stateOf(StreamId(9)), "the reservation was relinquished")
            peers.client.streamIdLedger.checkInvariants()
            // …and the association is unharmed: an id inside the range still opens.
            assertEquals(0L, (peers.client.open(negotiated(0, "fits")) as DataChannelConnection).id)
        }
}
