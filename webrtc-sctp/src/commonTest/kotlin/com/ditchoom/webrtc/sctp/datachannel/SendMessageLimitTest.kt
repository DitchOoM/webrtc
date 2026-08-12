@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

/**
 * **The send gate: a message larger than the peer will accept never reaches the wire** (RFC 8841 §6,
 * RFC 8831 §6.6's MUST NOT).
 *
 * Three properties, and the second and third are what make the first mean anything:
 *
 * 1. A message over the ceiling is refused with a **typed** reason naming which ceiling and why.
 * 2. A message **at** the ceiling is sent and arrives. Without this the fixtures pass on a gate that
 *    refuses everything, and an off-by-one that costs the interop matrix its `s1` boundary probe — a
 *    real phase, on every lane — would be green here.
 * 3. The refusal does not disturb the association: the very next message on the same channel goes
 *    through. A gate that failed the send by failing the *stack* would satisfy (1) and be far worse than
 *    no gate at all.
 *
 * The size is measured as `wireByteCount`, so a **text** message is refused on its encoded length rather
 * than its character count. That fixture is the cross-design one: `"é".repeat(n)` is `n` characters and
 * `2n` bytes, so a ceiling of `n` passes a `String.length` check and overruns the peer by a factor of
 * two. Nothing in the type system catches it — both numbers are plausible `Long`s.
 */
class SendMessageLimitTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    private class Peers(
        val client: SctpDataChannelStack,
        val server: SctpDataChannelStack,
    )

    private fun TestScope.peers(seed: Long): Peers {
        val transports = MemoryTransportPair(backgroundScope, seed = seed)
        val client = SctpDataChannelStack(transports.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(seed))
        val server =
            SctpDataChannelStack(transports.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(seed + 1))
        client.start()
        server.start()
        return Peers(client, server)
    }

    private fun bytes(size: Int): ReadBuffer {
        val buf = BufferFactory.managed().allocate(maxOf(1, size), ByteOrder.BIG_ENDIAN)
        repeat(size) { buf.writeByte((it and 0xFF).toByte()) }
        buf.resetForRead()
        buf.setLimit(size)
        return buf
    }

    @Test
    fun a_message_over_the_peer_s_advertised_ceiling_is_refused_before_the_wire() =
        runTest {
            val p = peers(seed = 31)
            p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(CEILING.toLong()))
            val channel = p.client.open(DataChannelConfig(label = "gate"))
            p.server.acceptBidirectional()

            val payload = bytes(CEILING + 1)
            val refused =
                try {
                    assertFailsWith<MessageRefusedException> { channel.send(DataChannelPayload.Binary(payload)) }
                } finally {
                    payload.freeIfNeeded()
                }
            val reason = assertIs<MessageRefusedReason.ExceedsAdvertisedLimit>(refused.reason)
            assertEquals((CEILING + 1).toLong(), reason.messageBytes)
            assertEquals(CEILING.toLong(), reason.ceilingBytes)

            p.client.shutdown()
        }

    /**
     * The anti-vacuity half, and the one the interop `s1` boundary probe depends on: a message at
     * **exactly** the advertised ceiling is a message the peer promised to receive, so it must go.
     */
    @Test
    fun a_message_at_exactly_the_ceiling_is_sent_and_arrives() =
        runTest {
            val p = peers(seed = 32)
            p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(CEILING.toLong()))
            val channel = p.client.open(DataChannelConfig(label = "gate"))
            val peer = p.server.acceptBidirectional()

            val payload = bytes(CEILING)
            try {
                channel.send(DataChannelPayload.Binary(payload))
            } finally {
                payload.freeIfNeeded()
            }
            val arrived = withTimeout(60.seconds) { peer.receive().first() }
            assertEquals(CEILING.toLong(), arrived.wireByteCount, "the boundary message arrives whole")
            arrived.release()

            p.client.shutdown()
        }

    /**
     * A refusal fails the SEND, not the stack. Nothing was queued, no TSN was assigned, the channel is
     * still open — so the next message goes through on the same channel, and its arrival is what proves
     * the association was never touched.
     */
    @Test
    fun a_refused_send_leaves_the_association_and_the_channel_usable() =
        runTest {
            val p = peers(seed = 33)
            p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(CEILING.toLong()))
            val channel = p.client.open(DataChannelConfig(label = "gate"))
            val peer = p.server.acceptBidirectional()

            val tooBig = bytes(CEILING * 4)
            try {
                assertFailsWith<MessageRefusedException> { channel.send(DataChannelPayload.Binary(tooBig)) }
            } finally {
                tooBig.freeIfNeeded()
            }
            channel.send(DataChannelPayload.Text("after"))
            val arrived = withTimeout(60.seconds) { peer.receive().first() }
            assertEquals("after", assertIs<DataChannelPayload.Text>(arrived).text.toString())
            assertEquals(SctpAssociationState.Established, p.client.state.value)

            p.client.shutdown()
        }

    /**
     * **The cross-design bug, in one fixture.** `"é"` is one `Char` and two UTF-8 bytes, so a message of
     * `CEILING` characters is `2 * CEILING` bytes on the wire. A gate measuring `String.length` passes it
     * and overruns a peer that stated `CEILING` — by exactly a factor of two, silently, with both numbers
     * looking entirely reasonable at the call site.
     */
    @Test
    fun a_text_message_is_measured_after_utf8_encoding_not_by_character_count() =
        runTest {
            val p = peers(seed = 34)
            p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(CEILING.toLong()))
            val channel = p.client.open(DataChannelConfig(label = "gate"))
            p.server.acceptBidirectional()

            val text = "é".repeat(CEILING)
            assertEquals(CEILING, text.length, "a length check would see exactly the ceiling and pass it")
            val refused = assertFailsWith<MessageRefusedException> { channel.send(DataChannelPayload.Text(text)) }
            val reason = assertIs<MessageRefusedReason.ExceedsAdvertisedLimit>(refused.reason)
            assertEquals(2L * CEILING, reason.messageBytes, "measured in bytes, which is twice the character count")

            p.client.shutdown()
        }

    /**
     * The same ceiling, three provenances, three reasons. `Advertised(65536)` is a promise, `AssumedDefault`
     * is RFC 8831 §6.6 applied to silence, and `NotYetNegotiated` is a send racing negotiation — and a
     * caller's response to each is different, which a single "too large" would make unavailable.
     */
    @Test
    fun the_same_ceiling_reached_three_ways_gives_three_different_reasons() =
        runTest {
            val overAssumed = PeerMessageLimit.ASSUMED_DEFAULT_BYTES + 1

            val notNegotiated = peers(seed = 35)
            val a = notNegotiated.client.open(DataChannelConfig(label = "gate"))
            notNegotiated.server.acceptBidirectional()
            assertIs<MessageRefusedReason.PeerLimitUnknown>(
                assertFailsWith<MessageRefusedException> { a.send(DataChannelPayload.Text("x".repeat(overAssumed.toInt()))) }.reason,
            )
            notNegotiated.client.shutdown()

            val silent = peers(seed = 36)
            silent.client.setPeerMessageLimit(PeerMessageLimit.AssumedDefault)
            val b = silent.client.open(DataChannelConfig(label = "gate"))
            silent.server.acceptBidirectional()
            assertIs<MessageRefusedReason.ExceedsAssumedDefault>(
                assertFailsWith<MessageRefusedException> { b.send(DataChannelPayload.Text("x".repeat(overAssumed.toInt()))) }.reason,
            )
            silent.client.shutdown()

            val promised = peers(seed = 37)
            promised.client.setPeerMessageLimit(PeerMessageLimit.Advertised(PeerMessageLimit.ASSUMED_DEFAULT_BYTES))
            val c = promised.client.open(DataChannelConfig(label = "gate"))
            promised.server.acceptBidirectional()
            assertIs<MessageRefusedReason.ExceedsAdvertisedLimit>(
                assertFailsWith<MessageRefusedException> { c.send(DataChannelPayload.Text("x".repeat(overAssumed.toInt()))) }.reason,
            )
            promised.client.shutdown()
        }

    /**
     * A peer that advertised `a=max-message-size:0` said it can take anything (RFC 8841 §6), so nothing is
     * refused — including a message far past the 64 KiB every other reading would stop at. This is the
     * inversion `PeerMessageLimit.Unlimited` exists to keep out of the comparison: as a `Long` it is the
     * tightest ceiling in the type, and the gate would refuse the empty message against it.
     */
    @Test
    fun an_unlimited_peer_refuses_nothing() =
        runTest {
            val p = peers(seed = 38)
            p.client.setPeerMessageLimit(PeerMessageLimit.Unlimited)
            val channel = p.client.open(DataChannelConfig(label = "gate"))
            val peer = p.server.acceptBidirectional()

            val huge = (PeerMessageLimit.ASSUMED_DEFAULT_BYTES + 1).toInt()
            val payload = bytes(huge)
            try {
                channel.send(DataChannelPayload.Binary(payload))
            } finally {
                payload.freeIfNeeded()
            }
            val arrived = withTimeout(120.seconds) { peer.receive().first() }
            assertEquals(huge.toLong(), arrived.wireByteCount)
            arrived.release()

            // …and the empty message, which is what a `Long` of 0 would have refused first.
            channel.send(DataChannelPayload.Binary(ReadBuffer.EMPTY_BUFFER))
            val empty = withTimeout(60.seconds) { peer.receive().first() }
            assertEquals(0L, empty.wireByteCount)
            empty.release()

            p.client.shutdown()
        }

    /**
     * DCEP is not user data. RFC 8832's OPEN/ACK are the protocol that brings a channel up, bounded by
     * their own grammar, and gating them on the peer's message ceiling would let a peer advertising a
     * tiny limit make its own channels unopenable. Proven by opening a channel while the ceiling is
     * *below* the DCEP OPEN this stack emits for it, and requiring the peer to accept it.
     */
    @Test
    fun a_tiny_peer_ceiling_does_not_block_the_dcep_handshake() =
        runTest {
            val p = peers(seed = 39)
            p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(1))
            val label = "a-label-longer-than-the-one-byte-ceiling"
            val channel = p.client.open(DataChannelConfig(label = label))
            val peer = withTimeout(60.seconds) { p.server.acceptBidirectional() }
            assertEquals(channel.id, peer.id, "the DCEP OPEN crossed and registered the peer's channel")

            // …while a one-byte USER message is still refused, which is what makes the above a carve-out
            // for control traffic rather than a gate that was never armed.
            val two = bytes(2)
            try {
                assertFailsWith<MessageRefusedException> { channel.send(DataChannelPayload.Binary(two)) }
            } finally {
                two.freeIfNeeded()
            }

            p.client.shutdown()
        }

    /**
     * The limit is delivered as an ordered drive-loop item, not assigned across coroutines, so a send
     * posted after it observes it. Both directions: raising the ceiling admits a message that was refused
     * a moment earlier.
     */
    @Test
    fun a_raised_ceiling_admits_a_message_that_was_just_refused() =
        runTest {
            val p = peers(seed = 40)
            p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(CEILING.toLong()))
            val channel = p.client.open(DataChannelConfig(label = "gate"))
            val peer = p.server.acceptBidirectional()

            val payload = bytes(CEILING * 2)
            try {
                assertFailsWith<MessageRefusedException> { channel.send(DataChannelPayload.Binary(payload)) }
                // No settle step: the new limit is posted onto the same FIFO inbox the send below posts
                // its command to, so "the limit is already in effect" is an ordering property rather than
                // a race a fixture has to wait out. That is the whole reason it is a command.
                p.client.setPeerMessageLimit(PeerMessageLimit.Advertised(CEILING.toLong() * 2))
                channel.send(DataChannelPayload.Binary(payload))
            } finally {
                payload.freeIfNeeded()
            }
            val arrived = withTimeout(120.seconds) { peer.receive().first() }
            assertEquals((CEILING * 2).toLong(), arrived.wireByteCount)
            arrived.release()

            p.client.shutdown()
        }

    private companion object {
        // Comfortably above one SCTP fragment so the gated messages are genuinely fragmented ones, and
        // well under the assumed default so the ADVERTISED ceiling is what every assertion turns on.
        private const val CEILING = 4096
    }
}
