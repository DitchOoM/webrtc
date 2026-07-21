@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.encodeToPlatformBuffer
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.Ecn
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Regression fixture for the signaling **request/response correlation** (W7 adversarial gate). UDP has no
 * request↔response pairing, and the client blindly consumes the next datagram on its socket — so a delayed
 * or duplicate reply arriving after a per-request timeout would sit in the RX buffer and permanently offset
 * the socket by one, mis-pairing every later reply (e.g. an answer-SDP reply consumed by a candidate poll,
 * fed into `addIceCandidate`, and a real candidate skipped). The fix stamps a nonce on each request that the
 * reply echoes; [UdpSignaling.awaitReply] drains + discards any reply whose nonce doesn't match.
 *
 * This models that exactly: the channel answers every GET with a **stale** reply (wrong nonce) *before* the
 * correct one. A correlating client must skip the stale and return the matching records. Without the nonce
 * check (the pre-fix "return the next datagram") the client would return the stale reply's empty records and
 * desync — so this test fails against that behavior.
 */
class SignalingCorrelationTest {
    @Test
    fun poll_discards_a_stale_reply_and_returns_the_nonce_matching_records() =
        runTest {
            // BufferFactory.Default is fine here — the fake channel isn't io_uring, so no native buffer is
            // required, and freeNativeMemory() is a no-op on heap buffers.
            val factory = BufferFactory.Default
            val signaling =
                UdpSignaling(
                    channel = StaleThenCorrectChannel(factory),
                    rendezvous = SocketAddress.ofLiteral("127.0.0.1", 9999),
                    session = "sess",
                    factory = factory,
                )

            val records = signaling.poll("offer", 0)

            assertEquals(listOf(StaleThenCorrectChannel.RECORD), records, "returned the nonce-matching reply, not the stale one")
        }
}

/**
 * A fake [DatagramChannel] that replies to every GET with a stale reply (a mismatched nonce) followed by the
 * correct one (echoing the request's nonce, carrying one record). It never touches a real socket.
 */
private class StaleThenCorrectChannel(
    private val factory: BufferFactory,
) : DatagramChannel {
    private val inbound = Channel<Datagram>(Channel.UNLIMITED)
    private var closed = false

    override val localAddress: SocketAddress? = null
    override val isOpen: Boolean get() = !closed
    override val maxWritableSize: Int = MAX_UDP_PAYLOAD
    override val capabilities: DatagramCapabilities = CAPABILITIES

    override suspend fun receive(): DatagramReadResult {
        val datagram = inbound.receiveCatching().getOrNull()
        return if (datagram != null) DatagramReadResult.Received(datagram) else DatagramReadResult.Closed()
    }

    override suspend fun send(
        payload: ReadBuffer,
        to: SocketAddress?,
        options: DatagramSendOptions,
    ) {
        check(!closed) { "channel is closed" }
        val nonce = GetRequestCodec.decode(payload.slice(), DecodeContext.Empty).nonce
        val peer = requireNotNull(to)
        // Stale first (wrong nonce, no records) — then the correct reply (this request's nonce, one record).
        val stale = MailboxResponseCodec.encodeToPlatformBuffer(MailboxResponse(0u, nonce + 4321u, 0u, emptyList()), factory)
        val correct = MailboxResponseCodec.encodeToPlatformBuffer(MailboxResponse(0u, nonce, 1u, listOf(MailboxRecord(RECORD))), factory)
        inbound.trySend(Datagram(payload = stale, peer = peer, ecn = Ecn.Unknown))
        inbound.trySend(Datagram(payload = correct, peer = peer, ecn = Ecn.Unknown))
    }

    override fun close() {
        closed = true
        inbound.close()
    }

    companion object {
        const val RECORD = "the-offer-sdp"
        private const val MAX_UDP_PAYLOAD = 65507

        val CAPABILITIES =
            DatagramCapabilities(
                ecnSend = true,
                ecnReceive = true,
                dscpSend = true,
                dontFragment = true,
                hopLimitSend = true,
                hopLimitReceive = true,
                localAddressReceive = true,
                sourceAddressSelect = true,
                multicast = false,
            )
    }
}
