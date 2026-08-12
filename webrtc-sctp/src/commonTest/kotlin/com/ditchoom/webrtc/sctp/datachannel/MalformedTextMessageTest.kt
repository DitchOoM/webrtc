@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

private val EPOCH = Instant.fromEpochSeconds(0)

/**
 * The bytes `C3 28 FF 41` — `0xC3` opens a two-byte sequence and `0x28` is not a continuation byte, then
 * `0xFF` is not a legal lead byte at all. No decoder on any target accepts this.
 */
private fun invalidUtf8(): ReadBuffer {
    val buf = BufferFactory.managed().allocate(4, ByteOrder.BIG_ENDIAN)
    buf.writeByte(0xC3.toByte())
    buf.writeByte(0x28.toByte())
    buf.writeByte(0xFF.toByte())
    buf.writeByte(0x41.toByte())
    buf.resetForRead()
    buf.setLimit(4)
    return buf
}

/** `héllo` in UTF-8 — the same shape as [invalidUtf8], multi-byte, but legal. */
private fun validUtf8(): ReadBuffer {
    val buf = BufferFactory.managed().allocate(6, ByteOrder.BIG_ENDIAN)
    for (b in listOf(0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F)) buf.writeByte(b.toByte())
    buf.resetForRead()
    buf.setLimit(6)
    return buf
}

/**
 * RFC 8831 §6.6 requires a `WebRTC String` message to be UTF-8; a peer is under no obligation to comply.
 * Decoding one is the only place this stack turns attacker-supplied bytes into a higher type, so it is the
 * only place that can fail — and it must fail as a **value**, not as a throw into the serialized drive
 * loop, which would take the whole association down with it (T0 discipline).
 *
 * The two fixtures here are a **discriminating pair**, and the second is what gives the first its meaning.
 * `a malformed message is discarded` on its own would pass just as green on a stack that had stopped
 * delivering anything at all; `the same timeline with valid bytes delivers` is what rules that out. Both
 * drive an identical timeline and differ only in the four bytes on the wire.
 *
 * Neither can be written through the public API — [DataChannelPayload.Text] holds characters precisely so
 * that an invalid string message is unconstructible — so both go through
 * [SctpDataChannelStack.sendUnencoded], which exists for this and nothing else.
 *
 * Worth stating because it was measured rather than assumed: `readString` throws on all four targets
 * checked (JVM `MalformedInputException`, Apple and wasmJs `CharacterCodingException`, JS a `TypeError`
 * with no Kotlin class name), which is why [SctpDataChannelStack.payloadFor] catches `Throwable` rather
 * than any named type. A target that instead substituted U+FFFD would deliver the message and leave
 * `discardedInbound` at zero — which is exactly what the first fixture below would catch.
 */
class MalformedTextMessageTest {
    private fun TestScope.clock(): () -> Instant = { EPOCH + testScheduler.currentTime.milliseconds }

    @Test
    fun a_string_message_with_invalid_utf8_is_discarded_and_never_delivered() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(71))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(72))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "text")) as DataChannelConnection
            val incoming = server.acceptBidirectional() as DataChannelConnection

            val bad = invalidUtf8()
            try {
                client.sendUnencoded(channel.streamId, PayloadProtocolId.WebRtcString, channel.config, bad)
            } finally {
                bad.freeIfNeeded()
            }
            // A sentinel behind it on the same stream. Ordered delivery means that if the malformed message
            // were delivered, it would arrive FIRST — so asserting the sentinel is what arrives proves the
            // discard, and proves the association kept running rather than dying on the decode.
            channel.send(DataChannelPayload.Binary(textBytes("after")))

            assertEquals("after", incoming.receive().first().expectBinaryAsString(), "the sentinel is the FIRST message delivered")
            assertEquals(1, server.discardedInbound, "exactly one message was discarded")

            client.shutdown()
        }

    @Test
    fun the_same_timeline_with_valid_utf8_delivers_a_text_message() =
        runTest {
            val pair = MemoryTransportPair(backgroundScope)
            val client = SctpDataChannelStack(pair.clientTransport, backgroundScope, clock(), SctpRole.Client, random = Random(73))
            val server = SctpDataChannelStack(pair.serverTransport, backgroundScope, clock(), SctpRole.Server, random = Random(74))
            client.start()
            server.start()

            val channel = client.open(DataChannelConfig(label = "text")) as DataChannelConnection
            val incoming = server.acceptBidirectional() as DataChannelConnection

            val good = validUtf8()
            try {
                client.sendUnencoded(channel.streamId, PayloadProtocolId.WebRtcString, channel.config, good)
            } finally {
                good.freeIfNeeded()
            }
            channel.send(DataChannelPayload.Binary(textBytes("after")))

            // Same wire path, same PPID, same sentinel behind it — only the four bytes differ. Here the
            // string message DOES arrive, first, and as Text: the discard above was about the bytes.
            assertEquals(
                "héllo",
                incoming
                    .receive()
                    .first()
                    .expectText()
                    .toString(),
                "a legal string message is delivered as Text",
            )
            assertEquals(0, server.discardedInbound, "nothing was discarded on the legal timeline")

            client.shutdown()
        }

    /** ASCII bytes as a buffer, for the binary sentinel — deliberately not a `DataChannelPayload.Text`. */
    private fun textBytes(s: String): ReadBuffer {
        val buf = BufferFactory.managed().allocate(s.length, ByteOrder.BIG_ENDIAN)
        for (c in s) buf.writeByte(c.code.toByte())
        buf.resetForRead()
        buf.setLimit(s.length)
        return buf
    }
}
