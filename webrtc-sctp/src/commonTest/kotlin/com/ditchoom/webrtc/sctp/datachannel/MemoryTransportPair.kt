@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.ExperimentalTime

/**
 * An in-memory [SctpDatagramTransport] pair — the plaintext stand-in for the DTLS record layer over an
 * ICE pair (HANDOFF W5: the AddressedDatagramChannel-shaped seam DTLS later fills). Datagrams cross via unbounded
 * channels; an optional seeded loss/delay lets a test drive the association's retransmission paths under
 * `runTest` virtual time (delays ride `delay()`, so wall-clock stays zero).
 */
internal class MemoryTransportPair(
    private val scope: CoroutineScope,
    private val lossRate: Double = 0.0,
    private val delay: Duration = Duration.ZERO,
    seed: Long = 42L,
) {
    private val aToB = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val bToA = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val random = Random(seed)

    val clientTransport: SctpDatagramTransport = Endpoint(aToB, bToA)
    val serverTransport: SctpDatagramTransport = Endpoint(bToA, aToB)

    private inner class Endpoint(
        private val sendCh: Channel<ReadBuffer>,
        private val recvCh: Channel<ReadBuffer>,
    ) : SctpDatagramTransport {
        override suspend fun send(packet: ReadBuffer) {
            packet.position(0)
            // A real COPY, not `packet.slice()`. `receive()` transfers ownership to the SCTP stack, which
            // releases what it is handed — and a slice takes a reference on the *sender's* chunk, so the
            // receiver's release would free a buffer the sender still owns. A wire is a copy anyway; the
            // slice was only ever standing in for one.
            val copy = copyOf(packet)
            if (lossRate > 0.0 && random.nextDouble() < lossRate) return
            if (delay == Duration.ZERO) {
                sendCh.trySend(copy)
            } else {
                scope.launch {
                    delay(delay)
                    sendCh.trySend(copy)
                }
            }
        }

        override suspend fun receive(): ReadBuffer? = recvCh.receiveCatching().getOrNull()

        override fun close() {
            sendCh.close()
        }
    }

    private fun copyOf(packet: ReadBuffer): ReadBuffer {
        val slice = packet.slice()
        val len = slice.remaining()
        val copy = BufferFactory.Default.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
        copy.write(slice)
        copy.resetForRead()
        copy.setLimit(len)
        return copy
    }
}
