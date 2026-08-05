@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
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

    /**
     * Kill the wire in both directions, so each stack's `receive()` returns null and each tears itself
     * down. One endpoint's `close()` only closes what *it* sends, which reaches the peer and not itself —
     * so a fixture that wants both sides down has to say so.
     *
     * Whatever is still in flight is dropped here, and dropping it means releasing it: these copies were
     * transferred to the receiving stack and it will now never read them.
     */
    fun cutWire() {
        aToB.close()
        bToA.close()
        drain(aToB)
        drain(bToA)
    }

    private fun drain(channel: Channel<ReadBuffer>) {
        while (true) {
            val buffer = channel.tryReceive().getOrNull() ?: break
            buffer.freeIfNeeded()
        }
    }

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
        // The slice exists only so the copy can read `packet` without disturbing its cursor, and it is
        // dead the moment the copy is made. Releasing it is NOT optional: on a pooled buffer `slice()` is
        // `addRef()`, so a harness that drops it pins one chunk of the code under test per datagram sent —
        // and reports it as a production leak. (This fixture-shaped false positive has cost this repo a
        // real investigation before; see CLAUDE.md on `TestNet.copyOf`.)
        val slice = packet.slice()
        return try {
            val len = slice.remaining()
            val copy = BufferFactory.Default.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
            copy.write(slice)
            copy.resetForRead()
            copy.setLimit(len)
            copy
        } finally {
            slice.freeIfNeeded()
        }
    }
}
