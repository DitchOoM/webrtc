@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The seeded [Impairment] pipe must be **replayable** (directive #2) — same seed, same outcome, forever
 * — and it must ride virtual time so a jittered link costs zero wall-clock. These are the invariants a
 * timeline-fuzz campaign depends on: a shrinker can only work if a scenario reproduces bit-for-bit.
 */
@OptIn(ExperimentalDatagramApi::class)
class VnetImpairmentTest {
    private val sender = vnetAddress("10.0.0.2", 5000)
    private val receiver = vnetAddress("10.0.0.3", 6000)

    @Test
    fun seeded_loss_is_deterministic_and_actually_drops() =
        runTest {
            val first = runLink(backgroundScope, ImpairmentConfig(loss = 0.5), seed = 1234)
            val second = runLink(backgroundScope, ImpairmentConfig(loss = 0.5), seed = 1234)
            assertEquals(first, second, "same seed ⇒ identical survivors, in identical order")
            assertTrue(first.size in 1 until COUNT, "loss=0.5 drops some but not all of $COUNT datagrams (got ${first.size})")

            val other = runLink(backgroundScope, ImpairmentConfig(loss = 0.5), seed = 9876)
            assertTrue(other != first, "a different seed draws a different survivor set")
        }

    @Test
    fun delay_reorders_but_never_loses_or_duplicates() =
        runTest {
            val config = ImpairmentConfig(minDelay = 10.milliseconds, maxDelay = 200.milliseconds)
            val arrivals = runLink(backgroundScope, config, seed = 42)
            assertEquals(COUNT, arrivals.size, "a lossless jittered link delivers every datagram exactly once")
            assertEquals((0 until COUNT).map { "d$it" }.toSet(), arrivals.toSet(), "every datagram arrives, whole")
            // Determinism holds for the reordered sequence too.
            assertEquals(arrivals, runLink(backgroundScope, config, seed = 42), "same seed ⇒ identical arrival order")
        }

    private suspend fun runLink(
        scope: CoroutineScope,
        config: ImpairmentConfig,
        seed: Long,
    ): List<String> {
        // Fresh vnet per run so the two runs are independent; the seed alone determines the outcome.
        val fabric = Impairment(config, scope, seed, base = DirectFabric)
        val vnet = Vnet(bufferFactory = BufferFactory.Default, fabric = fabric)
        val out = vnet.bind(sender)
        val inbound = vnet.bind(receiver)
        repeat(COUNT) { i -> out.send(payload("d$i"), to = receiver) }
        return drain(inbound)
    }

    private suspend fun drain(channel: DatagramChannel): List<String> {
        val arrivals = mutableListOf<String>()
        while (true) {
            val datagram = channel.receiveWithin(DRAIN_WINDOW) ?: break
            arrivals += datagram.text()
        }
        return arrivals
    }

    private fun payload(text: String): ReadBuffer {
        val buffer = BufferFactory.Default.allocate(text.length)
        buffer.writeString(text, Charset.UTF8)
        buffer.resetForRead()
        return buffer
    }

    private fun Datagram.text(): String = payload.readString(payload.remaining(), Charset.UTF8)

    private suspend fun DatagramChannel.receiveWithin(within: Duration): Datagram? =
        withTimeoutOrNull(within) {
            when (val result = receive()) {
                is DatagramReadResult.Received -> result.datagram
                is DatagramReadResult.Closed -> null
            }
        }

    private companion object {
        const val COUNT = 40
        val DRAIN_WINDOW = 2.seconds
    }
}
