@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.use
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.random.Random
import kotlin.time.Duration

/**
 * The knobs of a lossy virtual link. [loss] and [duplicate] are per-datagram probabilities; wire delay
 * is drawn uniformly in `[minDelay, maxDelay]`, and **reordering is emergent** — two datagrams that
 * draw different delays arrive out of order — so there is no separate reorder knob to keep consistent.
 */
internal data class ImpairmentConfig(
    val loss: Double = 0.0,
    val duplicate: Double = 0.0,
    val minDelay: Duration = Duration.ZERO,
    val maxDelay: Duration = Duration.ZERO,
) {
    init {
        require(loss in 0.0..1.0 && duplicate in 0.0..1.0) { "loss/duplicate must be probabilities" }
        require(minDelay <= maxDelay) { "minDelay must not exceed maxDelay" }
    }
}

/**
 * A seeded impairment pipe — the vnet analogue of `netem`. It wraps a [base] [Fabric] (typically [Nat]
 * or [DirectFabric]) and, per datagram, draws a **fixed number of values** from one `Random(seed)` (so
 * the stream is independent of which branch is taken and the scenario replays identically forever,
 * directive #2), then drops, delays, and/or duplicates the datagram. Delay is realized with [delay]
 * against the injected [scope], so it rides `runTest` virtual time — a 200 ms jittered link costs zero
 * wall-clock and reorders deterministically.
 *
 * Impairment sits **outside** NAT: each datagram is impaired once, end-to-end, and the surviving copies
 * are then translated by [base]. Because a reply is only ever sent after its request is delivered,
 * deferring [base] to delivery time preserves causality even under reordering.
 */
internal class Impairment(
    private val config: ImpairmentConfig,
    private val scope: CoroutineScope,
    seed: Long,
    private val base: Fabric = DirectFabric,
    private val bufferFactory: BufferFactory = BufferFactory.Default,
) : Fabric {
    @Suppress("UnseamedEntropy") // test-only seam; the seed IS the injected entropy for replay
    private val rng = Random(seed)

    override fun forward(
        from: SocketAddress,
        to: SocketAddress,
        payload: ReadBuffer,
        net: Vnet,
    ) {
        // Draw a fixed 4 values per datagram regardless of outcome — a stable RNG stream: drop roll,
        // duplicate roll, and two delay fractions.
        val dropRoll = rng.nextDouble()
        val duplicateRoll = rng.nextDouble()
        val delayA = delayFor(rng.nextDouble())
        val delayB = delayFor(rng.nextDouble())

        if (dropRoll < config.loss) return // dropped on the wire; the RNG has still advanced

        // ONE snapshot per scheduled delivery, never one shared by both. A duplicate is a second datagram
        // on the wire, and giving each its own copy keeps the rule this repo runs on — a buffer has exactly
        // one owner — true here too, instead of needing a shared count to decide which coroutine frees it.
        schedule(delayA, snapshot(payload), from, to, net)
        if (duplicateRoll < config.duplicate) {
            schedule(delayB, snapshot(payload), from, to, net)
        }
    }

    private fun delayFor(fraction: Double): Duration = config.minDelay + (config.maxDelay - config.minDelay) * fraction

    // The launched coroutine OWNS [snapshot], and `use` is what releases it on every way out — including
    // the cancellation path, where a scenario torn down mid-flight would otherwise strand every datagram
    // still in the pipe.
    private fun schedule(
        after: Duration,
        snapshot: PlatformBuffer,
        from: SocketAddress,
        to: SocketAddress,
        net: Vnet,
    ) {
        // ATOMIC because the alternative silently loses the snapshot: a datagram forwarded while the
        // scenario is being torn down launches into an already-cancelled scope, where a default-started
        // coroutine never runs its body at all — so the `use` that owes the release never executes.
        scope.launch(start = CoroutineStart.ATOMIC) {
            snapshot.use {
                if (after > Duration.ZERO) delay(after)
                base.forward(from, to, it, net)
            }
        }
    }

    // Copy the payload before send() returns so a deferred delivery still sees it (the caller may pool).
    //
    // The probe slice is a borrow — and an `addRef` on a pooled parent — so dropping it would pin the
    // SENDER's chunk. See Vnet.copyOf, which pays for the same slice one layer down.
    private fun snapshot(payload: ReadBuffer): PlatformBuffer {
        val slice = payload.slice()
        return try {
            val len = slice.remaining()
            val copy: PlatformBuffer = bufferFactory.allocate(maxOf(1, len))
            copy.write(slice)
            copy.resetForRead()
            copy.setLimit(len)
            copy
        } finally {
            slice.freeIfNeeded()
        }
    }
}
