package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.flow.Connection
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlin.jvm.JvmInline

/**
 * Bytes of application data queued on one data channel and not yet handed to the wire — W3C
 * `RTCDataChannel.bufferedAmount`.
 *
 * A value class rather than a `Long`, for the reason every identifier here is one: the two numbers a caller
 * holds at a `bufferedAmount` call site are a *depth* and a *threshold*, both counts of bytes, and the
 * compiler cannot tell them apart while they are `Long`s. It cannot tell them apart now either — they are
 * the same type — but a `Long` from somewhere else (a message size, a window) can no longer be passed by
 * accident, and that is the mistake worth foreclosing.
 *
 * Counts **application** bytes only (see [com.ditchoom.webrtc.sctp.association.SendOrigin]): the stack's own
 * RFC 8832 DCEP OPEN and ACK ride the same stream and are not something the application queued or can
 * drain.
 */
@JvmInline
public value class BufferedAmount(
    public val bytes: Long,
) : Comparable<BufferedAmount> {
    init {
        require(bytes >= 0L) { "a buffered amount cannot be negative, was $bytes" }
    }

    override fun compareTo(other: BufferedAmount): Int = bytes.compareTo(other.bytes)

    override fun toString(): String = "BufferedAmount($bytes bytes)"

    public companion object {
        /** Nothing queued — the threshold that means "wait until the channel has fully drained". */
        public val ZERO: BufferedAmount = BufferedAmount(0L)
    }
}

/**
 * A data channel that reports how much it still has queued (W3C `bufferedAmount` /
 * `bufferedamountlow`), for a producer that wants to pace itself explicitly rather than by suspension.
 *
 * `send()` already provides backpressure by suspending, and for the ordinary producer loop that is the whole
 * contract and this interface is unnecessary. It exists for the callers suspension cannot serve: a
 * `requestAnimationFrame`-shaped loop that must decide *whether to produce at all* this tick, and a
 * multiplexer choosing which of several channels to feed. Both need to ask rather than be blocked.
 *
 * ## Deliberate departure from the W3C API
 *
 * W3C spells the threshold as a mutable property, `bufferedAmountLowThreshold`, paired with an
 * `onbufferedamountlow` event. **Here it is a parameter of the wait**, and a reviewer scanning for the W3C
 * name will not find a property, so: the property form *requires* a stored latch correlated with the
 * current amount, and that pair admits states the event has no meaning in — "the threshold was lowered
 * while an event was pending", and "the latch is armed although the amount is already below the
 * threshold". Each needs its own rule about whether the event still fires, and every implementation
 * answers differently. Passing the threshold to [awaitBufferedAmountLow] stores nothing: there is no latch,
 * no correlated pair, and no state to get wrong — the wait is a predicate over a value the channel already
 * publishes.
 *
 * The port is mechanical:
 * ```
 * dc.bufferedAmountLowThreshold = 65536;      →   channel.awaitBufferedAmountLow(BufferedAmount(65_536))
 * dc.onbufferedamountlow = () => { … };
 * ```
 */
public interface BufferedDataChannel : Connection<DataChannelPayload> {
    /**
     * How much this channel currently has queued, as a stream.
     *
     * Republished once per drive-loop item rather than per byte: it is a **projection** of the association's
     * unsent queue, so it cannot disagree with what is actually queued — the alternative, a counter this
     * class maintained itself, is two sources of truth for one quantity and drifts the first time a fragment
     * leaves the queue by a path nobody instrumented. A closed channel publishes
     * [BufferedAmount.ZERO]; there is nothing left to drain, and a waiter must not be stranded by a close.
     */
    public val bufferedAmount: StateFlow<BufferedAmount>

    /**
     * Suspend until this channel has at most [threshold] bytes queued — W3C's `bufferedamountlow`, as a
     * wait rather than an event. Returns immediately when the channel is already at or below it.
     *
     * Defaults to [BufferedAmount.ZERO], i.e. fully drained, because that is the one threshold with a
     * meaning that does not depend on the caller's own sizing.
     */
    public suspend fun awaitBufferedAmountLow(threshold: BufferedAmount = BufferedAmount.ZERO) {
        bufferedAmount.first { it <= threshold }
    }
}
