package com.ditchoom.webrtc.sctp.association

import kotlin.jvm.JvmInline

/** One overrun window is the advertised window itself, which is the smallest ceiling that is not a lie. */
private const val SMALLEST_OVERRUN_WINDOWS = 1

/** See [ReceiveOverrunWindows.Default] for why the default is two windows rather than one. */
private const val DEFAULT_OVERRUN_WINDOWS = 2

/**
 * A claim on receive-buffer space that one delivered message occupies until the upper layer has finished
 * with it (RFC 4960 §6.2's a_rwnd, from the receiver's side).
 *
 * Handed out with every [SctpOutput.MessageReceived] and handed back as [SctpEvent.MessageConsumed]. Until
 * it comes back the message's bytes are still counted against the window this endpoint advertises, so a
 * peer that outruns the application is told to stop *by the protocol* rather than by an unbounded queue
 * quietly growing behind the delivery flow.
 *
 * The constructor is **internal**, which is the whole type-safety argument: a receipt cannot be minted by a
 * caller, only returned. A forged one would credit bytes that were never charged, and the window would then
 * advertise space the receiver does not have — an over-advertisement is invisible until memory runs out,
 * which is the one failure mode in this file that no test would catch. [ticket] is readable so a driver can
 * key its own bookkeeping on it; it is an opaque ordinal and carries no meaning beyond identity.
 *
 * Crediting the same receipt twice credits **once**: the window keeps the charge per ticket, so a driver
 * that both frees a held message and later sees it consumed cannot open the window past its capacity.
 */
@JvmInline
public value class DeliveryReceipt internal constructor(
    public val ticket: Long,
) {
    override fun toString(): String = "DeliveryReceipt(#$ticket)"
}

/**
 * How far above the advertised window this endpoint will still **store** an arriving DATA chunk, measured
 * in whole windows (RFC 4960 §6.2's want-of-buffer drop).
 *
 * ## The deliberate departure from RFC 4960 §6.2
 *
 * RFC 4960 §6.2 says a receiver with no buffer space *"SHOULD drop the DATA chunk"*, and reads as though
 * the test is against the window it advertised. **Applied there it deadlocks a receiver whose buffer is
 * full of half-reassembled messages.** The chunks that would complete those messages — and therefore
 * release every byte they hold — are exactly the ones above the highest TSN received, i.e. exactly the ones
 * a window-tight drop refuses. The receiver then advertises zero forever, the sender probes forever, and
 * nothing in the protocol breaks the tie.
 *
 * So the drop rule is applied at an **overrun ceiling** of `advertised window × [value]`, not at the
 * advertised window. Between the two the receiver keeps accepting: it has told the peer to stop, and it
 * absorbs what was already in flight (plus what completes a partial message) instead of discarding work.
 * **dcSCTP and usrsctp deviate the same way**, for the same reason — this is the deployed behaviour, not a
 * local invention.
 *
 * [Default] is two windows: one whole extra window of slack above the advertised zero. One window would put
 * the ceiling *at* the advertised window and re-create the deadlock exactly, which is why
 * [SMALLEST_OVERRUN_WINDOWS] is a floor rather than the default — a caller that deliberately wants the
 * literal §6.2 behaviour can ask for it, and nobody gets it by leaving the knob alone.
 */
@JvmInline
public value class ReceiveOverrunWindows(
    public val value: Int,
) {
    init {
        require(value >= SMALLEST_OVERRUN_WINDOWS) {
            "receiveOverrun must be at least $SMALLEST_OVERRUN_WINDOWS window, was $value"
        }
    }

    public companion object {
        /** Two windows — see the class KDoc for why one is a floor and not a default. */
        public val Default: ReceiveOverrunWindows = ReceiveOverrunWindows(DEFAULT_OVERRUN_WINDOWS)
    }
}

/**
 * The receive-buffer accountant (RFC 4960 §3.3.2 a_rwnd, §6.2 receiver): what this endpoint advertises it
 * can still take, and how much it will store above that before dropping.
 *
 * **Association-scoped, deliberately outside the [Tcb].** A [DeliveryReceipt] can come back after the
 * control block it was issued under is gone — the driver is a coroutine and the teardown is another — and a
 * window living inside the TCB would make that credit a null check at every call site rather than the no-op
 * it should be. [forgetAll] is what a teardown does instead: the charges of a dead association are dropped
 * whole, so a late credit for one of them finds nothing and changes nothing.
 *
 * Two quantities are held against the window and only one of them lives here. Bytes the reassembly queue is
 * still holding — stored fragments, and messages assembled but waiting on a Stream Sequence Number — are
 * that queue's own running total, passed in at each call. Bytes already delivered upward and not yet
 * consumed are this object's. Splitting them that way is what keeps the queue's release paths from having
 * to remember a second bookkeeping step: it frees a fragment and its total falls, with nothing else to
 * update (the fused-credit argument, one layer down from `InboundDelivery.discard`).
 */
internal class ReceiveWindow(
    private val capacity: UInt,
    overrun: ReceiveOverrunWindows,
) {
    // Long, because `capacity * windows` overflows a UInt for any capacity above 2 GiB / windows.
    private val overrunCeiling: Long = capacity.toLong() * overrun.value

    // ticket -> bytes charged. The map, rather than a byte count on the receipt itself, is what makes a
    // second credit for one message a no-op instead of an over-credit (see [DeliveryReceipt]).
    private val charges = HashMap<Long, Int>()
    private var deliveredBytes: Long = 0
    private var nextTicket: Long = 0

    /** Bytes delivered upward and not yet credited back — test-visible, and the anti-vacuity read. */
    val outstandingBytes: Long get() = deliveredBytes

    /**
     * The a_rwnd to advertise (RFC 4960 §3.3.2), given what the reassembly queue is currently holding.
     *
     * Floors at zero rather than going negative, because the overrun ceiling admits more than the window
     * and "I have taken more than I said I could" is spelled `0` on the wire, not as a wrapped u32.
     */
    fun advertised(heldForReassembly: Int): UInt {
        val free = capacity.toLong() - heldForReassembly.toLong() - deliveredBytes
        return if (free <= 0L) 0u else free.toUInt()
    }

    /**
     * Whether an arriving chunk of [incoming] bytes may still be stored — the RFC 4960 §6.2 drop test,
     * applied at the overrun ceiling (see [ReceiveOverrunWindows]).
     */
    fun admits(
        heldForReassembly: Int,
        incoming: Int,
    ): Boolean = heldForReassembly.toLong() + deliveredBytes + incoming <= overrunCeiling

    /** Charge [bytes] to the window for a message leaving for the upper layer, and name the charge. */
    fun issue(bytes: Int): DeliveryReceipt {
        val ticket = nextTicket
        nextTicket += 1
        charges[ticket] = bytes
        deliveredBytes += bytes
        return DeliveryReceipt(ticket)
    }

    /**
     * Return the space [receipt] was holding. Returns the bytes credited, which is **0** for a receipt that
     * was already credited or that belongs to an association that has since been torn down — both are
     * ordinary, and neither may move the window.
     */
    fun credit(receipt: DeliveryReceipt): Int {
        val bytes = charges.remove(receipt.ticket) ?: return 0
        deliveredBytes -= bytes
        return bytes
    }

    /** The association is going away: drop every outstanding charge, so a late credit finds nothing. */
    fun forgetAll() {
        charges.clear()
        deliveredBytes = 0
    }
}
