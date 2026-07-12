@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.ReadBuffer
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The client-side retransmission policy for a STUN request over an unreliable transport
 * (RFC 8489 §6.2.1). Defaults are the RFC's: an initial [rto] of 500 ms, [maxTransmissions] `Rc` = 7
 * requests total, the RTO doubling after each, and a final wait of `Rm` × RTO ([finalWaitRtoMultiple]
 * = 16) after the last request before the transaction is declared timed out.
 */
public data class StunRetransmitPolicy(
    public val rto: Duration = DEFAULT_RTO,
    public val maxTransmissions: Int = DEFAULT_RC,
    public val finalWaitRtoMultiple: Int = DEFAULT_RM,
) {
    init {
        require(maxTransmissions >= 1) { "Rc must be >= 1" }
        require(finalWaitRtoMultiple >= 1) { "Rm must be >= 1" }
    }

    public companion object {
        /** RFC 8489 §6.2.1 default initial RTO. */
        public val DEFAULT_RTO: Duration = 500.milliseconds

        /** RFC 8489 §6.2.1 `Rc`: total requests sent before giving up. */
        public const val DEFAULT_RC: Int = 7

        /** RFC 8489 §6.2.1 `Rm`: multiple of RTO to wait after the last request. */
        public const val DEFAULT_RM: Int = 16
    }
}

/** An event fed to a [StunTransaction] (sans-io: the driver owns I/O and the clock). */
public sealed interface StunTransactionEvent {
    /** Kick off the transaction: send the first request and arm the first retransmit timer. */
    public data object Start : StunTransactionEvent

    /** The retransmit/timeout timer reached [StunTransaction.nextDeadline]. */
    public data object TimerExpired : StunTransactionEvent

    /** A candidate response arrived (already parsed); ignored unless its transaction id matches. */
    public data class ResponseReceived(
        public val message: StunMessage,
    ) : StunTransactionEvent
}

/** A side effect the driver must perform, returned from [StunTransaction.handle]. */
public sealed interface StunTransactionOutput {
    /** Transmit these request bytes on the wire (the same buffer each time — a retransmission). */
    public data class SendRequest(
        public val datagram: ReadBuffer,
    ) : StunTransactionOutput

    /** The matching success/error response arrived; the transaction is done. */
    public data class Completed(
        public val response: StunMessage,
    ) : StunTransactionOutput

    /** No response after `Rc` requests + the final wait; the transaction failed. */
    public data class Failed(
        public val reason: StunTransactionFailure,
    ) : StunTransactionOutput
}

/** Why a [StunTransaction] terminated unsuccessfully — a typed reason, never a string (directive #3). */
public sealed interface StunTransactionFailure {
    /** `Rc` requests were sent and the final `Rm × RTO` wait elapsed with no response. */
    public data object TimedOut : StunTransactionFailure
}

/**
 * A single sans-io STUN client transaction (RFC 8489 §6.2). It owns **truth, not I/O**: a pure
 * `handle(event, now): List<Output>` plus [nextDeadline] — no dispatcher, no clock, no socket, no
 * coroutine (DESIGN_PRINCIPLES §6). The driver reads the clock, performs [StunTransactionOutput]s,
 * and re-arms its timer from [nextDeadline]; the same machine therefore runs under `runTest` virtual
 * time on every platform.
 *
 * Retransmission follows [policy]: request #1 on [StunTransactionEvent.Start], then a retransmit each
 * time the timer expires with the RTO doubling, up to `Rc` requests, then one final `Rm × RTO` wait
 * before [StunTransactionFailure.TimedOut]. The transaction id in [request] must be [transactionId]
 * (seeded entropy is injected upstream — see [TransactionId.random]); responses whose id differs are
 * ignored, so a driver may fan one datagram out to several live transactions.
 */
public class StunTransaction(
    public val transactionId: TransactionId,
    private val request: ReadBuffer,
    private val policy: StunRetransmitPolicy = StunRetransmitPolicy(),
) {
    private var transmissions = 0
    private var armedDeadline: Instant? = null
    private var currentInterval: Duration = policy.rto
    private var awaitingFinalWait = false
    private var terminal = false

    /** The armed retransmit/timeout instant, or null when none is pending (not started, or terminal). */
    public fun nextDeadline(): Instant? = armedDeadline

    /** True once the transaction has completed or failed; further events are no-ops. */
    public val isTerminal: Boolean get() = terminal

    public fun handle(
        event: StunTransactionEvent,
        now: Instant,
    ): List<StunTransactionOutput> {
        if (terminal) return emptyList()
        return when (event) {
            StunTransactionEvent.Start -> onStart(now)
            StunTransactionEvent.TimerExpired -> onTimer(now)
            is StunTransactionEvent.ResponseReceived -> onResponse(event.message)
        }
    }

    private fun onStart(now: Instant): List<StunTransactionOutput> {
        if (transmissions != 0) return emptyList() // idempotent: Start only fires once
        transmissions = 1
        currentInterval = policy.rto
        armAfterSend(now)
        return listOf(StunTransactionOutput.SendRequest(request))
    }

    private fun onTimer(now: Instant): List<StunTransactionOutput> {
        if (awaitingFinalWait) {
            terminal = true
            armedDeadline = null
            return listOf(StunTransactionOutput.Failed(StunTransactionFailure.TimedOut))
        }
        transmissions++
        currentInterval *= 2 // RTO, 2·RTO, 4·RTO, … (RFC 8489 §6.2.1)
        armAfterSend(now)
        return listOf(StunTransactionOutput.SendRequest(request))
    }

    // After sending the k-th request, arm either the next (doubled) retransmit or, once the Rc-th
    // request has gone out, the single final Rm × RTO wait before timing out (RFC 8489 §6.2.1).
    private fun armAfterSend(now: Instant) {
        armedDeadline =
            if (transmissions >= policy.maxTransmissions) {
                awaitingFinalWait = true
                now + policy.rto * policy.finalWaitRtoMultiple
            } else {
                now + currentInterval
            }
    }

    private fun onResponse(message: StunMessage): List<StunTransactionOutput> {
        if (message.transactionId != transactionId) return emptyList()
        terminal = true
        armedDeadline = null
        return listOf(StunTransactionOutput.Completed(message))
    }
}
