@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import kotlin.time.Duration
import kotlin.time.ExperimentalTime

/**
 * The RTO estimator (RFC 4960 §6.3.1, the RFC 6298 recurrence). Pure arithmetic over injected RTT
 * samples — no clock inside; the driver passes the measured round-trip [Duration]. Karn's algorithm
 * (RFC 4960 §6.3.1 C5) lives in the caller: it only feeds [observe] a sample from a DATA chunk that was
 * **not** retransmitted, so an ambiguous ack never corrupts SRTT.
 */
internal class RttEstimator(
    private val config: SctpConfig,
) {
    private var srtt: Duration = Duration.ZERO
    private var rttvar: Duration = Duration.ZERO
    private var hasSample = false

    /** The current retransmission timeout, clamped to `[rtoMin, rtoMax]`; RTO.Initial before any sample. */
    var rto: Duration = config.rtoInitial
        private set

    /** Fold one unambiguous RTT sample into SRTT/RTTVAR and recompute [rto] (RFC 4960 §6.3.1 C2/C3). */
    fun observe(sample: Duration) {
        if (!hasSample) {
            srtt = sample
            rttvar = sample / 2
            hasSample = true
        } else {
            val delta = (srtt - sample).absoluteValue
            rttvar = rttvar * (BETA_DEN - 1) / BETA_DEN + delta / BETA_DEN
            srtt = srtt * (ALPHA_DEN - 1) / ALPHA_DEN + sample / ALPHA_DEN
        }
        rto = (srtt + rttvar * K).coerceIn(config.rtoMin, config.rtoMax)
    }

    /** Double the RTO on a T3-rtx expiry (RFC 4960 §6.3.3 E2), clamped to RTO.Max. */
    fun backoff() {
        rto = (rto * 2).coerceAtMost(config.rtoMax)
    }

    private companion object {
        // alpha = 1/8, beta = 1/4 (RFC 4960 §6.3.1); K = 4 (the RTTVAR multiplier in the RTO formula).
        private const val ALPHA_DEN = 8
        private const val BETA_DEN = 4
        private const val K = 4
    }
}

/**
 * The congestion controller (RFC 4960 §7.2): slow start, congestion avoidance, and the cwnd collapse on
 * loss. Pure state over bytes — the association tells it what was acked and when a retransmit fired; it
 * owns cwnd/ssthresh/partial-bytes-acked. One path only (the dcSCTP subset has no multihoming, RFC
 * §11.2), so there is a single cwnd, not a per-destination table.
 */
internal class CongestionControl(
    private val config: SctpConfig,
    peerAdvertisedRwnd: UInt,
) {
    private val mtu: Int = config.maxPayloadBytes

    /** Congestion window in bytes — the cap on outstanding (unacknowledged) data (RFC 4960 §7.2.1). */
    var cwnd: Int = config.initialCwndMtus * mtu
        private set

    /** Slow-start threshold (RFC 4960 §7.2.1): initialized to the peer's advertised receive window. */
    var ssthresh: Int = peerAdvertisedRwnd.toInt().coerceAtLeast(config.initialCwndMtus * mtu)
        private set

    private var partialBytesAcked = 0

    /**
     * Grow cwnd for [bytesAcked] newly-acknowledged bytes (RFC 4960 §7.2.1/§7.2.2). [fullyUtilized] is
     * whether cwnd was being fully used before this ack — the RFC only grows the window when the sender
     * was actually cwnd-limited, so an idle sender does not inflate cwnd.
     */
    fun onDataAcked(
        bytesAcked: Int,
        fullyUtilized: Boolean,
    ) {
        if (bytesAcked <= 0 || !fullyUtilized) return
        if (cwnd <= ssthresh) {
            // Slow start: increase by min(bytes acked, MTU) per SACK that advances the cum ack.
            cwnd += minOf(bytesAcked, mtu)
        } else {
            // Congestion avoidance: at most one MTU per RTT, paced by partial_bytes_acked.
            partialBytesAcked += bytesAcked
            if (partialBytesAcked >= cwnd) {
                partialBytesAcked -= cwnd
                cwnd += mtu
            }
        }
    }

    /** T3-rtx timeout collapse (RFC 4960 §7.2.3): ssthresh = max(cwnd/2, 4*MTU), cwnd = MTU. */
    fun onTimeout() {
        ssthresh = maxOf(cwnd / 2, MIN_SSTHRESH_MTUS * mtu)
        cwnd = mtu
        partialBytesAcked = 0
    }

    /** Fast-retransmit collapse (RFC 4960 §7.2.4): ssthresh = max(cwnd/2, 4*MTU), cwnd = ssthresh. */
    fun onFastRetransmit() {
        ssthresh = maxOf(cwnd / 2, MIN_SSTHRESH_MTUS * mtu)
        cwnd = ssthresh
        partialBytesAcked = 0
    }

    private companion object {
        private const val MIN_SSTHRESH_MTUS = 4
    }
}
