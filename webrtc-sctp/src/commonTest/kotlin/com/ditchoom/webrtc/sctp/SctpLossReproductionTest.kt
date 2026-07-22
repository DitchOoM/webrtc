@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.association.SctpAssociation
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpEvent
import com.ditchoom.webrtc.sctp.association.SctpOutput
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **Deterministic reproduction of the L2 `impaired-loss-delay` stall at the SCTP layer** — the sibling of
 * [com.ditchoom.webrtc.dtls]'s `DtlsLossReproductionTest`, one protocol layer up. The
 * `PeerConnectionState` trace the harness now prints (PR #26) pinned the intermittent impaired-lane
 * failure on an **asymmetry**: the offerer reaches `Connected` (its SCTP association `Established`) while
 * the answerer sits in `Connecting` — i.e. its SCTP handshake never completes — for the whole 90 s
 * watchdog, with no typed `Failed`. `Connected` requires SCTP `Established` (PeerConnection.runEstablishment),
 * so the stall is in the four-way handshake under loss.
 *
 * Two pure sans-io [SctpAssociation]s (active client + passive server) run the four-way handshake over an
 * in-memory pipe with **scripted, seeded** per-datagram loss under the engine's injected virtual clock —
 * so retransmission timing is 100 % deterministic and replays at zero wall-clock. A given seed always
 * produces the same outcome; there is no flake here, only the mechanism. Loss is per emitted packet: each
 * [SctpOutput.Transmit] is its own datagram the driver `send`s, so each is independently exposed to the
 * link's loss (matching production).
 */
class SctpLossReproductionTest {
    private val epoch = Instant.fromEpochSeconds(0)

    // Match the harness's fast SCTP RTO (Main.kt) so the reproduction mirrors the impaired lane. A deadlock
    // is a no-timer stall independent of the RTO values; the budget only bounds the actively-retransmitting
    // case. maxInitRetransmits (default 8) with this backoff (0.5,1,2,4,8,16,32,60…) can run past 90 s, so
    // the budget is generous — what we assert is that a lossy handshake NEVER no-timer-deadlocks, and always
    // completes at realistic (5–10 %) loss.
    private val config = SctpConfig(rtoInitial = 500.milliseconds, rtoMin = 100.milliseconds)
    private val budget = 120.seconds

    private class Outcome(
        val elapsed: Duration?,
        val client: SctpAssociationState,
        val server: SctpAssociationState,
        // true only when the run ended with neither side armed a timer while NOT both-Established — a
        // genuine no-progress deadlock (the bug class), as opposed to a still-actively-retransmitting run
        // that merely exhausted the budget (acceptable at extreme loss).
        val deadlock: Boolean = false,
        // true when an association ABORTed the handshake (exhausted retransmits → typed Failed, not a hang).
        val aborted: Boolean = false,
    )

    /**
     * Drive one full four-way handshake with independent per-datagram loss probability [loss], seeded by
     * [seed]. The active [client] opens (INIT); the passive [server] only ever reacts to datagrams (it arms
     * no timer of its own — SCTP's responder is driven entirely by the initiator's retransmits). Delivery is
     * immediate (sub-ms base RTT is negligible against the 100 ms+ retransmit timers). Returns the virtual
     * time to reach BOTH-`Established`, or `null` if it deadlocked / aborted / exceeded the budget.
     */
    private fun driveWithLoss(
        loss: Double,
        seed: Long,
    ): Outcome {
        val net = Random(seed)
        val client = SctpAssociation(config, Random(seed xor 0x1111))
        val server = SctpAssociation(config, Random(seed xor 0x2222))
        var now = epoch
        val toServer = ArrayDeque<ReadBuffer>()
        val toClient = ArrayDeque<ReadBuffer>()
        var aborted = false

        fun ship(
            dest: ArrayDeque<ReadBuffer>,
            outputs: List<SctpOutput>,
        ) {
            for (o in outputs) {
                when (o) {
                    is SctpOutput.Transmit -> {
                        o.packet.position(0)
                        if (net.nextDouble() >= loss) dest.addLast(o.packet.slice()) // else: this datagram is lost
                    }
                    is SctpOutput.Aborted -> aborted = true
                    else -> Unit
                }
            }
        }

        ship(toServer, client.handle(SctpEvent.Associate, now)) // client sends INIT; server waits passively

        while (true) {
            var delivered = false
            while (toServer.isNotEmpty()) {
                ship(toClient, server.handle(SctpEvent.DatagramReceived(toServer.removeFirst()), now))
                delivered = true
            }
            while (toClient.isNotEmpty()) {
                ship(toServer, client.handle(SctpEvent.DatagramReceived(toClient.removeFirst()), now))
                delivered = true
            }
            if (client.state == SctpAssociationState.Established && server.state == SctpAssociationState.Established) {
                return Outcome(now - epoch, client.state, server.state)
            }
            if (aborted) return Outcome(null, client.state, server.state, aborted = true)
            if (delivered) continue // keep exchanging within this instant before advancing the clock

            val dc = client.nextDeadline(now)
            val ds = server.nextDeadline(now)
            // Neither side armed a timer and we are not both-Established → a true no-timer deadlock (the bug).
            val next =
                listOfNotNull(dc, ds).minOrNull()
                    ?: return Outcome(null, client.state, server.state, deadlock = true)
            now = next
            if (now - epoch > budget) return Outcome(null, client.state, server.state) // still retransmitting: mere loss
            if (dc != null && dc <= now) ship(toServer, client.handle(SctpEvent.TimerFired, now))
            if (ds != null && ds <= now) ship(toClient, server.handle(SctpEvent.TimerFired, now))
        }
    }

    private fun SctpAssociationState.tag(): String = this::class.simpleName ?: "?"

    /**
     * THE GATE (directive #5): a full SCTP four-way handshake must complete under per-datagram loss for
     * every seed at realistic rates, and must NEVER no-timer-deadlock at any rate. This is the SCTP sibling
     * of the DTLS lost-final-flight gate; it guards the impaired-lane failure the trace localized to the
     * answerer's SCTP handshake never reaching `Established`.
     */
    @Test
    fun a_lossy_sctp_handshake_always_completes_within_the_budget() {
        for (loss in listOf(0.05, 0.10, 0.20)) {
            val n = 400
            var timeouts = 0
            var deadlocks = 0
            var aborts = 0
            var maxOk = Duration.ZERO
            var stuckExample = ""
            for (s in 0 until n) {
                val o = driveWithLoss(loss = loss, seed = s.toLong())
                val e = o.elapsed
                if (e == null) {
                    timeouts++
                    if (o.deadlock) {
                        deadlocks++
                        stuckExample = "seed=$s client=${o.client.tag()} server=${o.server.tag()}"
                    } else if (o.aborted) {
                        aborts++
                        if (stuckExample.isEmpty()) stuckExample = "seed=$s ABORT client=${o.client.tag()} server=${o.server.tag()}"
                    }
                } else if (e > maxOk) {
                    maxOk = e
                }
            }
            println("[repro] SCTP loss=$loss n=$n: timeouts=$timeouts (deadlocks=$deadlocks aborts=$aborts) maxOk=$maxOk")
            // The bug class is the DEADLOCK — a no-timer stall. Zero at EVERY rate.
            assertEquals(0, deadlocks, "SCTP handshake no-timer DEADLOCK at $loss loss ($deadlocks/$n; e.g. $stuckExample)")
            // Within the harness's realistic range (5 %, plus a 2× margin at 10 %), the handshake must
            // always complete — no aborts, no budget timeouts. Beyond that (20 %) graceful loss is fine.
            if (loss <= 0.10) {
                assertEquals(0, aborts, "SCTP handshake ABORTED (exhausted retransmits) at $loss loss ($aborts/$n; e.g. $stuckExample)")
                assertEquals(0, timeouts, "SCTP handshake exceeded the budget at $loss loss ($timeouts/$n)")
            }
        }
    }
}
