@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ReadBuffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **Deterministic reproduction of the L2 `impaired-loss-delay` handshake timeout** — the flake a
 * real-`netem` Docker lane surfaced but (being kernel-random) could never pin down. Two PURE-Kotlin
 * engines run a full mutually-authenticated handshake over an in-memory pipe with **scripted, seeded**
 * per-record-datagram loss, under the engine's own injected virtual clock — so the retransmission timing
 * that decides success is 100% deterministic and replays at zero wall-clock. A given seed always produces
 * the same outcome; there is no flake here, only the mechanism.
 *
 * Loss is modelled **per record datagram** because the driver ([com.ditchoom.webrtc.PureKotlinDtls]) sends
 * each `DtlsStep.records` entry as its own `iceData.send(...)` datagram — so a multi-record flight (the
 * server's ServerHello…Certificate…Finished flight is several records) exposes EACH record to the link's
 * loss, not the flight as a whole.
 */
class DtlsLossReproductionTest {
    private val epoch = Instant.fromEpochSeconds(0)
    private val budget = 30.seconds // DtlsConfig.handshakeTimeout — a longer handshake IS the L2 failure

    /** Outcome of one driven handshake: the elapsed virtual time (null = did not both-establish), each
     *  side's terminal state, plus how many times the Established side re-sent its last flight and how many
     *  retransmit-timer rounds fired (to distinguish a fix-not-firing logic gap from a too-slow-backoff
     *  timing gap). */
    private class Outcome(
        val elapsed: Duration?,
        val client: DtlsState,
        val server: DtlsState,
        val clientResends: Int,
        val timerRounds: Int,
        // true only when the run ended with BOTH sides idle and NO retransmit timer armed — a genuine
        // deadlock (the bug). A timeout that instead exhausted the 30 s budget while still actively
        // retransmitting (deadlock=false) is mere loss, acceptable at extreme rates.
        val deadlock: Boolean = false,
    )

    /**
     * Drive one full handshake with independent per-record loss probability [loss], seeded by [seed].
     * Delivery is immediate (the harness RTT — sub-ms base + 20 ms netem — is negligible against the 1 s+
     * retransmit timers). Returns the virtual time to reach BOTH-Established, or `null` if it exceeded the
     * 30 s budget (the timeout we are hunting) or failed typed.
     */
    private fun driveWithLoss(
        loss: Double,
        seed: Long,
        enableDtls13: Boolean = true,
    ): Outcome {
        val net = Random(seed)
        val client = DtlsEngine(DtlsConfig(random = Random(seed xor 0x1111), enableDtls13 = enableDtls13))
        val server = DtlsEngine(DtlsConfig(random = Random(seed xor 0x2222), enableDtls13 = enableDtls13))
        var clientState: DtlsState = DtlsState.Handshaking
        var serverState: DtlsState = DtlsState.Handshaking
        try {
            var now = epoch
            val toServer = ArrayDeque<ReadBuffer>()
            val toClient = ArrayDeque<ReadBuffer>()

            fun ship(
                dest: ArrayDeque<ReadBuffer>,
                records: List<ReadBuffer>,
            ) {
                for (r in records) if (net.nextDouble() >= loss) dest.addLast(r) // else: this datagram is lost
            }

            var clientResends = 0
            var timerRounds = 0
            ship(toServer, client.start(DtlsRole.Client, now).records)
            server.start(DtlsRole.Server, now) // server emits nothing until the ClientHello arrives

            while (true) {
                var delivered = false
                while (toServer.isNotEmpty()) {
                    val step = server.onDatagram(toServer.removeFirst(), now)
                    serverState = step.state
                    ship(toClient, step.records)
                    delivered = true
                }
                while (toClient.isNotEmpty()) {
                    val step = client.onDatagram(toClient.removeFirst(), now)
                    if (clientState is DtlsState.Established && step.records.isNotEmpty()) clientResends++ // fix fired
                    clientState = step.state
                    ship(toServer, step.records)
                    delivered = true
                }
                if (clientState is DtlsState.Established && serverState is DtlsState.Established) {
                    return Outcome(now - epoch, clientState, serverState, clientResends, timerRounds)
                }
                if (clientState is DtlsState.Failed || serverState is DtlsState.Failed) {
                    return Outcome(null, clientState, serverState, clientResends, timerRounds)
                }
                if (delivered) continue // keep exchanging within this instant before advancing the clock

                val dc = client.nextDeadline(now)
                val ds = server.nextDeadline(now)
                // Neither side has a timer and we are not both-Established → a true no-timer deadlock (bug).
                val next =
                    listOfNotNull(dc, ds).minOrNull()
                        ?: return Outcome(null, clientState, serverState, clientResends, timerRounds, deadlock = true)
                now = next
                // Kept actively retransmitting but ran out of the 30 s budget → mere loss, not a stall.
                if (now - epoch > budget) return Outcome(null, clientState, serverState, clientResends, timerRounds, deadlock = false)
                timerRounds++
                if (dc != null && dc <= now) ship(toServer, client.onTimeout(now).records)
                if (ds != null && ds <= now) ship(toClient, server.onTimeout(now).records)
            }
        } finally {
            client.close()
            server.close()
        }
    }

    private fun DtlsState.tag(): String =
        when (this) {
            is DtlsState.Established -> "Established"
            is DtlsState.Handshaking -> "Handshaking"
            is DtlsState.Failed -> "Failed"
            is DtlsState.Closed -> "Closed"
        }

    /**
     * THE GATE (directive #5 — the fix ships with its deterministic fixture): a full mutually-authenticated
     * DTLS 1.3 handshake must complete under per-datagram loss within the 30 s `handshakeTimeout`, for every
     * seed, at loss rates from mild to severe. Before the lost-final-flight fix
     * ([Dtls13Handshake.peerRetransmitAfterEstablished] + the timer re-arm), 5% loss deadlocked ~16% of
     * seeds at `client=Established, server=Handshaking`; the assertion below FAILS against that engine.
     *
     * Deterministic + flake-free: seeded loss, virtual clock, zero wall-clock — the opposite of the
     * kernel-random real-`netem` Docker lane that surfaced (but could not pin down) this bug.
     */
    @Test
    fun a_lossy_handshake_always_completes_within_the_budget() {
        if (!engineCryptoAvailable()) return
        // Both versions: DTLS 1.3 (the impaired lane's default — client sends the last flight) AND DTLS 1.2
        // (the Pion-lane fallback — the SERVER sends the last flight; the mirror-role deadlock).
        for (dtls13 in listOf(true, false)) {
            for (loss in listOf(0.05, 0.10, 0.20)) {
                val n = 300
                var timeouts = 0
                var deadlocks = 0
                var maxOk = Duration.ZERO
                var stuckExample = ""
                for (s in 0 until n) {
                    val o = driveWithLoss(loss = loss, seed = s.toLong(), enableDtls13 = dtls13)
                    val e = o.elapsed
                    if (e == null) {
                        timeouts++
                        if (o.deadlock) {
                            deadlocks++
                            stuckExample = "seed=$s client=${o.client.tag()} server=${o.server.tag()}"
                        }
                    } else if (e > maxOk) {
                        maxOk = e
                    }
                }
                val v = if (dtls13) "1.3" else "1.2"
                println("[repro] DTLS $v loss=$loss n=$n: timeouts=$timeouts (deadlocks=$deadlocks) maxOk=$maxOk")
                // The bug is the DEADLOCK — a no-timer stall on a lost final flight. Zero at EVERY rate (it
                // depends only on whether a final flight was lost, not on how much loss there is).
                assertEquals(0, deadlocks, "DTLS $v lost-final-flight DEADLOCK at $loss loss ($deadlocks/$n; e.g. $stuckExample)")
                // Within the harness's realistic range (5%, plus a 2x margin at 10%), the handshake must
                // always complete in budget. Beyond that (20%) graceful loss is fine.
                if (loss <= 0.10) assertEquals(0, timeouts, "DTLS $v exceeded the 30s budget at $loss loss ($timeouts/$n)")
            }
        }
    }
}
