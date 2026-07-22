@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.SignatureScheme
import com.ditchoom.buffer.crypto.SignatureSupport
import com.ditchoom.buffer.crypto.signatures
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsEngine
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.DtlsState
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
 * **Deterministic reproduction of the L2 `impaired-loss-delay` stall across the DTLS↔SCTP boundary** — the
 * failure the harness's per-side `PeerConnectionState` trace (PR #26) localized but that neither the pure
 * [com.ditchoom.webrtc.dtls] `DtlsLossReproductionTest` (DTLS handshake alone is loss-robust) nor the pure
 * [com.ditchoom.webrtc.sctp] `SctpLossReproductionTest` (the SCTP four-way handshake alone is loss-robust)
 * reproduces. The trace showed the offerer reaching `Connected` (its SCTP `Established`) while the answerer
 * sat in `Connecting` — i.e. the SCTP handshake completes on one side but never the other — under 5 % loss.
 * `Connected` requires SCTP `Established` (PeerConnection.runEstablishment), so the stall is in the
 * **interaction**: SCTP handshake packets ride the DTLS transport as application data, and the two layers'
 * retransmission timers interleave in a way only the combined stack exposes.
 *
 * This drives the exact production composition of `runEstablishment` **minus ICE**: each peer is a real
 * [DtlsEngine] (the pure-Kotlin handshake) with a real [SctpAssociation] on top — the SCTP association's
 * [SctpOutput.Transmit] packets are sealed as DTLS application data ([DtlsEngine.send]) and its inbound
 * datagrams are the DTLS-decrypted [com.ditchoom.webrtc.dtls.DtlsStep.applicationData] — over an in-memory
 * pipe with **scripted, seeded** per-datagram loss under the engines' injected virtual clock. 100 %
 * deterministic; a given seed always produces the same outcome. Loss is per emitted record datagram
 * (matching the driver, which `send`s each record separately), so a multi-record flight is exposed record
 * by record.
 */
class DtlsSctpLossReproductionTest {
    private val epoch = Instant.fromEpochSeconds(0)

    // Match the harness (Main.kt): DTLS 1.3 default + fast SCTP RTO. A deadlock is a no-timer stall
    // independent of these; the budget only bounds the still-retransmitting case.
    private val sctpConfig = SctpConfig(rtoInitial = 500.milliseconds, rtoMin = 100.milliseconds)
    private val budget = 90.seconds // the harness's real watchdog

    // A peer = one DTLS engine + one SCTP association. The DTLS client is the SCTP active opener (it calls
    // Associate once its DTLS reaches Established); the DTLS server's SCTP is the passive responder.
    private class Peer(
        seed: Long,
        val isClient: Boolean,
        enableDtls13: Boolean,
        sctpConfig: SctpConfig,
    ) {
        val dtls = DtlsEngine(DtlsConfig(random = Random(seed xor 0x0D71), enableDtls13 = enableDtls13))
        val sctp = SctpAssociation(sctpConfig, Random(seed xor 0x5C79))
        var dtlsState: DtlsState = DtlsState.Handshaking
        var sctpStarted = false
        var sctpAborted = false

        val dtlsRole: DtlsRole get() = if (isClient) DtlsRole.Client else DtlsRole.Server
        val dtlsEstablished: Boolean get() = dtlsState is DtlsState.Established
        val sctpEstablished: Boolean get() = sctp.state == SctpAssociationState.Established
    }

    private class Outcome(
        val elapsed: Duration?,
        val a: Peer,
        val b: Peer,
        val deadlock: Boolean = false,
        val aborted: Boolean = false,
        // true when the run emitted an unbounded flood of datagrams within a bounded virtual time — a
        // record storm (two Established peers echoing handshake-epoch retransmits at each other forever).
        val storm: Boolean = false,
    ) {
        fun diag(seed: Long): String =
            "seed=$seed A[dtls=${a.dtlsState.tag()} sctp=${a.sctp.state.tag()}] B[dtls=${b.dtlsState.tag()} sctp=${b.sctp.state.tag()}]"
    }

    /** Thrown internally when the datagram budget is blown — a runaway record storm rather than progress. */
    private class StormException : Exception()

    /**
     * Drive one full establishment (DTLS handshake → SCTP four-way handshake, tunneled) with independent
     * per-datagram loss probability [loss], seeded by [seed]. Peer A is the DTLS/SCTP client (sends first);
     * peer B the server. Returns the virtual time to reach BOTH SCTP-`Established`, or `null` if it
     * deadlocked / aborted / exceeded the budget.
     */
    private fun driveWithLoss(
        loss: Double,
        seed: Long,
        enableDtls13: Boolean,
    ): Outcome {
        val net = Random(seed)
        val a = Peer(seed xor 0x1111, isClient = true, enableDtls13, sctpConfig)
        val b = Peer(seed xor 0x2222, isClient = false, enableDtls13, sctpConfig)
        var now = epoch
        val toB = ArrayDeque<ReadBuffer>() // datagrams A→B
        val toA = ArrayDeque<ReadBuffer>() // datagrams B→A

        // A correct establishment settles in well under a few hundred record datagrams even at 20 % loss;
        // blowing past this many means an unbounded record storm, not slow progress — surface it as a storm.
        var shipped = 0

        fun ship(
            dest: ArrayDeque<ReadBuffer>,
            records: List<ReadBuffer>,
        ) {
            for (r in records) {
                shipped++
                if (shipped > STORM_CAP) throw StormException()
                if (net.nextDouble() >= loss) dest.addLast(r) // else: this record datagram is lost
            }
        }

        // Encrypt each SCTP Transmit as DTLS application data and put the resulting record(s) on the wire.
        fun emitSctp(
            peer: Peer,
            outputs: List<SctpOutput>,
            wire: ArrayDeque<ReadBuffer>,
        ) {
            for (o in outputs) {
                when (o) {
                    is SctpOutput.Transmit -> {
                        o.packet.position(0)
                        ship(wire, peer.dtls.send(o.packet.slice(), now).records)
                    }
                    is SctpOutput.Aborted -> peer.sctpAborted = true
                    else -> Unit // StateChanged read via sctp.state; MessageReceived irrelevant pre-data
                }
            }
        }

        // Once a peer's DTLS is Established, the active (client) side opens its SCTP association (INIT).
        fun maybeStartSctp(
            peer: Peer,
            wire: ArrayDeque<ReadBuffer>,
        ) {
            if (peer.dtlsEstablished && peer.isClient && !peer.sctpStarted) {
                peer.sctpStarted = true
                emitSctp(peer, peer.sctp.handle(SctpEvent.Associate, now), wire)
            }
        }

        // Feed one inbound wire datagram into a peer's DTLS: emit any resulting handshake records, and route
        // any decrypted application data (SCTP packets) into its association, encrypting the replies back out.
        fun deliver(
            peer: Peer,
            datagram: ReadBuffer,
            outWire: ArrayDeque<ReadBuffer>,
        ) {
            val step = peer.dtls.onDatagram(datagram, now)
            peer.dtlsState = step.state
            ship(outWire, step.records)
            for (app in step.applicationData) {
                emitSctp(peer, peer.sctp.handle(SctpEvent.DatagramReceived(app), now), outWire)
            }
            maybeStartSctp(peer, outWire)
        }

        ship(toB, a.dtls.start(a.dtlsRole, now).records) // client sends ClientHello
        b.dtls.start(b.dtlsRole, now) // server emits nothing until the ClientHello arrives

        try {
            while (true) {
                var delivered = false
                while (toB.isNotEmpty()) {
                    deliver(b, toB.removeFirst(), toA)
                    delivered = true
                }
                while (toA.isNotEmpty()) {
                    deliver(a, toA.removeFirst(), toB)
                    delivered = true
                }
                maybeStartSctp(a, toB)
                maybeStartSctp(b, toA)

                if (a.sctpEstablished && b.sctpEstablished) return Outcome(now - epoch, a, b)
                if (a.sctpAborted || b.sctpAborted) return Outcome(null, a, b, aborted = true)
                if (delivered) continue // exchange fully within this instant before advancing the clock

                val deadlines =
                    listOfNotNull(
                        a.dtls.nextDeadline(now),
                        a.sctp.nextDeadline(now),
                        b.dtls.nextDeadline(now),
                        b.sctp.nextDeadline(now),
                    )
                // No side has a timer and we are not both-Established → a true no-timer deadlock (the bug class).
                val next = deadlines.minOrNull() ?: return Outcome(null, a, b, deadlock = true)
                now = next
                if (now - epoch > budget) return Outcome(null, a, b) // still retransmitting: mere loss, not a stall

                a.dtls.nextDeadline(now)?.let { if (it <= now) ship(toB, a.dtls.onTimeout(now).records) }
                a.sctp.nextDeadline(now)?.let { if (it <= now) emitSctp(a, a.sctp.handle(SctpEvent.TimerFired, now), toB) }
                b.dtls.nextDeadline(now)?.let { if (it <= now) ship(toA, b.dtls.onTimeout(now).records) }
                b.sctp.nextDeadline(now)?.let { if (it <= now) emitSctp(b, b.sctp.handle(SctpEvent.TimerFired, now), toA) }
            }
        } catch (_: StormException) {
            return Outcome(null, a, b, storm = true)
        }
    }

    /**
     * THE GATE (directive #5): a full DTLS→SCTP establishment must complete under per-datagram loss for
     * every seed at realistic (5–10 %) rates, and must NEVER no-timer-deadlock at any rate. This guards the
     * impaired-lane failure the trace localized to the answerer's SCTP handshake never reaching
     * `Established` while the offerer did — a stall the DTLS-only and SCTP-only gates cannot see because it
     * lives in the interleaving of the two layers' retransmissions.
     */
    @Test
    fun a_lossy_dtls_then_sctp_establishment_always_completes() {
        if (!engineCryptoAvailable()) return // browsers delegate to RTCPeerConnection; the blocking engine isn't here
        for (dtls13 in listOf(true, false)) {
            for (loss in listOf(0.05, 0.10, 0.20)) {
                val n = 200
                var timeouts = 0
                var deadlocks = 0
                var aborts = 0
                var storms = 0
                var maxOk = Duration.ZERO
                var example = ""
                for (s in 0 until n) {
                    val o = driveWithLoss(loss = loss, seed = s.toLong(), enableDtls13 = dtls13)
                    when {
                        o.elapsed != null -> if (o.elapsed > maxOk) maxOk = o.elapsed
                        o.storm -> {
                            storms++
                            timeouts++
                            if (example.isEmpty()) example = "STORM ${o.diag(s.toLong())}"
                        }
                        o.deadlock -> {
                            deadlocks++
                            timeouts++
                            if (example.isEmpty()) example = "DEADLOCK ${o.diag(s.toLong())}"
                        }
                        o.aborted -> {
                            aborts++
                            timeouts++
                            if (example.isEmpty()) example = "ABORT ${o.diag(s.toLong())}"
                        }
                        else -> {
                            timeouts++
                            if (example.isEmpty()) example = "BUDGET ${o.diag(s.toLong())}"
                        }
                    }
                }
                val v = if (dtls13) "1.3" else "1.2"
                println(
                    "[repro] DTLS $v→SCTP loss=$loss n=$n: timeouts=$timeouts (deadlocks=$deadlocks storms=$storms aborts=$aborts) maxOk=$maxOk",
                )
                assertEquals(0, deadlocks, "DTLS $v→SCTP no-timer DEADLOCK at $loss loss ($deadlocks/$n; e.g. $example)")
                assertEquals(0, storms, "DTLS $v→SCTP handshake record STORM at $loss loss ($storms/$n; e.g. $example)")
                if (loss <= 0.10) {
                    assertEquals(0, timeouts, "DTLS $v→SCTP establishment stalled at $loss loss ($timeouts/$n; e.g. $example)")
                }
            }
        }
    }
}

private const val STORM_CAP = 100_000

private fun DtlsState.tag(): String = this::class.simpleName ?: "?"

private fun SctpAssociationState.tag(): String = this::class.simpleName ?: "?"

private fun engineCryptoAvailable(): Boolean = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256) is SignatureSupport.Blocking
