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
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The storm-class invariant (WS-1), stated generically.** The post-Established handshake-record storm
 * (#28) was one instance of a broader failure mode: an **established, idle** sans-io core that keeps
 * emitting output forever when fed no new input. A single reproduction pins one instance; this pins the
 * *class* — for DTLS, for SCTP, and for the combined stack, an Established core driven only by its own
 * expiring timers (never any inbound datagram) must emit a **bounded** number of records and then
 * **quiesce** (`nextDeadline` → null). A storm fails this instantly: it blows the record cap within a
 * handful of steps; a healthy core retransmits its final flight a bounded number of times, or not at all,
 * and then arms no further timer.
 *
 * This is deliberately not a loss test — loss produces legitimate retransmission. It is the dual: with a
 * *perfect* link and *nothing to send*, a settled stack must fall silent. That is the property the storm
 * violated, so it is the property this guards, at every layer where the storm could live.
 */
class BoundedOutputWhenIdleTest {
    private val epoch = Instant.fromEpochSeconds(0)
    private val sctpConfig = SctpConfig(rtoInitial = 500.milliseconds, rtoMin = 100.milliseconds)

    /** A storm emits per step, so a healthy quiesced core stays far under this; a storm blows it at once. */
    private val recordCap = 200

    /** Long enough that any legitimate final-flight retransmission budget expires within it. */
    private val horizon = 600.seconds

    /** DTLS: two Established engines, each driven only by its own timers with no inbound, must fall silent. */
    @Test
    fun established_dtls_engine_emits_bounded_output_when_idle() {
        if (!engineCryptoAvailable()) return
        val (a, b, now) = establishDtls(seed = 1)
        assertQuiescesBounded("DTLS client") { probeDtlsIdle(a, now) }
        assertQuiescesBounded("DTLS server") { probeDtlsIdle(b, now) }
    }

    /** SCTP: two Established associations, idle, driven only by TimerFired, must emit bounded output. */
    @Test
    fun established_sctp_association_emits_bounded_output_when_idle() {
        val (a, b, now) = establishSctp(seed = 2)
        assertQuiescesBounded("SCTP client") { probeSctpIdle(a, now) }
        assertQuiescesBounded("SCTP server") { probeSctpIdle(b, now) }
    }

    /** Full stack: an Established DTLS+SCTP peer, idle, driving both cores' timers, must emit bounded output. */
    @Test
    fun established_full_stack_emits_bounded_output_when_idle() {
        if (!engineCryptoAvailable()) return
        val (a, b, now) = establishFullStack(seed = 3)
        assertQuiescesBounded("full-stack client") { probeStackIdle(a, now) }
        assertQuiescesBounded("full-stack server") { probeStackIdle(b, now) }
    }

    // --- idle probes: advance only this core's own timers, delivering nothing, counting self-emitted output ---

    private data class Probe(
        val emitted: Int,
        val quiesced: Boolean,
    )

    private fun probeDtlsIdle(
        engine: DtlsEngine,
        start: Instant,
    ): Probe {
        var now = start
        var emitted = 0
        while (now - epoch <= horizon) {
            val deadline = engine.nextDeadline(now) ?: return Probe(emitted, quiesced = true)
            now = maxOf(deadline, now)
            emitted += engine.onTimeout(now).records.size
            if (emitted > recordCap) return Probe(emitted, quiesced = false)
        }
        return Probe(emitted, quiesced = engine.nextDeadline(now) == null)
    }

    private fun probeSctpIdle(
        assoc: SctpAssociation,
        start: Instant,
    ): Probe {
        var now = start
        var emitted = 0
        while (now - epoch <= horizon) {
            val deadline = assoc.nextDeadline(now) ?: return Probe(emitted, quiesced = true)
            now = maxOf(deadline, now)
            emitted += assoc.handle(SctpEvent.TimerFired, now).count { it is SctpOutput.Transmit }
            if (emitted > recordCap) return Probe(emitted, quiesced = false)
        }
        return Probe(emitted, quiesced = assoc.nextDeadline(now) == null)
    }

    private fun probeStackIdle(
        peer: StackPeer,
        start: Instant,
    ): Probe {
        var now = start
        var emitted = 0
        while (now - epoch <= horizon) {
            val d =
                listOfNotNull(peer.dtls.nextDeadline(now), peer.sctp.nextDeadline(now)).minOrNull()
                    ?: return Probe(emitted, quiesced = true)
            now = maxOf(d, now)
            if (peer.dtls.nextDeadline(now)?.let { it <= now } == true) {
                emitted +=
                    peer.dtls
                        .onTimeout(now)
                        .records.size
            }
            if (peer.sctp.nextDeadline(now)?.let { it <= now } == true) {
                // Each SCTP retransmit rides one DTLS record, so count the sealed records it would put on the wire.
                for (o in peer.sctp.handle(SctpEvent.TimerFired, now)) {
                    if (o is SctpOutput.Transmit) {
                        o.packet.position(0)
                        emitted +=
                            peer.dtls
                                .send(o.packet.slice(), now)
                                .records.size
                    }
                }
            }
            if (emitted > recordCap) return Probe(emitted, quiesced = false)
        }
        val stillArmed = listOfNotNull(peer.dtls.nextDeadline(now), peer.sctp.nextDeadline(now)).isNotEmpty()
        return Probe(emitted, quiesced = !stillArmed)
    }

    private fun assertQuiescesBounded(
        who: String,
        probe: () -> Probe,
    ) {
        val p = probe()
        assertTrue(p.emitted <= recordCap, "$who emitted an unbounded record storm when idle (${p.emitted} > $recordCap)")
        assertTrue(p.quiesced, "$who never quiesced when idle (still emitting/armed after $horizon, emitted=${p.emitted})")
    }

    // --- establishment: lossless, direct sans-io drive, stop the instant both sides are Established ---

    private fun establishDtls(seed: Long): Triple<DtlsEngine, DtlsEngine, Instant> {
        val a = DtlsEngine(DtlsConfig(random = Random(seed xor 0x0D71)))
        val b = DtlsEngine(DtlsConfig(random = Random(seed xor 0x5C79)))
        var now = epoch
        val toB = ArrayDeque<ReadBuffer>()
        val toA = ArrayDeque<ReadBuffer>()
        var aState: DtlsState = DtlsState.Handshaking
        var bState: DtlsState = DtlsState.Handshaking

        toB += a.start(DtlsRole.Client, now).records
        b.start(DtlsRole.Server, now)
        var guard = 0
        while (aState !is DtlsState.Established || bState !is DtlsState.Established) {
            check(guard++ < STEP_GUARD) { "DTLS establishment did not settle" }
            var delivered = false
            while (toB.isNotEmpty()) {
                val step = b.onDatagram(toB.removeFirst(), now)
                bState = step.state
                toA += step.records
                delivered = true
            }
            while (toA.isNotEmpty()) {
                val step = a.onDatagram(toA.removeFirst(), now)
                aState = step.state
                toB += step.records
                delivered = true
            }
            if (delivered) continue
            val next = listOfNotNull(a.nextDeadline(now), b.nextDeadline(now)).minOrNull() ?: break
            now = next
            a.nextDeadline(now)?.let { if (it <= now) toB += a.onTimeout(now).records }
            b.nextDeadline(now)?.let { if (it <= now) toA += b.onTimeout(now).records }
        }
        return Triple(a, b, now)
    }

    private fun establishSctp(seed: Long): Triple<SctpAssociation, SctpAssociation, Instant> {
        val client = SctpAssociation(sctpConfig, Random(seed xor 0x1111))
        val server = SctpAssociation(sctpConfig, Random(seed xor 0x2222))
        var now = epoch
        val toServer = ArrayDeque<ReadBuffer>()
        val toClient = ArrayDeque<ReadBuffer>()

        fun ship(
            dest: ArrayDeque<ReadBuffer>,
            outputs: List<SctpOutput>,
        ) {
            for (o in outputs) {
                if (o is SctpOutput.Transmit) {
                    o.packet.position(0)
                    dest.addLast(o.packet.slice())
                }
            }
        }
        ship(toServer, client.handle(SctpEvent.Associate, now))
        var guard = 0
        while (client.state != SctpAssociationState.Established || server.state != SctpAssociationState.Established) {
            check(guard++ < STEP_GUARD) { "SCTP establishment did not settle" }
            var delivered = false
            while (toServer.isNotEmpty()) {
                ship(toClient, server.handle(SctpEvent.DatagramReceived(toServer.removeFirst()), now))
                delivered = true
            }
            while (toClient.isNotEmpty()) {
                ship(toServer, client.handle(SctpEvent.DatagramReceived(toClient.removeFirst()), now))
                delivered = true
            }
            if (delivered) continue
            val next = listOfNotNull(client.nextDeadline(now), server.nextDeadline(now)).minOrNull() ?: break
            now = next
            client.nextDeadline(now)?.let { if (it <= now) ship(toServer, client.handle(SctpEvent.TimerFired, now)) }
            server.nextDeadline(now)?.let { if (it <= now) ship(toClient, server.handle(SctpEvent.TimerFired, now)) }
        }
        return Triple(client, server, now)
    }

    private class StackPeer(
        val dtls: DtlsEngine,
        val sctp: SctpAssociation,
        val isClient: Boolean,
    ) {
        var dtlsState: DtlsState = DtlsState.Handshaking
        var sctpStarted = false
    }

    // A lossless mirror of DtlsSctpLossReproductionTest.driveWithLoss: DTLS handshake, then the client opens
    // the SCTP association (tunneled as DTLS app data), driven to both-Established — the exact composition.
    private fun establishFullStack(seed: Long): Triple<StackPeer, StackPeer, Instant> {
        val a =
            StackPeer(
                DtlsEngine(DtlsConfig(random = Random(seed xor 0x0D71))),
                SctpAssociation(sctpConfig, Random(seed xor 0x5C79)),
                isClient = true,
            )
        val b =
            StackPeer(
                DtlsEngine(DtlsConfig(random = Random(seed xor 0x2A2A))),
                SctpAssociation(sctpConfig, Random(seed xor 0x7B7B)),
                isClient = false,
            )
        var now = epoch
        val toB = ArrayDeque<ReadBuffer>()
        val toA = ArrayDeque<ReadBuffer>()

        fun emitSctp(
            peer: StackPeer,
            outputs: List<SctpOutput>,
            wire: ArrayDeque<ReadBuffer>,
        ) {
            for (o in outputs) {
                if (o is SctpOutput.Transmit) {
                    o.packet.position(0)
                    wire += peer.dtls.send(o.packet.slice(), now).records
                }
            }
        }

        fun maybeStartSctp(
            peer: StackPeer,
            wire: ArrayDeque<ReadBuffer>,
        ) {
            if (peer.dtlsState is DtlsState.Established && peer.isClient && !peer.sctpStarted) {
                peer.sctpStarted = true
                emitSctp(peer, peer.sctp.handle(SctpEvent.Associate, now), wire)
            }
        }

        fun deliver(
            peer: StackPeer,
            datagram: ReadBuffer,
            outWire: ArrayDeque<ReadBuffer>,
        ) {
            val step = peer.dtls.onDatagram(datagram, now)
            peer.dtlsState = step.state
            outWire += step.records
            for (app in step.applicationData) emitSctp(peer, peer.sctp.handle(SctpEvent.DatagramReceived(app), now), outWire)
            maybeStartSctp(peer, outWire)
        }

        toB += a.dtls.start(DtlsRole.Client, now).records
        b.dtls.start(DtlsRole.Server, now)
        var guard = 0
        while (a.sctp.state != SctpAssociationState.Established || b.sctp.state != SctpAssociationState.Established) {
            check(guard++ < STEP_GUARD) { "full-stack establishment did not settle" }
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
            if (delivered) continue
            val next =
                listOfNotNull(
                    a.dtls.nextDeadline(now),
                    a.sctp.nextDeadline(now),
                    b.dtls.nextDeadline(now),
                    b.sctp.nextDeadline(now),
                ).minOrNull() ?: break
            now = next
            a.dtls.nextDeadline(now)?.let { if (it <= now) toB += a.dtls.onTimeout(now).records }
            a.sctp.nextDeadline(now)?.let { if (it <= now) emitSctp(a, a.sctp.handle(SctpEvent.TimerFired, now), toB) }
            b.dtls.nextDeadline(now)?.let { if (it <= now) toA += b.dtls.onTimeout(now).records }
            b.sctp.nextDeadline(now)?.let { if (it <= now) emitSctp(b, b.sctp.handle(SctpEvent.TimerFired, now), toA) }
        }
        return Triple(a, b, now)
    }

    private fun engineCryptoAvailable(): Boolean = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256) is SignatureSupport.Blocking

    private companion object {
        const val STEP_GUARD = 100_000
    }
}
