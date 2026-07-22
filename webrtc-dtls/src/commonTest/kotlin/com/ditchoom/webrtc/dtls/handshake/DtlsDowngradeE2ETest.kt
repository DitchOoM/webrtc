@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsEngine
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.DtlsState
import com.ditchoom.webrtc.dtls.DtlsVersion
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import com.ditchoom.webrtc.dtls.wire.CipherSuiteId
import com.ditchoom.webrtc.dtls.wire.ClientHello
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.ExtensionType
import com.ditchoom.webrtc.dtls.wire.HandshakeFragment
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.writeView
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **DTLS 1.3 → 1.2 downgrade detection, proven end-to-end through two real [DtlsEngine]s** (RFC 8446
 * §4.1.3 / RFC 9147). The sentinel unit test ([DtlsDowngradeSentinelTest]) proves each half in isolation
 * — the server *stamps* the sentinel, and a client *rejects* a hand-crafted ServerHello carrying it. This
 * test closes the loop: it drives a genuine 1.3-capable client against a genuine 1.3-capable server and
 * shows the client engine end in [DtlsState.Failed] with [DtlsFailureReason.DowngradeDetected] — but only
 * when an on-path attacker is present.
 *
 * **Why a plain two-engine test cannot surface `DowngradeDetected`.** The engine has, by design, *no*
 * client-side 1.3→1.2 fallback — that non-fallback IS the security property (a silent fallback is exactly
 * the attack the sentinel defends against). The server stamps the sentinel iff *it* is 1.3-capable
 * (`enableDtls13 = true`), independent of what the client offered. So a 1.3-client ↔ 1.2-only-server pair
 * negotiates a clean 1.2 ServerHello with **no** sentinel and the client fails a plain [HandshakeFailure],
 * never `DowngradeDetected`. To surface the real thing you must reproduce the RFC's *active attacker*.
 *
 * **The reproduced attack.** Both engines are 1.3-capable. An in-flight MITM ([stripDtls13FromFlight])
 * forges a 1.2-only ClientHello out of the client's real one before it reaches the server: it strips the
 * `supported_versions` (0xFEFC) and `key_share` extensions and substitutes the 1.2 WebRTC cipher suite
 * (0xC02B) for the client's 1.3-only offer (0x1301) — exactly the ClientHello a real 1.3-capable browser,
 * which lists both suites, would present once its 1.3 offer is stripped. The server, seeing a ClientHello
 * that no longer offers 1.3, selects its DTLS 1.2 FSM and — being itself 1.3-capable — stamps the
 * `DOWNGRD\x01` sentinel into its ServerHello.Random. That ServerHello reaches the **untampered** real 1.3
 * client, which offered 1.3, sees a lower selected version carrying the sentinel, and correctly rejects it
 * as [DowngradeDetected].
 *
 * All deterministic: seeded [Random], virtual [Instant] clock, no `Clock.System`/`Random.Default`, no
 * network, zero wall-clock. The drive loop is bounded by an iteration [guard] so a non-converging exchange
 * fails loudly instead of hanging (directive #4).
 */
class DtlsDowngradeE2ETest {
    private val epoch = Instant.fromEpochSeconds(0)

    /**
     * Which datagrams on the client→server path the MITM rewrites. [None] is the honest network (the
     * positive control); [StripDtls13] is the active attacker that removes the 1.3 offer from every
     * ClientHello it sees.
     */
    private enum class Attack { None, StripDtls13 }

    /** The terminal state of each engine after a driven handshake. */
    private class Outcome(
        val client: DtlsState,
        val server: DtlsState,
    )

    // ── the three proofs ─────────────────────────────────────────────────────────────────────────

    /**
     * THE PROOF (audit #5a): an active on-path attacker that strips the 1.3 offer from the ClientHello is
     * detected end-to-end. Two real 1.3-capable engines; the MITM downshifts the server to 1.2; the
     * untampered 1.3 client rejects the sentinel-bearing ServerHello as [DowngradeDetected] — never a
     * silent fallback. Every seed.
     */
    @Test
    fun a_stripped_1_3_offer_is_detected_as_a_downgrade_end_to_end() {
        if (!engineCryptoAvailable()) return
        for (seed in 0L until 32L) {
            val o = drive(attack = Attack.StripDtls13, clientDtls13 = true, serverDtls13 = true, seed = seed)
            val client = assertIs<DtlsState.Failed>(o.client, "seed=$seed: the 1.3 client must reject the downgrade, was ${o.client}")
            assertEquals(
                DtlsFailureReason.DowngradeDetected,
                client.reason,
                "seed=$seed: a 1.2 ServerHello carrying the RFC 8446 §4.1.3 sentinel is a detected downgrade, not a plain failure",
            )
        }
    }

    /**
     * POSITIVE CONTROL: with **no** attacker, the very same two 1.3-capable engines complete a full
     * mutually-authenticated handshake and both reach [DtlsState.Established] negotiating **DTLS 1.3** —
     * proving the harness itself never spuriously downgrades and the `DowngradeDetected` above is caused by
     * the MITM, not by the drive loop.
     */
    @Test
    fun without_the_attacker_both_engines_establish_dtls_1_3() {
        if (!engineCryptoAvailable()) return
        for (seed in 0L until 32L) {
            val o = drive(attack = Attack.None, clientDtls13 = true, serverDtls13 = true, seed = seed)
            val client =
                assertIs<DtlsState.Established>(o.client, "seed=$seed: an unattacked 1.3 handshake must establish, client was ${o.client}")
            val server =
                assertIs<DtlsState.Established>(o.server, "seed=$seed: an unattacked 1.3 handshake must establish, server was ${o.server}")
            assertEquals(DtlsVersion.Dtls13, client.negotiatedVersion, "seed=$seed: the client negotiated 1.3")
            assertEquals(DtlsVersion.Dtls13, server.negotiatedVersion, "seed=$seed: the server negotiated 1.3")
        }
    }

    /**
     * NEGATIVE CONTROL: the same MITM strip, but against a server that is **not** 1.3-capable
     * (`enableDtls13 = false`). That server selects 1.2 and leaves its Random fully random — no sentinel to
     * find — so the 1.3 client rejects the downgrade as a plain [HandshakeFailure], never `DowngradeDetected`.
     * This proves it is the *sentinel*, not merely *any* 1.2 ServerHello, that triggers `DowngradeDetected`.
     */
    @Test
    fun a_stripped_offer_against_a_1_2_only_server_is_a_plain_failure_not_a_downgrade() {
        if (!engineCryptoAvailable()) return
        for (seed in 0L until 32L) {
            val o = drive(attack = Attack.StripDtls13, clientDtls13 = true, serverDtls13 = false, seed = seed)
            val client = assertIs<DtlsState.Failed>(o.client, "seed=$seed: a downgraded handshake still fails, was ${o.client}")
            assertEquals(
                DtlsFailureReason.HandshakeFailure,
                client.reason,
                "seed=$seed: a sentinel-free 1.2 ServerHello is a plain failure — only the sentinel makes it a detected downgrade",
            )
        }
    }

    // ── the two-engine drive loop (an in-memory pipe with an optional on-path attacker) ──────────

    /**
     * Drive one full handshake between two real engines over an in-memory, lossless pipe. On the
     * client→server path an [attack] of [Attack.StripDtls13] rewrites every ClientHello to remove its 1.3
     * offer (the MITM). Delivery is immediate; the virtual clock advances to the nearest armed timer only
     * when both queues drain. Bounded by [guard] iterations (directive #4: a watchdog, never a wall-clock).
     */
    private fun drive(
        attack: Attack,
        clientDtls13: Boolean,
        serverDtls13: Boolean,
        seed: Long,
    ): Outcome {
        val factory = BufferFactory.managed()
        val client = DtlsEngine(DtlsConfig(bufferFactory = factory, enableDtls13 = clientDtls13, random = Random(seed xor 0x1111)))
        val server = DtlsEngine(DtlsConfig(bufferFactory = factory, enableDtls13 = serverDtls13, random = Random(seed xor 0x2222)))
        var clientState: DtlsState = DtlsState.Handshaking
        var serverState: DtlsState = DtlsState.Handshaking
        try {
            var now = epoch
            val toServer = ArrayDeque<ReadBuffer>()
            val toClient = ArrayDeque<ReadBuffer>()

            // The MITM: on the client→server path, strip the 1.3 offer from any ClientHello; else verbatim.
            fun toServer(records: List<ReadBuffer>) {
                for (r in records) toServer.addLast(if (attack == Attack.StripDtls13) stripDtls13FromFlight(r, factory) else r)
            }

            toServer(client.start(DtlsRole.Client, now).records)
            server.start(DtlsRole.Server, now) // the server emits nothing until the ClientHello arrives

            var guard = 0
            while (true) {
                check(guard++ < 500) { "downgrade drive loop did not converge (client=$clientState server=$serverState)" }
                var delivered = false
                while (toServer.isNotEmpty()) {
                    val step = server.onDatagram(toServer.removeFirst(), now)
                    serverState = step.state
                    for (r in step.records) toClient.addLast(r)
                    delivered = true
                }
                while (toClient.isNotEmpty()) {
                    val step = client.onDatagram(toClient.removeFirst(), now)
                    clientState = step.state
                    toServer(step.records)
                    delivered = true
                }
                if (clientState is DtlsState.Failed || serverState is DtlsState.Failed) return Outcome(clientState, serverState)
                if (clientState is DtlsState.Established && serverState is DtlsState.Established) return Outcome(clientState, serverState)
                if (delivered) continue // exchange everything within this instant before advancing the clock

                val next =
                    listOfNotNull(client.nextDeadline(now), server.nextDeadline(now)).minOrNull()
                        ?: return Outcome(clientState, serverState) // no timer armed and not both-established → done (or wedged)
                now = next
                check(
                    now - epoch <= 60.seconds,
                ) { "downgrade drive loop exceeded its virtual budget (client=$clientState server=$serverState)" }
                if (client.nextDeadline(now)?.let { it <= now } == true) toServer(client.onTimeout(now).records)
                if (server.nextDeadline(now)?.let { it <= now } == true) for (r in server.onTimeout(now).records) toClient.addLast(r)
            }
        } finally {
            client.close()
            server.close()
        }
    }

    // ── the on-path attacker's tamper (RFC 8446 §4.1.3): strip supported_versions + key_share ─────

    /**
     * Rewrite a client→server datagram to remove the DTLS 1.3 offer: for every complete ClientHello it
     * carries, drop the `supported_versions` (0xFEFC) and `key_share` extensions and re-encode. Records
     * that are not a complete ClientHello (and datagrams with none) pass through byte-for-byte. This is the
     * minimal on-path mutation that makes a 1.3-capable server believe its peer is 1.2-only. Array-free —
     * buffers and slice views only (directive #1).
     */
    private fun stripDtls13FromFlight(
        datagram: ReadBuffer,
        factory: BufferFactory,
    ): ReadBuffer {
        val records = DtlsRecord.decodeAll(datagram) ?: return datagram
        val rebuilt = ArrayList<ReadBuffer>(records.size)
        var changed = false
        for (rec in records) {
            val stripped = strippedClientHelloRecord(rec, factory)
            if (stripped != null) {
                rebuilt += stripped
                changed = true
            } else {
                rebuilt += encodeVerbatim(rec, factory)
            }
        }
        if (!changed) return datagram
        val total = rebuilt.sumOf { it.remaining() }
        val out = factory.allocate(total, ByteOrder.BIG_ENDIAN)
        for (r in rebuilt) out.writeView(r)
        out.resetForRead()
        return out
    }

    /**
     * If [rec] is a Handshake record whose sole fragment is a *complete* ClientHello, return a new record
     * carrying that ClientHello with `supported_versions` + `key_share` removed (same message_seq and same
     * record header). Otherwise null (the caller re-emits the record verbatim).
     */
    private fun strippedClientHelloRecord(
        rec: DtlsRecord,
        factory: BufferFactory,
    ): ReadBuffer? {
        if (rec.contentType.value != ContentType.Handshake.value) return null
        val fragments = HandshakeFragment.decodeAll(rec.fragment) ?: return null
        if (fragments.size != 1) return null
        val f = fragments[0]
        if (f.msgType.value != HandshakeType.ClientHello.value) return null
        if (f.fragmentOffset != 0 || f.fragmentLength != f.length) return null // must be a whole message
        val ch = ClientHello.parse(f.fragmentBody) ?: return null

        val filtered =
            ch.extensions.filter {
                it.type.value != ExtensionType.SupportedVersions.value && it.type.value != ExtensionType.KeyShare.value
            }
        // Forge a 1.2-only ClientHello: our minimal engine client offers just the 1.3 suite (0x1301), so on
        // top of stripping the two 1.3 extensions the attacker also substitutes the 1.2 WebRTC suite (0xC02B)
        // — exactly the ClientHello a real 1.3-capable browser (which lists both suites) would present once
        // its 1.3 offer is stripped. Without it the 1.2 server rejects the hello (no shared cipher) and never
        // gets to stamp the sentinel — the attack requires the server to actually negotiate 1.2.
        val downgradedSuites = listOf(CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256)
        val newCh = ClientHello(ch.version, ch.random, ch.sessionId, ch.cookie, downgradedSuites, filtered)

        val body = factory.allocate(2048, ByteOrder.BIG_ENDIAN)
        newCh.bodyInto(body)
        body.resetForRead()

        val message = HandshakeMessage(HandshakeType.ClientHello, f.messageSeq, body)
        val fragment = factory.allocate(message.wireSize, ByteOrder.BIG_ENDIAN)
        message.encodeInto(fragment)
        fragment.resetForRead()

        val newRec = DtlsRecord(rec.contentType, rec.version, rec.epoch, rec.sequenceNumber, fragment)
        val out = factory.allocate(newRec.wireSize, ByteOrder.BIG_ENDIAN)
        newRec.encodeInto(out)
        out.resetForRead()
        return out
    }

    /** Re-encode a decoded record byte-for-byte (an untouched record on the tampered path). */
    private fun encodeVerbatim(
        rec: DtlsRecord,
        factory: BufferFactory,
    ): ReadBuffer {
        val out = factory.allocate(rec.wireSize, ByteOrder.BIG_ENDIAN)
        rec.encodeInto(out)
        out.resetForRead()
        return out
    }
}
