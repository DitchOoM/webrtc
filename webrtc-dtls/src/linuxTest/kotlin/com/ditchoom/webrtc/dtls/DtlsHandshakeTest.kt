package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The W4 exit fixture (TESTING §7 W4): two of our own DTLS stacks complete a handshake over an
 * in-memory datagram pipe, driven entirely by a virtual clock — no sockets, no wall-clock. Because the
 * engines are caller-clocked (injected `current_time_cb`), the whole handshake advances at zero
 * wall-clock and each side ends [DtlsState.Established] with the peer's real certificate fingerprint,
 * which must equal the other side's advertised `localFingerprint`.
 */
class DtlsHandshakeTest {
    @Test
    fun two_stacks_complete_a_dtls_handshake_under_virtual_time() {
        val client = DtlsEngine(DtlsRole.Client, DtlsConfig())
        val server = DtlsEngine(DtlsRole.Server, DtlsConfig())
        try {
            val (c, s) = drive(client, server)
            assertIs<DtlsState.Established>(c, "client established, was $c")
            assertIs<DtlsState.Established>(s, "server established, was $s")

            // Each side sees the OTHER's certificate — the a=fingerprint cross-check WebRTC relies on.
            assertEquals(server.localFingerprint, c.peerFingerprint)
            assertEquals(client.localFingerprint, s.peerFingerprint)
            assertEquals(64, client.localFingerprint.sha256Hex.length) // 32 bytes → 64 hex chars

            // The default config negotiates 1.3 (§11.3): both browser engines ship it now.
            assertEquals(DtlsVersion.Dtls13, c.negotiatedVersion)
            assertEquals(DtlsVersion.Dtls13, s.negotiatedVersion)
        } finally {
            client.close()
            server.close()
        }
    }

    /**
     * The 1.2 floor still works (§11.3): pinning `enableDtls13 = false` is the interop lane for peers
     * without 1.3 — notably Pion, whose released v3 is DTLS 1.2 only.
     */
    @Test
    fun two_stacks_fall_back_to_dtls_1_2_when_1_3_is_disabled() {
        val pinned = DtlsConfig(enableDtls13 = false)
        val client = DtlsEngine(DtlsRole.Client, pinned)
        val server = DtlsEngine(DtlsRole.Server, pinned)
        try {
            val (c, s) = drive(client, server)
            assertIs<DtlsState.Established>(c, "client established, was $c")
            assertIs<DtlsState.Established>(s, "server established, was $s")
            assertEquals(DtlsVersion.Dtls12, c.negotiatedVersion)
            assertEquals(DtlsVersion.Dtls12, s.negotiatedVersion)
            assertEquals(server.localFingerprint, c.peerFingerprint)
        } finally {
            client.close()
            server.close()
        }
    }

    @Test
    fun application_data_flows_after_the_handshake() {
        val client = DtlsEngine(DtlsRole.Client, DtlsConfig())
        val server = DtlsEngine(DtlsRole.Server, DtlsConfig())
        try {
            drive(client, server)
            // Client encrypts a payload; server must decrypt the identical bytes.
            val payload = bytesOf(0xDE, 0xAD, 0xBE, 0xEF, 0x2A)
            val sent = client.send(payload, now)
            assertTrue(sent.records.isNotEmpty(), "encrypted record produced")

            var decrypted: ReadBuffer? = null
            for (rec in sent.records) {
                val step = server.onDatagram(rec, now)
                if (step.applicationData.isNotEmpty()) decrypted = step.applicationData.first()
            }
            assertNotNull(decrypted, "server decrypted application data")
            assertEquals("deadbeef2a", hexOf(decrypted))
        } finally {
            client.close()
            server.close()
        }
    }

    // ── a deterministic synchronous two-endpoint conductor over a virtual clock ─────────────────────

    private var now = 0L

    /** Shuttle records between the two engines, firing DTLS timers when both stall, until both settle. */
    private fun drive(
        client: DtlsEngine,
        server: DtlsEngine,
    ): Pair<DtlsState, DtlsState> {
        val toServer = ArrayDeque<ReadBuffer>()
        val toClient = ArrayDeque<ReadBuffer>()

        var cState: DtlsState = client.start(now).also { toServer.addAll(it.records) }.state
        var sState: DtlsState = DtlsState.Handshaking

        var guard = 0
        while (guard++ < 200) {
            if (cState is DtlsState.Established && sState is DtlsState.Established) break
            if (cState is DtlsState.Failed) break
            if (sState is DtlsState.Failed) break

            if (toServer.isNotEmpty()) {
                val step = server.onDatagram(toServer.removeFirst(), now)
                sState = step.state
                toClient.addAll(step.records)
            } else if (toClient.isNotEmpty()) {
                val step = client.onDatagram(toClient.removeFirst(), now)
                cState = step.state
                toServer.addAll(step.records)
            } else {
                // Both idle mid-handshake → advance virtual time to the nearest armed DTLS timer.
                val deadlines = listOfNotNull(client.nextTimeoutMicros(now), server.nextTimeoutMicros(now))
                if (deadlines.isEmpty()) break
                now = maxOf(now + 1, deadlines.min())
                client.onTimeout(now).let {
                    cState = it.state
                    toServer.addAll(it.records)
                }
                server.onTimeout(now).let {
                    sState = it.state
                    toClient.addAll(it.records)
                }
            }
        }
        return cState to sState
    }

    private fun bytesOf(vararg values: Int): ReadBuffer {
        val buf = BufferFactory.managed().allocate(values.size, ByteOrder.BIG_ENDIAN)
        values.forEach { buf.writeByte(it.toByte()) }
        buf.resetForRead()
        return buf
    }

    private fun hexOf(buf: ReadBuffer): String {
        val sb = StringBuilder()
        while (buf.limit() - buf.position() > 0) {
            val b = buf.readByte().toInt() and 0xFF
            sb.append("0123456789abcdef"[b ushr 4])
            sb.append("0123456789abcdef"[b and 0x0F])
        }
        return sb.toString()
    }
}
