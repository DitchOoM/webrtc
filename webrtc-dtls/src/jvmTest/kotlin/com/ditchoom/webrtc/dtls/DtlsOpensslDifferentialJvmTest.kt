package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The highest-value differential (owner's ask, 2026-07-20): our pure-Kotlin [DtlsEngine] as a DTLS
 * **server** completes a real handshake against `openssl s_client -dtls1_2` over a live loopback UDP
 * socket, then exchanges encrypted application data — proving interop against a **second** independent
 * stack (OpenSSL's, sharing no code with our engine or with the BoringSSL oracle). This is the coverage
 * a self-loopback structurally cannot give: OpenSSL only completes if our ServerHello, our ECDHE
 * ServerKeyExchange signature, our TLS-1.2 PRF `verify_data`, and our AES-128-GCM records are all
 * byte-correct, and it independently verifies the `a=fingerprint` binding by presenting a cert whose
 * SHA-256 we cross-check against the file OpenSSL was handed.
 *
 * OpenSSL is the client (not `s_server`) on purpose: `s_client` tolerates our self-signed server cert
 * by default (prints a verify warning, continues), whereas making `s_server` accept a self-signed
 * *client* cert for mutual auth needs a verify callback it doesn't expose. Our server only fingerprints
 * the peer (RFC 8827 — no PKI), so it accepts OpenSSL's self-signed client cert symmetrically.
 *
 * Runtime-only (a real subprocess + socket); skips cleanly where `openssl` is absent (e.g. a minimal CI
 * image) so it never turns a missing external tool into a red build.
 */
class DtlsOpensslDifferentialJvmTest {
    private val factory: BufferFactory = BufferFactory.managed()

    @Test
    fun our_server_completes_a_handshake_and_exchanges_data_with_openssl_s_client() {
        if (!opensslAvailable()) {
            println("[skip] openssl not on PATH — DTLS openssl differential not run")
            return
        }
        val work =
            File.createTempFile("dtls-openssl", "").apply {
                delete()
                mkdirs()
            }
        try {
            val cert = File(work, "client-cert.pem")
            val key = File(work, "client-key.pem")
            generateEcdsaCert(cert, key)
            val expectedPeerFp = sha256FingerprintOf(cert) // OpenSSL presents this cert; our server must see it

            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { socket ->
                socket.soTimeout = POLL_MILLIS
                val server = DtlsEngine(DtlsConfig(bufferFactory = factory, enableDtls13 = false))
                val t0 = System.nanoTime()

                fun nowUs() = (System.nanoTime() - t0) / 1000

                // Launch openssl s_client as the DTLS client pointed at our socket.
                val proc =
                    ProcessBuilder(
                        "openssl",
                        "s_client",
                        "-dtls1_2",
                        "-quiet",
                        "-connect",
                        "127.0.0.1:${socket.localPort}",
                        "-cert",
                        cert.absolutePath,
                        "-key",
                        key.absolutePath,
                        "-cipher",
                        "ECDHE-ECDSA-AES128-GCM-SHA256",
                    ).redirectErrorStream(true).start()
                val opensslOut = ConcurrentLinkedQueue<String>()
                val stdoutPump =
                    Thread {
                        try {
                            proc.inputStream.bufferedReader().forEachLine { opensslOut.add(it) }
                        } catch (_: Throwable) {
                        }
                    }.apply {
                        isDaemon = true
                        start()
                    }

                try {
                    server.start(DtlsRole.Server, nowUs()) // arms the server; no records until fed
                    var peer: SocketAddress? = null
                    var state: DtlsState = DtlsState.Handshaking
                    var rxCount = 0
                    var txCount = 0

                    // ── handshake pump: relay datagrams, firing our retransmit timer on a quiet link ──
                    val handshakeDeadline = System.nanoTime() + HANDSHAKE_TIMEOUT_NANOS
                    while (state !is DtlsState.Established && System.nanoTime() < handshakeDeadline) {
                        val inbound = receive(socket)
                        if (inbound != null) {
                            rxCount++
                            peer = inbound.socketAddress
                            val step = server.onDatagram(toBuffer(inbound.data, inbound.length), nowUs())
                            txCount += step.records.size
                            sendAll(socket, step.records, peer)
                            state = step.state
                            (state as? DtlsState.Failed)?.let {
                                fail("our server failed the handshake: ${it.reason} — openssl: $opensslOut")
                            }
                        } else {
                            // socket timed out — fire the DTLS timer if a flight is due for retransmit.
                            val due = server.nextTimeoutMicros(nowUs())
                            if (due != null && nowUs() >= due) {
                                val step = server.onTimeout(nowUs())
                                txCount += step.records.size
                                sendAll(socket, step.records, peer)
                            }
                        }
                    }

                    assertIs<DtlsState.Established>(
                        state,
                        "our server established against openssl s_client (rx=$rxCount tx=$txCount peer=$peer) — openssl: $opensslOut",
                    )
                    assertEquals(
                        expectedPeerFp,
                        state.peerFingerprint.sha256Hex,
                        "our server fingerprinted OpenSSL's actual client certificate",
                    )
                    assertEquals(DtlsVersion.Dtls12, state.negotiatedVersion)

                    // ── openssl → ours: openssl encrypts a line from its stdin; our server must decrypt it ──
                    val token = "ping-from-openssl-7a2b"
                    proc.outputStream.write("$token\n".toByteArray())
                    proc.outputStream.flush()

                    val decrypted = StringBuilder()
                    val appDeadline = System.nanoTime() + APPDATA_TIMEOUT_NANOS
                    while (!decrypted.contains(token) && System.nanoTime() < appDeadline) {
                        val inbound = receive(socket) ?: continue
                        val step = server.onDatagram(toBuffer(inbound.data, inbound.length), nowUs())
                        sendAll(socket, step.records, inbound.socketAddress)
                        step.applicationData.forEach { decrypted.append(fromBuffer(it)) }
                    }
                    assertTrue(decrypted.contains(token), "our server decrypted OpenSSL's application data (got: '$decrypted')")

                    // ── ours → openssl: our server encrypts; openssl -quiet prints the plaintext to stdout ──
                    val reply = "pong-from-ours-9c3d"
                    sendAll(socket, server.send(toBuffer("$reply\n".toByteArray()), nowUs()).records, peer)
                    val echoDeadline = System.nanoTime() + APPDATA_TIMEOUT_NANOS
                    var sawReply = false
                    while (!sawReply && System.nanoTime() < echoDeadline) {
                        sawReply = opensslOut.any { it.contains(reply) }
                        if (!sawReply) Thread.sleep(20)
                    }
                    assertTrue(sawReply, "openssl decrypted our application data and echoed it to stdout (saw: $opensslOut)")
                } finally {
                    server.close()
                    proc.destroyForcibly()
                    stdoutPump.interrupt()
                }
            }
        } finally {
            work.deleteRecursively()
        }
    }

    // ── UDP + subprocess plumbing (jvmTest: ByteArray is fine outside *Main) ────────────────────────

    private fun receive(socket: DatagramSocket): DatagramPacket? {
        val pkt = DatagramPacket(ByteArray(MAX_DATAGRAM), MAX_DATAGRAM)
        return try {
            socket.receive(pkt)
            pkt
        } catch (_: SocketTimeoutException) {
            null
        }
    }

    private fun sendAll(
        socket: DatagramSocket,
        records: List<ReadBuffer>,
        peer: SocketAddress?,
    ) {
        if (peer == null) return
        for (record in records) {
            val bytes = toByteArray(record)
            socket.send(DatagramPacket(bytes, bytes.size, peer))
        }
    }

    private fun toBuffer(
        bytes: ByteArray,
        len: Int = bytes.size,
    ): ReadBuffer {
        val b = factory.allocate(len, ByteOrder.BIG_ENDIAN)
        for (i in 0 until len) b.writeByte(bytes[i])
        b.resetForRead()
        return b
    }

    private fun toByteArray(buf: ReadBuffer): ByteArray {
        val p = buf.position()
        val n = buf.remaining()
        val out = ByteArray(n)
        for (i in 0 until n) out[i] = buf.readByte()
        buf.position(p)
        return out
    }

    private fun fromBuffer(buf: ReadBuffer): String {
        val bytes = toByteArray(buf)
        return bytes.decodeToString()
    }

    // ── openssl helpers ────────────────────────────────────────────────────────────────────────────

    private fun opensslAvailable(): Boolean =
        try {
            ProcessBuilder("openssl", "version").redirectErrorStream(true).start().waitFor() == 0
        } catch (_: Throwable) {
            false
        }

    private fun generateEcdsaCert(
        cert: File,
        key: File,
    ) {
        val rc =
            ProcessBuilder(
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                key.absolutePath,
                "-out",
                cert.absolutePath,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=openssl-peer",
            ).redirectErrorStream(true).start().waitFor()
        assertEquals(0, rc, "openssl req generated a throwaway ECDSA cert")
    }

    /** Lowercase, colon-free SHA-256 of the cert's DER — the form [CertificateFingerprint.sha256Hex] uses. */
    private fun sha256FingerprintOf(cert: File): String {
        val proc =
            ProcessBuilder("openssl", "x509", "-in", cert.absolutePath, "-noout", "-fingerprint", "-sha256")
                .redirectErrorStream(true)
                .start()
        val line = proc.inputStream.bufferedReader().readText()
        proc.waitFor()
        // Format: "sha256 Fingerprint=AB:CD:...:EF"
        val hex =
            line
                .substringAfter('=', "")
                .trim()
                .replace(":", "")
                .lowercase()
        assertTrue(hex.length == 64, "parsed a 32-byte fingerprint from openssl x509, got '$line'")
        return hex
    }

    private companion object {
        const val MAX_DATAGRAM = 65536
        const val POLL_MILLIS = 300
        const val HANDSHAKE_TIMEOUT_NANOS = 20_000_000_000L // 20s — generous for a subprocess + loopback
        const val APPDATA_TIMEOUT_NANOS = 10_000_000_000L
    }
}
