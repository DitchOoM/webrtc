@file:OptIn(ExperimentalTime::class)

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
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * A third independent DTLS 1.2 client against our server: **werift** (pure TypeScript), the stack the
 * `node-interop` / `jvm-node` L2 harness lanes use as their answerer. Same shape as
 * [DtlsOpensslDifferentialJvmTest], but over a JS implementation whose record layer, PRF and AEAD share
 * nothing with OpenSSL/BoringSSL — so it catches the class of bug the C stacks tolerate.
 *
 * Runtime-only, and skips cleanly unless BOTH `node` and an installed `werift` are present (the harness
 * image installs one under `test-harness/node/node_modules`; `WERIFT_MODULE_DIR` overrides).
 */
class DtlsWeriftDifferentialJvmTest {
    private val factory: BufferFactory = BufferFactory.managed()

    @Test
    fun our_server_completes_a_handshake_and_exchanges_data_with_a_werift_client() {
        val werift = weriftModuleDir()
        if (werift == null || !nodeAvailable() || !opensslAvailable()) {
            println("[skip] node/werift/openssl not available — DTLS werift differential not run")
            return
        }
        val work =
            File.createTempFile("dtls-werift", "").apply {
                delete()
                mkdirs()
            }
        try {
            val cert = File(work, "client-cert.pem")
            val key = File(work, "client-key.pem")
            generateEcdsaCert(cert, key)
            val expectedPeerFp = sha256FingerprintOf(cert)
            val script = File(work, "werift-client.mjs").apply { writeText(CLIENT_SCRIPT) }

            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { socket ->
                socket.soTimeout = POLL_MILLIS
                val server = DtlsEngine(DtlsConfig(bufferFactory = factory, enableDtls13 = false))
                val t0 = System.nanoTime()

                fun now(): Instant = Instant.fromEpochSeconds(0) + (System.nanoTime() - t0).nanoseconds

                val proc =
                    ProcessBuilder(
                        "node",
                        script.absolutePath,
                        "127.0.0.1",
                        socket.localPort.toString(),
                        cert.absolutePath,
                        key.absolutePath,
                    ).apply {
                        environment()["WERIFT_DIR"] = werift.absolutePath
                        redirectErrorStream(true)
                    }.start()
                val nodeOut = ConcurrentLinkedQueue<String>()
                val stdoutPump =
                    Thread {
                        try {
                            proc.inputStream.bufferedReader().forEachLine { nodeOut.add(it) }
                        } catch (_: Throwable) {
                        }
                    }.apply {
                        isDaemon = true
                        start()
                    }

                try {
                    server.start(DtlsRole.Server, now())
                    var peer: SocketAddress? = null
                    var state: DtlsState = DtlsState.Handshaking

                    val handshakeDeadline = System.nanoTime() + HANDSHAKE_TIMEOUT_NANOS
                    while (state !is DtlsState.Established && System.nanoTime() < handshakeDeadline) {
                        val inbound = receive(socket)
                        if (inbound != null) {
                            peer = inbound.socketAddress
                            val step = server.onDatagram(toBuffer(inbound.data, inbound.length), now())
                            sendAll(socket, step.records, peer)
                            state = step.state
                            (state as? DtlsState.Failed)?.let {
                                fail("our server failed the handshake: ${it.reason} — werift: $nodeOut")
                            }
                        } else {
                            val due = server.nextDeadline(now())
                            if (due != null && now() >= due) {
                                sendAll(socket, server.onTimeout(now()).records, peer)
                            }
                        }
                    }
                    assertIs<DtlsState.Established>(state, "our server established against werift — werift: $nodeOut")
                    assertEquals(expectedPeerFp, state.peerFingerprint.sha256Hex)
                    assertEquals(DtlsVersion.Dtls12, state.negotiatedVersion)

                    // werift must ALSO consider itself connected (it only sends after our Finished lands)
                    // and be able to decrypt our application data — the half the pcap can never show.
                    val decrypted = StringBuilder()
                    val appDeadline = System.nanoTime() + APPDATA_TIMEOUT_NANOS
                    while (!decrypted.contains(WERIFT_PING) && System.nanoTime() < appDeadline) {
                        val inbound = receive(socket)
                        if (inbound == null) {
                            val due = server.nextDeadline(now())
                            if (due != null && now() >= due) sendAll(socket, server.onTimeout(now()).records, peer)
                            continue
                        }
                        val step = server.onDatagram(toBuffer(inbound.data, inbound.length), now())
                        sendAll(socket, step.records, inbound.socketAddress)
                        step.applicationData.forEach { decrypted.append(fromBuffer(it)) }
                    }
                    assertTrue(
                        nodeOut.any { it.contains("WERIFT-CONNECTED") },
                        "werift reached DTLS connected on our server's final flight — werift: $nodeOut",
                    )
                    // werift's post-connect RFC 8827 check: the SHA-256 of the certificate DER it received
                    // must equal the a=fingerprint we would have published (DtlsEngine.localFingerprint).
                    assertEquals(
                        "WERIFT-PEER-FP ${server.localFingerprint.sha256Hex}",
                        nodeOut.first { it.startsWith("WERIFT-PEER-FP") },
                        "werift's SHA-256 of our certificate matches the fingerprint we advertise in SDP",
                    )
                    assertTrue(
                        decrypted.contains(WERIFT_PING),
                        "our server decrypted werift's application data (got '$decrypted') — werift: $nodeOut",
                    )

                    val reply = "pong-from-ours-4f1a"
                    sendAll(socket, server.send(toBuffer(reply.encodeToByteArray()), now()).records, peer)
                    val echoDeadline = System.nanoTime() + APPDATA_TIMEOUT_NANOS
                    var sawReply = false
                    while (!sawReply && System.nanoTime() < echoDeadline) {
                        sawReply = nodeOut.any { it.contains(reply) }
                        if (!sawReply) Thread.sleep(20)
                    }
                    assertTrue(sawReply, "werift decrypted our application data (saw: $nodeOut)")
                } finally {
                    server.close()
                    proc.destroyForcibly()
                    stdoutPump.interrupt()
                    println(nodeOut.joinToString("\n"))
                }
            }
        } finally {
            work.deleteRecursively()
        }
    }

    // ── UDP plumbing (jvmTest: ByteArray is fine outside *Main) ─────────────────────────────────────

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

    private fun fromBuffer(buf: ReadBuffer): String = toByteArray(buf).decodeToString()

    // ── external-tool discovery ────────────────────────────────────────────────────────────────────

    private fun weriftModuleDir(): File? {
        System.getenv("WERIFT_MODULE_DIR")?.let { return File(it).takeIf { d -> d.isDirectory } }
        var dir: File? = File("").absoluteFile
        while (dir != null) {
            val candidate = File(dir, "test-harness/node/node_modules/werift")
            if (candidate.isDirectory) return candidate
            dir = dir.parentFile
        }
        return null
    }

    private fun nodeAvailable(): Boolean = runs("node", "--version")

    private fun opensslAvailable(): Boolean = runs("openssl", "version")

    private fun runs(vararg cmd: String): Boolean =
        try {
            ProcessBuilder(*cmd).redirectErrorStream(true).start().waitFor() == 0
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
                "/CN=werift-peer",
            ).redirectErrorStream(true).start().waitFor()
        assertEquals(0, rc, "openssl req generated a throwaway ECDSA cert")
    }

    private fun sha256FingerprintOf(cert: File): String {
        val proc =
            ProcessBuilder("openssl", "x509", "-in", cert.absolutePath, "-noout", "-fingerprint", "-sha256")
                .redirectErrorStream(true)
                .start()
        val line = proc.inputStream.bufferedReader().readText()
        proc.waitFor()
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
        const val HANDSHAKE_TIMEOUT_NANOS = 30_000_000_000L
        const val APPDATA_TIMEOUT_NANOS = 15_000_000_000L
        const val WERIFT_PING = "ping-from-werift"

        /** werift's DtlsClient over a plain `dgram` transport, printing a line per lifecycle event. */
        val CLIENT_SCRIPT =
            """
            import dgram from "node:dgram";
            import fs from "node:fs";
            import { createHash } from "node:crypto";
            import { createRequire } from "node:module";

            const require = createRequire(import.meta.url);
            const { DtlsClient } = require(process.env.WERIFT_DIR + "/lib/dtls/src/client");

            const [host, portStr, certPath, keyPath] = process.argv.slice(2);
            const port = Number(portStr);

            const socket = dgram.createSocket("udp4");
            await new Promise((r) => socket.bind(0, "127.0.0.1", r));

            const transport = {
              type: "udp",
              get address() { return socket.address(); },
              closed: false,
              onData: () => {},
              send: async (data) =>
                new Promise((res, rej) => socket.send(data, port, host, (e) => (e ? rej(e) : res()))),
              close: async () => socket.close(),
            };
            socket.on("message", (data) => transport.onData(data, [host, port]));

            // Exactly the options werift's own RTCDtlsTransport passes in the client role (see
            // webrtc/src/transport/dtls.ts): SRTP profiles offered even for a data-channel-only session,
            // extended master secret on, and NO `certificateRequest` — so our CertificateRequest has to be
            // parsed off the wire for werift to send a client certificate at all.
            const client = new DtlsClient({
              transport,
              cert: fs.readFileSync(certPath, "utf8"),
              key: fs.readFileSync(keyPath, "utf8"),
              signatureHash: { hash: 4, signature: 3 },
              srtpProfiles: [7, 1],
              extendedMasterSecret: true,
            });

            client.onConnect.subscribe(() => {
              console.log("WERIFT-CONNECTED");
              // The check werift's RTCDtlsTransport runs right after connecting: SHA-256 of our
              // certificate's DER, matched against the SDP a=fingerprint. A mismatch there throws inside
              // an unawaited promise — the peer would just sit in `connecting` forever.
              const der = client.remoteCertificate;
              console.log(
                "WERIFT-PEER-FP " +
                  (der ? createHash("sha256").update(der).digest("hex") : "<none>"),
              );
              setInterval(() => client.send(Buffer.from("$WERIFT_PING")), 250);
            });
            client.onData.subscribe((d) => console.log("WERIFT-DATA " + d.toString()));
            client.onError.subscribe((e) => console.log("WERIFT-ERROR " + e));
            client.onClose.subscribe(() => console.log("WERIFT-CLOSED"));

            await client.connect();
            setTimeout(() => {
              console.log("WERIFT-TIMEOUT connected=" + client.connected);
              process.exit(client.connected ? 0 : 3);
            }, 40000);
            """.trimIndent()
    }
}
