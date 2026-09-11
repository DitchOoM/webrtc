@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.testsuite

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramCapabilities
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.socket.quic.CertificateHash
import com.ditchoom.socket.quic.MigrationResult
import com.ditchoom.socket.quic.QuicByteStream
import com.ditchoom.socket.quic.QuicOptions
import com.ditchoom.socket.quic.QuicScope
import com.ditchoom.socket.quic.QuicTlsConfig
import com.ditchoom.socket.quic.ScopedRead
import com.ditchoom.socket.quic.read
import com.ditchoom.webrtc.ice.CandidateType
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.ice.IceAgentDriver
import com.ditchoom.webrtc.ice.IceConnectionState
import com.ditchoom.webrtc.ice.IceRole
import com.ditchoom.webrtc.quic.QuicOverIceIdentity
import com.ditchoom.webrtc.quic.QuicOverIceOutcome
import com.ditchoom.webrtc.quic.QuicOverIcePath
import com.ditchoom.webrtc.quic.QuicOverIceRole
import com.ditchoom.webrtc.quic.quicOverIce
import com.ditchoom.webrtc.testsuite.vnet.NatProfile
import com.ditchoom.webrtc.testsuite.vnet.Vnets
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.File
import kotlin.coroutines.CoroutineContext
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * QUIC over ICE on the vnet — the ICE mode of `draft-seemann-quic-nat-traversal`, end to end: two
 * **production** [IceAgentDriver]s behind full-cone NATs gather host + server-reflexive candidates
 * against the vnet STUN server and nominate a pair; then a real quiche connection is opened on that
 * pair through `webrtc-quic` — the controlling agent dials, the controlled one listens — and a stream
 * is echoed across it. No socket is bound for QUIC: it rides the very vnet endpoint ICE checked.
 *
 * Real time rather than `runTest`: quiche's timers and threads are wall-clock, and a virtual `withTimeout`
 * around wall-clock work fires the instant the scheduler idles. The watchdog is therefore a real
 * [withTimeout] on observable outcomes (directive 4), never a budget on any step. ICE and the vnet share
 * ONE serial dispatcher, because the vnet is single-threaded by design and quiche sends from its own
 * pool — see [sendingOn].
 */
class QuicOverIceVnetTest {
    @Test
    fun a_quic_stream_echoes_over_the_pair_ice_nominated_through_full_cone_nats() =
        runBlocking {
            val ice = Dispatchers.Default.limitedParallelism(1)
            val scope = CoroutineScope(SupervisorJob() + ice)
            val identity = TestQuicIdentity.materialize()
            try {
                withTimeout(WATCHDOG) {
                    withContext(ice) {
                        val topology = Vnets.build(scope, NatProfile.FullCone)
                        val binder = DatagramBinder { topology.vnet.bind(it).sendingOn(ice) }
                        val clock = { Clock.System.now() }
                        val alice = IceAgentDriver(IceRole.Controlling, Random(1), binder, scope, clock)
                        val bob = IceAgentDriver(IceRole.Controlled, Random(2), binder, scope, clock)
                        alice.start()
                        bob.start()
                        alice.gatherHost(topology.aliceHost.host, topology.aliceHost.port, topology.stunAddress)
                        bob.gatherHost(topology.bobHost.host, topology.bobHost.port, topology.stunAddress)
                        signal(from = alice, to = bob)
                        signal(from = bob, to = alice)
                        alice.awaitConnected()
                        bob.awaitConnected()

                        val server =
                            async {
                                bob.quicOverIce(identity.endpoint) { path ->
                                    echoUntilEnd()
                                    path
                                }
                            }
                        val client =
                            async {
                                alice.quicOverIce(identity.endpoint) { path ->
                                    val migration = migrate()
                                    val stream = openStream()
                                    stream.write(utf8(MESSAGE), DEADLINE)
                                    stream.shutdownSend()
                                    ClientRun(path, migration, echoed = readToEnd(stream))
                                }
                            }

                        val run =
                            when (val outcome = client.await()) {
                                is QuicOverIceOutcome.Completed -> outcome.value
                                is QuicOverIceOutcome.PairMoved -> fail("the pair moved under the client: $outcome")
                                is QuicOverIceOutcome.IceFailed -> fail("ICE failed under the client: $outcome")
                            }
                        val served =
                            when (val outcome = server.await()) {
                                is QuicOverIceOutcome.Completed -> outcome.value
                                is QuicOverIceOutcome.PairMoved -> fail("the pair moved under the server: $outcome")
                                is QuicOverIceOutcome.IceFailed -> fail("ICE failed under the server: $outcome")
                            }

                        assertEquals(MESSAGE, run.echoed, "the stream must come back byte for byte over the nominated pair")
                        assertEquals(QuicOverIceRole.Client, run.path.role, "the controlling agent dials")
                        assertEquals(QuicOverIceRole.Server, served.role, "the controlled agent listens")
                        // The pair was reached THROUGH the NATs, not around them: each side meets the peer on the
                        // server-reflexive address the vnet STUN server reported, pairing its own srflx as its base
                        // (RFC 8445 §6.1.2.2).
                        assertEquals(CandidateType.ServerReflexive, run.path.pair.remote.type, "the client dialled the peer's srflx")
                        assertEquals(CandidateType.ServerReflexive, served.pair.remote.type, "the server answered the peer's srflx")
                        assertEquals(CandidateType.Host, run.path.pair.local.type, "a local srflx pairs as its base")
                        // Limit 1, as a value the caller sees: a client on ICE's socket cannot migrate — the socket's
                        // owner is the only thing that can move the path, whatever MigrationPolicy asked for.
                        assertEquals(
                            MigrationResult.Unmoved.Impossible.BackendCannotMigrate,
                            run.migration,
                            "a shared-port client reports that it cannot migrate, rather than pretending",
                        )
                        // ICE was untouched by the QUIC bytes riding beside its checks: nothing QUIC sent was
                        // mistaken for a connectivity check, and consent kept flowing on both sides.
                        assertTrue(alice.state.value.isConverged(), "alice's ICE session survived QUIC: ${alice.state.value}")
                        assertTrue(bob.state.value.isConverged(), "bob's ICE session survived QUIC: ${bob.state.value}")

                        alice.close()
                        bob.close()
                        topology.vnet.close()
                    }
                }
            } finally {
                scope.cancel()
                identity.delete()
            }
        }

    /** What the dialling side observed, returned through the composition's outcome. */
    private data class ClientRun(
        val path: QuicOverIcePath,
        val migration: MigrationResult,
        val echoed: String,
    )

    private suspend fun QuicScope.echoUntilEnd() {
        val stream = acceptStream()
        while (true) {
            when (stream.read(DEADLINE) { chunk -> stream.write(chunk, DEADLINE) }) {
                is ScopedRead.Data -> continue
                ScopedRead.End -> break
                ScopedRead.Reset -> fail("the client reset the echo stream")
            }
        }
        stream.shutdownSend()
    }

    private suspend fun readToEnd(stream: QuicByteStream): String {
        val text = StringBuilder()
        while (true) {
            when (val read = stream.read(DEADLINE) { it.readString(it.remaining(), Charset.UTF8) }) {
                is ScopedRead.Data -> text.append(read.value)
                ScopedRead.End -> return text.toString()
                ScopedRead.Reset -> fail("the server reset the echo stream")
            }
        }
    }

    // Scripted signaling: hand [from]'s credentials + candidates to [to] (the trickle seam, direct).
    private fun signal(
        from: IceAgentDriver,
        to: IceAgentDriver,
    ) {
        to.setRemoteCredentials(from.localCredentials)
        from.localCandidates.forEach { to.addRemoteCandidate(it) }
    }

    private suspend fun IceAgentDriver.awaitConnected(): IceConnectionState =
        state.first {
            when (it) {
                is IceConnectionState.Connected, is IceConnectionState.Completed -> true
                is IceConnectionState.Failed -> error("expected a connection, but ICE failed: ${it.reason}")
                IceConnectionState.New, IceConnectionState.Checking -> false
            }
        }

    private fun IceConnectionState.isConverged(): Boolean =
        when (this) {
            is IceConnectionState.Connected, is IceConnectionState.Completed -> true
            is IceConnectionState.Failed, IceConnectionState.New, IceConnectionState.Checking -> false
        }

    private fun utf8(text: String): ReadBuffer =
        BufferFactory.Default.allocate(text.length * MAX_UTF8_BYTES_PER_CHAR).apply {
            writeString(text, Charset.UTF8)
            resetForRead()
        }

    /**
     * The vnet is single-threaded by design (its NAT tables are plain maps), and every ICE driver here runs
     * on one serial dispatcher — but quiche sends from its own pool. Hop each send onto that dispatcher so
     * the vnet's contract holds; a receive is a channel read and needs no hop.
     */
    private fun AddressedDatagramChannel.sendingOn(context: CoroutineContext): AddressedDatagramChannel =
        object : AddressedDatagramChannel {
            override val localAddress: SocketAddress get() = this@sendingOn.localAddress
            override val isOpen: Boolean get() = this@sendingOn.isOpen
            override val capabilities: DatagramCapabilities get() = this@sendingOn.capabilities
            override val maxWritableSize: Int get() = this@sendingOn.maxWritableSize

            override suspend fun receive(): DatagramReadResult = this@sendingOn.receive()

            override suspend fun send(
                payload: ReadBuffer,
                to: SocketAddress,
                options: DatagramSendOptions,
            ) = withContext(context) { this@sendingOn.send(payload, to, options) }

            override fun close() = this@sendingOn.close()
        }

    /**
     * One self-signed P-256 leaf for both endpoints, written to temp files because quiche loads PEM by
     * path. The dialling side pins its SHA-256 (the `a=fingerprint` shape of trust, not a CA) — so the
     * handshake is verified, not `verifyPeer = false`.
     */
    private class TestQuicIdentity private constructor(
        private val cert: File,
        private val key: File,
    ) {
        val endpoint =
            QuicOverIceIdentity(
                tls = QuicTlsConfig(certChainPath = cert.absolutePath, privKeyPath = key.absolutePath),
                options =
                    QuicOptions(
                        alpnProtocols = listOf(ALPN),
                        serverCertificateHashes = listOf(pinnedHash()),
                    ),
            )

        fun delete() {
            cert.delete()
            key.delete()
        }

        companion object {
            fun materialize(): TestQuicIdentity =
                TestQuicIdentity(
                    cert = File.createTempFile("quic-over-ice", ".crt").apply { writeText(CERT_PEM) },
                    key = File.createTempFile("quic-over-ice", ".key").apply { writeText(KEY_PEM) },
                )

            private fun pinnedHash(): CertificateHash {
                val digest = BufferFactory.Default.allocate(CERT_SHA256_HEX.length / 2)
                CERT_SHA256_HEX.chunked(2).forEach { digest.writeByte(it.toInt(16).toByte()) }
                digest.resetForRead()
                return CertificateHash(digest)
            }
        }
    }

    private companion object {
        val WATCHDOG = 60.seconds
        val DEADLINE = 10.seconds
        const val MESSAGE = "hello over the pair ICE nominated"
        const val ALPN = "quic-over-ice-echo"
        const val MAX_UTF8_BYTES_PER_CHAR = 4

        // openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 -subj /CN=quic-over-ice
        const val CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBqjCCAVCgAwIBAgIUTdiYRnGi5Y/0ddFv+Nt7J+B6kHEwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcXVpYy1vdmVyLWljZTAgFw0yNjA5MTExNzI2NThaGA8yMTI2
MDgxODE3MjY1OFowGDEWMBQGA1UEAwwNcXVpYy1vdmVyLWljZTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABJxr3PzQ1Er1eMc18+yDHlgLXogKeLDfBdWAa7i2g05w
zRdiDYk4hT0hBEOdNrpbT/7L7evbYWdyEIYj7Xfv5NGjdjB0MB0GA1UdDgQWBBSs
I58XgxrecQuxvRkjHzDceX2k7zAfBgNVHSMEGDAWgBSsI58XgxrecQuxvRkjHzDc
eX2k7zAPBgNVHRMBAf8EBTADAQH/MCEGA1UdEQQaMBiHBMsAcRSHBMsAcQqHBMsA
cSCHBMsAcR8wCgYIKoZIzj0EAwIDSAAwRQIhAODbUpNvU3vuk6wtB0MI6WDaCXe7
1HD8G1dIwC3pfZ40AiBddpwlwbz2NlRfUGZ/VkdYw3GlNlIeXHArgMPcHellmQ==
-----END CERTIFICATE-----
"""
        const val KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLYa+L7GQHLSf6UpZ
/JUZn1m8DY5LRHf54APGgnS54M6hRANCAASca9z80NRK9XjHNfPsgx5YC16ICniw
3wXVgGu4toNOcM0XYg2JOIU9IQRDnTa6W0/+y+3r22FnchCGI+137+TR
-----END PRIVATE KEY-----
"""

        // openssl x509 -in cert -outform DER | openssl dgst -sha256
        const val CERT_SHA256_HEX = "4b5890066454ba0c61f4da6c91fedab74d3b36d04ac4029686c1c044ed6c1cb1"
    }
}
