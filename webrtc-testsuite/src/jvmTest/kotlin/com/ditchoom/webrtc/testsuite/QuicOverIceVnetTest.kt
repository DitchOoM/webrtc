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
import com.ditchoom.webrtc.ice.IcePath
import com.ditchoom.webrtc.ice.IceRole
import com.ditchoom.webrtc.quic.QuicOverIceIdentity
import com.ditchoom.webrtc.quic.QuicOverIceOutcome
import com.ditchoom.webrtc.quic.QuicOverIcePath
import com.ditchoom.webrtc.quic.QuicOverIceRole
import com.ditchoom.webrtc.quic.quicOverIce
import com.ditchoom.webrtc.testsuite.vnet.NatProfile
import com.ditchoom.webrtc.testsuite.vnet.Vnets
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Base64
import kotlin.coroutines.CoroutineContext
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
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

    /**
     * Limit 2, as a value: an ICE restart that nominates another pair ends the QUIC session as
     * [QuicOverIceOutcome.PairMoved] on **both** sides, naming the pair it rode and the pair ICE moved
     * to. Nothing in QUIC can follow — a shared-port client cannot migrate and QUIC v1 cannot chase a
     * peer's address — so the caller reconnects over `to`, and the composition says so instead of
     * leaving an idle timeout to be interpreted.
     */
    @Test
    fun an_ice_restart_that_nominates_another_pair_ends_the_session_as_pair_moved() =
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
                        val alice = IceAgentDriver(IceRole.Controlling, Random(3), binder, scope, clock)
                        val bob = IceAgentDriver(IceRole.Controlled, Random(4), binder, scope, clock)
                        alice.start()
                        bob.start()
                        alice.gatherHost(topology.aliceHost.host, topology.aliceHost.port, topology.stunAddress)
                        bob.gatherHost(topology.bobHost.host, topology.bobHost.port, topology.stunAddress)
                        signal(from = alice, to = bob)
                        signal(from = bob, to = alice)
                        alice.awaitConnected()
                        bob.awaitConnected()

                        // Both sessions echo once to prove they are up, then hold the connection open.
                        val echoed = CompletableDeferred<String>()
                        val server =
                            async {
                                bob.quicOverIce(identity.endpoint) { path ->
                                    echoUntilEnd()
                                    awaitCancellation()
                                }
                            }
                        val client =
                            async {
                                alice.quicOverIce(identity.endpoint) { path ->
                                    val stream = openStream()
                                    stream.write(utf8(MESSAGE), DEADLINE)
                                    stream.shutdownSend()
                                    echoed.complete(readToEnd(stream))
                                    awaitCancellation()
                                }
                            }
                        assertEquals(MESSAGE, echoed.await(), "the session was up before the restart")
                        val before = alice.path.value
                        val riddenBefore =
                            if (before is IcePath.Nominated) {
                                before.pair
                            } else {
                                fail(
                                    "a nominated pair before the restart, got $before",
                                )
                            }

                        // RFC 8445 §9: both agents restart, re-gather on a fresh base (the vnet needs a free
                        // address, which is what makes "did the pair move?" observable), re-signal, reconverge.
                        alice.restartAndAwait()
                        bob.restartAndAwait()
                        alice.gatherHost(topology.aliceHost.host, topology.aliceHost.port + 1, topology.stunAddress)
                        bob.gatherHost(topology.bobHost.host, topology.bobHost.port + 1, topology.stunAddress)
                        signal(from = alice, to = bob)
                        signal(from = bob, to = alice)

                        val clientMoved =
                            when (val outcome = client.await()) {
                                is QuicOverIceOutcome.PairMoved -> outcome
                                is QuicOverIceOutcome.Completed ->
                                    fail(
                                        "the client's block never returns; it should have been ended by the move: $outcome",
                                    )
                                is QuicOverIceOutcome.IceFailed -> fail("ICE failed under the client: $outcome")
                            }
                        val serverMoved =
                            when (val outcome = server.await()) {
                                is QuicOverIceOutcome.PairMoved -> outcome
                                is QuicOverIceOutcome.Completed ->
                                    fail(
                                        "the server's block never returns; it should have been ended by the move: $outcome",
                                    )
                                is QuicOverIceOutcome.IceFailed -> fail("ICE failed under the server: $outcome")
                            }
                        assertEquals(riddenBefore, clientMoved.from, "the client names the pair it rode")
                        assertEquals(
                            topology.aliceHost.port + 1,
                            clientMoved.to.local.address.port
                                .toInt(),
                            "and the pair ICE moved to, on the new base",
                        )
                        assertEquals(
                            topology.bobHost.port + 1,
                            serverMoved.to.local.address.port
                                .toInt(),
                            "the server saw the same move from its side",
                        )

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
     * One self-signed P-256 leaf for both endpoints, generated per run and written to temp files because
     * quiche loads PEM by path. The dialling side pins its SHA-256 — the `a=fingerprint` shape of trust,
     * not a CA — so the handshake is verified rather than `verifyPeer = false`. Generated rather than
     * checked in because socket enforces the W3C `serverCertificateHashes` constraints on a pinned leaf
     * (validity <= 14 days, currently valid, ECDSA P-256): a committed certificate would rot in a
     * fortnight. The JDK has no public X.509 builder, so [X509Der] writes the ten-field TBSCertificate
     * itself and `SHA256withECDSA` signs it.
     */
    private class TestQuicIdentity private constructor(
        private val cert: File,
        private val key: File,
        certDer: ByteArray,
    ) {
        val endpoint =
            QuicOverIceIdentity(
                tls = QuicTlsConfig(certChainPath = cert.absolutePath, privKeyPath = key.absolutePath),
                options =
                    QuicOptions(
                        alpnProtocols = listOf(ALPN),
                        serverCertificateHashes = listOf(pinOf(certDer)),
                    ),
            )

        fun delete() {
            cert.delete()
            key.delete()
        }

        companion object {
            fun materialize(): TestQuicIdentity {
                val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
                val certDer = X509Der.selfSigned(keys, subject = "quic-over-ice", validFor = 7.days)
                return TestQuicIdentity(
                    cert = File.createTempFile("quic-over-ice", ".crt").apply { writeText(X509Der.pem("CERTIFICATE", certDer)) },
                    key =
                        File
                            .createTempFile(
                                "quic-over-ice",
                                ".key",
                            ).apply { writeText(X509Der.pem("PRIVATE KEY", keys.private.encoded)) },
                    certDer = certDer,
                )
            }

            private fun pinOf(certDer: ByteArray): CertificateHash {
                val sha256 = MessageDigest.getInstance("SHA-256").digest(certDer)
                val digest = BufferFactory.Default.allocate(sha256.size)
                for (byte in sha256) digest.writeByte(byte)
                digest.resetForRead()
                return CertificateHash(digest)
            }
        }
    }

    /** Just enough DER to mint a self-signed ECDSA P-256 X.509 v3 leaf. Test-only; arrays are fine here. */
    private object X509Der {
        private const val SEQUENCE = 0x30
        private const val SET = 0x31
        private const val INTEGER = 0x02
        private const val BIT_STRING = 0x03
        private const val OID = 0x06
        private const val UTF8_STRING = 0x0C
        private const val UTC_TIME = 0x17
        private const val EXPLICIT_0 = 0xA0
        private const val X509_V3 = 2
        private const val SERIAL_BYTES = 16
        private const val SERIAL_LEAD_MASK = 0x3F
        private const val SERIAL_LEAD_BIT = 0x40

        // ecdsa-with-SHA256 (1.2.840.10045.4.3.2) and id-at-commonName (2.5.4.3), pre-encoded.
        private val ECDSA_WITH_SHA256 = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02)
        private val COMMON_NAME = byteArrayOf(0x55, 0x04, 0x03)
        private val UTC = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC)

        fun selfSigned(
            keys: KeyPair,
            subject: String,
            validFor: kotlin.time.Duration,
        ): ByteArray {
            val now = Instant.now()
            val algorithm = seq(tlv(OID, ECDSA_WITH_SHA256))
            val name = seq(tlv(SET, seq(tlv(OID, COMMON_NAME), tlv(UTF8_STRING, subject.encodeToByteArray()))))
            val validity = seq(utcTime(now.minus(1, ChronoUnit.HOURS)), utcTime(now.plus(validFor.inWholeSeconds, ChronoUnit.SECONDS)))
            val tbs =
                seq(
                    tlv(EXPLICIT_0, tlv(INTEGER, byteArrayOf(X509_V3.toByte()))),
                    tlv(INTEGER, serial()),
                    algorithm,
                    name,
                    validity,
                    name,
                    keys.public.encoded, // already a DER SubjectPublicKeyInfo with the namedCurve OID
                )
            val signature =
                Signature
                    .getInstance("SHA256withECDSA")
                    .apply {
                        initSign(keys.private)
                        update(tbs)
                    }.sign()
            return seq(tbs, algorithm, tlv(BIT_STRING, byteArrayOf(0) + signature))
        }

        fun pem(
            label: String,
            der: ByteArray,
        ): String =
            "-----BEGIN $label-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END $label-----\n"

        // A DER INTEGER is two's-complement and minimal: BoringSSL rejects a leading zero that is not
        // needed for sign, so the first byte is pinned into 0x40..0x7F — positive, non-zero, no padding.
        private fun serial(): ByteArray =
            ByteArray(SERIAL_BYTES).also {
                SecureRandom().nextBytes(it)
                it[0] = (it[0].toInt() and SERIAL_LEAD_MASK or SERIAL_LEAD_BIT).toByte()
            }

        private fun utcTime(at: Instant): ByteArray = tlv(UTC_TIME, UTC.format(at).encodeToByteArray())

        private fun seq(vararg parts: ByteArray): ByteArray = tlv(SEQUENCE, parts.reduce { acc, part -> acc + part })

        private fun tlv(
            tag: Int,
            content: ByteArray,
        ): ByteArray = byteArrayOf(tag.toByte()) + length(content.size) + content

        private fun length(n: Int): ByteArray {
            if (n < 0x80) return byteArrayOf(n.toByte())
            val digits = ArrayList<Byte>()
            var rest = n
            while (rest > 0) {
                digits.add(0, (rest and 0xFF).toByte())
                rest = rest ushr 8
            }
            return byteArrayOf((0x80 or digits.size).toByte()) + digits.toByteArray()
        }
    }

    private companion object {
        val WATCHDOG = 60.seconds
        val DEADLINE = 10.seconds
        const val MESSAGE = "hello over the pair ICE nominated"
        const val ALPN = "quic-over-ice-echo"
        const val MAX_UTF8_BYTES_PER_CHAR = 4
    }
}
