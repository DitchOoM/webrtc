@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.DtlsState
import com.ditchoom.webrtc.dtls.KeyExchangeGroup
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import com.ditchoom.webrtc.dtls.wire.CipherSuiteId
import com.ditchoom.webrtc.dtls.wire.ClientHello
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.NamedGroup
import com.ditchoom.webrtc.dtls.wire.ProtocolVersion
import com.ditchoom.webrtc.dtls.wire.ServerHello
import com.ditchoom.webrtc.dtls.wire.Tls13Bodies
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The DTLS 1.3 **HelloRetryRequest reject paths** (RFC 8446 §4.1.4). The happy P-256↔X25519 retry lives in
 * [Dtls13HelloRetryRequestTest]; PR #32 also added several MUST-reject branches that shipped untested. A
 * conforming peer never drives them, so each is exercised by feeding a real client/server a hand-crafted
 * **adversarial** handshake message and asserting the typed fatal outcome ([DtlsState.Failed] with
 * [DtlsFailureReason.HandshakeFailure]) — never a hang, never a throw-through (T0). The adversarial
 * messages are assembled with the same wire codec production uses ([Tls13Bodies]/[ServerHello]/[ClientHello]),
 * so the framing is real; only the *semantics* are hostile.
 *
 * All state machines are sans-io and caller-clocked: a reject is produced synchronously inside one
 * `onDatagram`, so these run at zero wall-clock. The watchdog per case is the observable terminal itself —
 * a [DtlsState.Failed] that arms no further timer ([nextDeadline] == null), proving the endpoint neither
 * spins nor waits after rejecting.
 *
 * Branches covered (all verified LIVE in [Dtls13Handshake] but previously uncovered):
 *  - **client:** a *second* HelloRetryRequest (message_seq 1) is fatal ("client MUST abort if it receives a
 *    second HelloRetryRequest", RFC 8446 §4.1.4). The reassembler only dedups retransmits, so a malicious
 *    server can genuinely deliver a distinct second HRR.
 *  - **client:** an HRR requesting a group we ALREADY key-shared is fatal (a HRR for a group we offered a
 *    key_share for is a protocol error, RFC 8446 §4.1.4).
 *  - **client:** an HRR requesting a group we did NOT offer (an unsupported group) is rejected.
 *  - **server:** a second ClientHello that key-shares a group ≠ the one our HRR demanded is fatal.
 */
class Dtls13HelloRetryRejectTest {
    private val now: Instant = Instant.fromEpochSeconds(0)

    // A dedicated factory for assembling the adversarial datagrams (kept apart from the endpoints' own).
    private val craft: BufferFactory = BufferFactory.managed()
    private var craftRecordSeq = 0L

    private fun clientConfig(preferred: KeyExchangeGroup) =
        DtlsConfig(bufferFactory = BufferFactory.managed(), keyExchangeGroup = preferred, random = Random(101))

    private fun serverConfig(preferred: KeyExchangeGroup) =
        DtlsConfig(bufferFactory = BufferFactory.managed(), keyExchangeGroup = preferred, random = Random(202))

    private fun cert(seed: Int) = SelfSignedCertificate.generate(BufferFactory.managed(), Random(seed))

    // ── client reject paths ────────────────────────────────────────────────────────────────────────

    @Test
    fun a_second_hello_retry_request_is_fatal() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val clientCert = cert(31)
        // Client prefers (key-shares) P-256; it offers X25519 too, so a first HRR for X25519 is legitimate.
        val client = Dtls13Handshake(clientConfig(KeyExchangeGroup.Secp256r1), DtlsRole.Client, clientCert)
        try {
            client.start(now) // emits ClientHello1 (key_share P-256); we discard the records
            // A valid first HRR for X25519 (offered, not key-shared): the client adopts X25519 and retries.
            val afterFirst =
                client.onDatagram(helloRetryRequest(NamedGroup.X25519, messageSeq = 0), now)
            assertIs<DtlsState.Handshaking>(afterFirst.state, "first HRR is honoured, client retries")
            assertTrue(afterFirst.records.isNotEmpty(), "client emits ClientHello2 after the first HRR")
            // A SECOND HRR (message_seq 1) — requesting P-256, which after the retry would otherwise be a
            // legal retry group (offered, ≠ the now-key-shared X25519). The ONLY thing that fails it is the
            // second-HRR guard, so this isolates that branch (RFC 8446 §4.1.4: MUST abort on a second HRR).
            val afterSecond =
                client.onDatagram(helloRetryRequest(NamedGroup.Secp256r1, messageSeq = 1), now)
            val failed = assertIs<DtlsState.Failed>(afterSecond.state, "a second HRR must be fatal")
            assertEquals(DtlsFailureReason.HandshakeFailure, failed.reason)
            assertNull(client.nextDeadline(now), "a rejected endpoint arms no retransmit timer")
        } finally {
            client.close()
            clientCert.close()
        }
    }

    @Test
    fun an_hrr_for_the_already_key_shared_group_is_fatal() {
        if (!engineCryptoAvailable()) return
        val clientCert = cert(32)
        // Client prefers (key-shares) P-256; an HRR asking for P-256 asks for the group we already shared.
        val client = Dtls13Handshake(clientConfig(KeyExchangeGroup.Secp256r1), DtlsRole.Client, clientCert)
        try {
            client.start(now)
            val after =
                client.onDatagram(helloRetryRequest(NamedGroup.Secp256r1, messageSeq = 0), now)
            val failed = assertIs<DtlsState.Failed>(after.state, "an HRR for our key-shared group is fatal")
            assertEquals(DtlsFailureReason.HandshakeFailure, failed.reason)
            assertNull(client.nextDeadline(now))
        } finally {
            client.close()
            clientCert.close()
        }
    }

    @Test
    fun an_hrr_for_a_group_we_did_not_offer_is_rejected() {
        if (!engineCryptoAvailable()) return
        val clientCert = cert(33)
        // Client offers X25519 + P-256 only. An HRR naming secp384r1 (0x0018) asks for a group we never
        // advertised (and do not support) — it maps to no KeyExchangeGroup, so it is rejected.
        val client = Dtls13Handshake(clientConfig(KeyExchangeGroup.Secp256r1), DtlsRole.Client, clientCert)
        try {
            client.start(now)
            val after =
                client.onDatagram(helloRetryRequest(SECP384R1, messageSeq = 0), now)
            val failed = assertIs<DtlsState.Failed>(after.state, "an HRR for an un-offered group is rejected")
            assertEquals(DtlsFailureReason.HandshakeFailure, failed.reason)
            assertNull(client.nextDeadline(now))
        } finally {
            client.close()
            clientCert.close()
        }
    }

    // ── server reject path ─────────────────────────────────────────────────────────────────────────

    @Test
    fun a_second_client_hello_with_the_wrong_group_is_fatal() {
        if (!engineCryptoAvailable()) return
        val serverCert = cert(34)
        // Server prefers X25519. A ClientHello that key-shares P-256 (but offers X25519) makes the server
        // answer with an HRR demanding X25519 — then a second ClientHello that key-shares P-256 again
        // (≠ the demanded X25519) must be fatal (server-side reject).
        val server = Dtls13Handshake(serverConfig(KeyExchangeGroup.X25519), DtlsRole.Server, serverCert)
        try {
            server.start(now) // the server waits for a ClientHello
            val afterCh1 =
                server.onDatagram(
                    clientHello(
                        keyShareGroup = NamedGroup.Secp256r1,
                        offeredGroups = listOf(NamedGroup.Secp256r1, NamedGroup.X25519),
                        messageSeq = 0,
                    ),
                    now,
                )
            assertIs<DtlsState.Handshaking>(afterCh1.state, "the server sends an HRR, not a terminal")
            assertTrue(afterCh1.records.isNotEmpty(), "the server emits a HelloRetryRequest")
            // ClientHello2 key-shares P-256 again — but the server demanded X25519. Fatal.
            val afterCh2 =
                server.onDatagram(
                    clientHello(
                        keyShareGroup = NamedGroup.Secp256r1,
                        offeredGroups = listOf(NamedGroup.Secp256r1, NamedGroup.X25519),
                        messageSeq = 1,
                    ),
                    now,
                )
            val failed = assertIs<DtlsState.Failed>(afterCh2.state, "a CH2 with the wrong key_share is fatal")
            assertEquals(DtlsFailureReason.HandshakeFailure, failed.reason)
            assertNull(server.nextDeadline(now), "a rejected endpoint arms no retransmit timer")
        } finally {
            server.close()
            serverCert.close()
        }
    }

    // ── adversarial-message assembly (production wire codec, hostile semantics) ───────────────────────

    /** A plaintext epoch-0 datagram carrying a HelloRetryRequest (a ServerHello with the HRR sentinel random). */
    private fun helloRetryRequest(
        requestedGroup: NamedGroup,
        messageSeq: Int,
    ): ReadBuffer {
        val body =
            buildBody {
                ServerHello(
                    ProtocolVersion.Dtls12,
                    Tls13Bodies.helloRetryRandom(craft),
                    emptyBuf(),
                    CipherSuiteId.TlsAes128GcmSha256,
                    listOf(
                        Tls13Bodies.supportedVersionsServerHello(craft),
                        Tls13Bodies.keyShareHelloRetryRequest(requestedGroup, craft),
                    ),
                ).bodyInto(it)
            }
        return handshakeDatagram(HandshakeType.ServerHello, messageSeq, body)
    }

    /** A plaintext epoch-0 datagram carrying a ClientHello with a key_share for [keyShareGroup]. */
    private fun clientHello(
        keyShareGroup: NamedGroup,
        offeredGroups: List<NamedGroup>,
        messageSeq: Int,
    ): ReadBuffer {
        val body =
            buildBody {
                ClientHello(
                    ProtocolVersion.Dtls12,
                    random32(),
                    emptyBuf(),
                    emptyBuf(),
                    listOf(CipherSuiteId.TlsAes128GcmSha256),
                    listOf(
                        Tls13Bodies.supportedGroupsClientHello(offeredGroups, craft),
                        Tls13Bodies.supportedVersionsClientHello(craft),
                        // The point is never inspected before the group is rejected; a placeholder suffices.
                        Tls13Bodies.keyShareClientHello(keyShareGroup, placeholderPoint(), craft),
                    ),
                ).bodyInto(it)
            }
        return handshakeDatagram(HandshakeType.ClientHello, messageSeq, body)
    }

    /** Frames [body] as one unfragmented handshake message inside a plaintext (epoch-0) DTLS record. */
    private fun handshakeDatagram(
        msgType: HandshakeType,
        messageSeq: Int,
        body: ReadBuffer,
    ): ReadBuffer {
        val msg = HandshakeMessage(msgType, messageSeq, body)
        val wire = craft.allocate(msg.wireSize, ByteOrder.BIG_ENDIAN)
        msg.encodeInto(wire)
        wire.resetForRead()
        val record = DtlsRecord(ContentType.Handshake, ProtocolVersion.Dtls12, 0, craftRecordSeq++, wire)
        val out = craft.allocate(record.wireSize, ByteOrder.BIG_ENDIAN)
        record.encodeInto(out)
        out.resetForRead()
        return out
    }

    private fun buildBody(block: (WriteBuffer) -> Unit): ReadBuffer {
        val b = craft.allocate(512, ByteOrder.BIG_ENDIAN)
        block(b)
        b.resetForRead()
        return b
    }

    private fun emptyBuf(): ReadBuffer {
        val b = craft.allocate(1, ByteOrder.BIG_ENDIAN)
        b.resetForRead()
        b.setLimit(0)
        return b
    }

    private fun random32(): ReadBuffer {
        val b = craft.allocate(32, ByteOrder.BIG_ENDIAN)
        repeat(32) { b.writeByte(it.toByte()) }
        b.resetForRead()
        return b
    }

    /** A syntactically-well-formed but never-inspected ephemeral point (rejects fire before it is used). */
    private fun placeholderPoint(): ReadBuffer {
        val b = craft.allocate(32, ByteOrder.BIG_ENDIAN)
        repeat(32) { b.writeByte(0) }
        b.resetForRead()
        return b
    }

    private companion object {
        // secp384r1 (RFC 8446 §4.2.7 code point 0x0018) — a group this stack neither offers nor supports.
        val SECP384R1 = NamedGroup(0x0018)
    }
}
