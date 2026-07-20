package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.EcdsaSignatureEncoding
import com.ditchoom.buffer.crypto.KeyAgreementCurve
import com.ditchoom.buffer.crypto.SignatureScheme
import com.ditchoom.buffer.crypto.SignatureSupport
import com.ditchoom.buffer.crypto.VerifyKey
import com.ditchoom.buffer.crypto.ecdsaSignatureEncoding
import com.ditchoom.buffer.crypto.ecdsaSignatureToDer
import com.ditchoom.buffer.crypto.ecdsaSignatureToP1363
import com.ditchoom.buffer.crypto.signatures
import com.ditchoom.buffer.crypto.spkiToEcPublicKey
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.dtls.DtlsRole
import com.ditchoom.webrtc.dtls.DtlsState
import com.ditchoom.webrtc.dtls.DtlsStep
import com.ditchoom.webrtc.dtls.DtlsVersion
import com.ditchoom.webrtc.dtls.crypto.DerReader
import com.ditchoom.webrtc.dtls.crypto.Dtls13RecordProtection
import com.ditchoom.webrtc.dtls.crypto.EcdheKeyExchange
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.crypto.Tls13KeySchedule
import com.ditchoom.webrtc.dtls.wire.CertificateVerify
import com.ditchoom.webrtc.dtls.wire.CipherSuiteId
import com.ditchoom.webrtc.dtls.wire.ClientHello
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.Extension
import com.ditchoom.webrtc.dtls.wire.ExtensionType
import com.ditchoom.webrtc.dtls.wire.HandshakeFragment
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage
import com.ditchoom.webrtc.dtls.wire.HandshakeReassembler
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.ProtocolVersion
import com.ditchoom.webrtc.dtls.wire.ServerHello
import com.ditchoom.webrtc.dtls.wire.SignatureSchemeId
import com.ditchoom.webrtc.dtls.wire.Tls13Bodies
import com.ditchoom.webrtc.dtls.wire.u16
import com.ditchoom.webrtc.dtls.wire.u8

/**
 * The sans-io DTLS 1.3 handshake state machine for `TLS_AES_128_GCM_SHA256` (RFC 9147 over RFC 8446) —
 * the pure-Kotlin core the [com.ditchoom.webrtc.dtls.DtlsEngine] drives when 1.3 is negotiated. Caller
 * clocked (`nowMicros`), no coroutine, no wall clock. Byte-matched against the BoringSSL oracle.
 *
 * WebRTC is **mutually authenticated** (RFC 8827), so both peers send Certificate + CertificateVerify.
 * The flights (no HelloRetryRequest in the happy P-256 path; deferred to interop):
 * ```
 *   client → ClientHello                                                        (epoch 0, plaintext)
 *   server → ServerHello                                                        (epoch 0, plaintext)
 *            {EncryptedExtensions, CertificateRequest, Certificate,
 *             CertificateVerify, Finished}                                      (epoch 2, handshake keys)
 *   client → {Certificate, CertificateVerify, Finished}                         (epoch 2, handshake keys)
 * ```
 * `{}` = protected under the DTLS 1.3 unified-header record layer ([Dtls13RecordProtection]). Application
 * data flows at epoch 3 (application traffic keys). There is no ChangeCipherSpec in DTLS 1.3; inbound ACK
 * records (RFC 9147 §7) are decrypted and ignored — the lossless caller-clocked path never needs them.
 */
internal class Dtls13Handshake(
    private val config: DtlsConfig,
    private val role: DtlsRole,
    private val certificate: SelfSignedCertificate,
) : DtlsHandshakeFsm {
    private val factory: BufferFactory = config.bufferFactory
    private val random = config.random
    private val schedule = Tls13KeySchedule(factory)
    private val reassembler = HandshakeReassembler(factory)
    private val transcript = TranscriptHash(factory, dtls13 = true)
    private val ecdhe: EcdheKeyExchange = EcdheKeyExchange.generate()

    private lateinit var localRandom: ReadBuffer
    private var peerCertDer: ReadBuffer? = null
    private var peerPoint: ReadBuffer? = null

    // Secret schedule material.
    private var handshakeSecret: ReadBuffer? = null
    private var masterSecret: ReadBuffer? = null
    private var clientHsSecret: ReadBuffer? = null
    private var serverHsSecret: ReadBuffer? = null
    private var handshakeProtection: Dtls13RecordProtection? = null
    private var appProtection: Dtls13RecordProtection? = null

    // Record send state: monotonic per epoch. Epoch 0 = plaintext, 2 = handshake keys, 3 = app keys.
    private var epoch0Seq = 0L
    private var epoch2Seq = 0L
    private var epoch3Seq = 0L
    private var appSecretsReady = false

    private var sendMsgSeq = 0
    private var started = false
    private var terminal: DtlsState? = null

    // Retransmission (RFC 9147 §5.8): the last flight + a backoff timer.
    private var lastFlight: List<FlightItem>? = null
    private var retransmitDeadline: Long? = null
    private var retransmitBackoffMicros = INITIAL_RETRANSMIT_MICROS

    private class FlightItem(
        val realContentType: Int,
        val payload: ReadBuffer,
        val epoch: Int,
    )

    // ── sans-io surface ──────────────────────────────────────────────────────────────────────────

    override fun start(nowMicros: Long): DtlsStep {
        check(!started) { "start() called twice" }
        started = true
        localRandom = randomBytes(RANDOM_BYTES)
        if (role == DtlsRole.Client) {
            val out = mutableListOf<ReadBuffer>()
            sendClientHelloFlight(out, nowMicros)
            return step(out, emptyList())
        }
        return step(emptyList(), emptyList()) // server waits for ClientHello
    }

    override fun onDatagram(
        datagram: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep {
        (terminal as? DtlsState.Failed)?.let { return DtlsStep(emptyList(), emptyList(), it) }
        (terminal as? DtlsState.Closed)?.let { return DtlsStep(emptyList(), emptyList(), it) }
        val out = mutableListOf<ReadBuffer>()
        val appData = mutableListOf<ReadBuffer>()
        walkRecords(datagram, out, appData, nowMicros)
        terminal?.let { return DtlsStep(out, appData, it) }
        return DtlsStep(out, appData, stateNow())
    }

    override fun onTimeout(nowMicros: Long): DtlsStep {
        terminal?.let { return DtlsStep(emptyList(), emptyList(), it) }
        val deadline = retransmitDeadline ?: return step(emptyList(), emptyList())
        if (nowMicros < deadline) return step(emptyList(), emptyList())
        val flight = lastFlight ?: return step(emptyList(), emptyList())
        val out = flight.map { emit(it) }.toMutableList()
        retransmitBackoffMicros = minOf(retransmitBackoffMicros * 2, MAX_RETRANSMIT_MICROS)
        retransmitDeadline = nowMicros + retransmitBackoffMicros
        return step(out, emptyList())
    }

    override fun sealApplicationData(
        applicationData: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep {
        val prot = appProtection
        if (terminal !is DtlsState.Established || prot == null) {
            return DtlsStep(emptyList(), emptyList(), terminal ?: DtlsState.Handshaking)
        }
        val record = prot.seal(applicationData, ContentType.ApplicationData.value, EPOCH_APP, epoch3Seq++)
        return DtlsStep(listOf(record), emptyList(), terminal!!)
    }

    override fun beginClose(nowMicros: Long): DtlsStep {
        if (terminal is DtlsState.Closed) return DtlsStep(emptyList(), emptyList(), DtlsState.Closed)
        val out = mutableListOf<ReadBuffer>()
        val prot = appProtection
        if (prot != null && terminal is DtlsState.Established) {
            val alert =
                buildBody {
                    it.writeByte(1) // warning
                    it.writeByte(0) // close_notify
                }
            out += prot.seal(alert, ContentType.Alert.value, EPOCH_APP, epoch3Seq++)
        }
        cancelRetransmit()
        terminal = DtlsState.Closed
        return DtlsStep(out, emptyList(), DtlsState.Closed)
    }

    override fun nextTimeoutMicros(nowMicros: Long): Long? = if (terminal != null) null else retransmitDeadline

    override fun close() {
        ecdhe.close()
        handshakeProtection?.close()
        appProtection?.close()
    }

    // ── inbound record demux (mixed plaintext epoch-0 + unified-header epoch-2/3 in one datagram) ──

    private fun walkRecords(
        datagram: ReadBuffer,
        out: MutableList<ReadBuffer>,
        appData: MutableList<ReadBuffer>,
        now: Long,
    ) {
        val start = datagram.position()
        val end = datagram.limit()
        var pos = start
        while (pos < end) {
            val firstByte = datagram.u8(pos)
            if (Dtls13RecordProtection.isUnifiedHeader(firstByte)) {
                if (pos + Dtls13RecordProtection.HEADER_BYTES > end) return // truncated header — drop tail
                val len = datagram.u16(pos + 3)
                val recordEnd = pos + Dtls13RecordProtection.HEADER_BYTES + len
                if (recordEnd > end) return
                val epochBits = firstByte and 0x3
                val prot = if (epochBits == (EPOCH_APP and 0x3)) appProtection else handshakeProtection
                prot?.open(datagram, pos, recordEnd)?.let { opened ->
                    dispatchDecrypted(opened, out, appData, now)
                }
                pos = recordEnd
            } else {
                if (pos + DtlsRecord.HEADER_BYTES > end) return
                val len = datagram.u16(pos + DTLS_LENGTH_OFFSET)
                val bodyStart = pos + DtlsRecord.HEADER_BYTES
                val bodyEnd = bodyStart + len
                if (bodyEnd > end) return
                if (firstByte == ContentType.Handshake.value) {
                    processHandshakeBytes(datagram.let { sliceOf(it, bodyStart, bodyEnd) }, out, now)
                }
                // ChangeCipherSpec / Alert / ACK in cleartext are ignored (DTLS 1.3 sends none of these plaintext).
                pos = bodyEnd
            }
            if (terminal != null) return
        }
    }

    private fun dispatchDecrypted(
        opened: Dtls13RecordProtection.Opened,
        out: MutableList<ReadBuffer>,
        appData: MutableList<ReadBuffer>,
        now: Long,
    ) {
        when (opened.contentType) {
            ContentType.Handshake.value -> processHandshakeBytes(opened.content, out, now)
            ContentType.ApplicationData.value -> appData += opened.content
            ContentType.Alert.value -> fail(DtlsFailureReason.HandshakeFailure)
            ACK_CONTENT_TYPE -> Unit // RFC 9147 §7 ACK — nothing to do on a lossless caller-clocked path
            else -> Unit
        }
    }

    private fun processHandshakeBytes(
        handshakeBytes: ReadBuffer,
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        val fragments = HandshakeFragment.decodeAll(handshakeBytes) ?: return
        for (fragment in fragments) {
            for (message in reassembler.offer(fragment)) {
                cancelRetransmit()
                when (role) {
                    DtlsRole.Client -> handleAsClient(message, out, now)
                    DtlsRole.Server -> handleAsServer(message, out, now)
                }
                if (terminal != null) return
            }
        }
    }

    // ── client role ────────────────────────────────────────────────────────────────────────────

    private fun handleAsClient(
        message: HandshakeMessage,
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        when (message.msgType.value) {
            HandshakeType.ServerHello.value -> {
                val sh = ServerHello.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                if (sh.cipherSuite.value != CipherSuiteId.TlsAes128GcmSha256.value) return fail(DtlsFailureReason.HandshakeFailure)
                val versionExt = sh.extensions.firstOrNull { it.type.value == ExtensionType.SupportedVersions.value }
                if (versionExt == null || Tls13Bodies.selectedVersion(versionExt.body) != ProtocolVersion.Dtls13.value) {
                    return fail(DtlsFailureReason.HandshakeFailure)
                }
                val ksExt =
                    sh.extensions.firstOrNull { it.type.value == ExtensionType.KeyShare.value }
                        ?: return fail(DtlsFailureReason.HandshakeFailure)
                peerPoint = Tls13Bodies.parseKeyShareServerHello(ksExt.body)?.let { copyOf(it) }
                    ?: return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
                deriveHandshakeSecrets(client = true)
            }
            HandshakeType.EncryptedExtensions.value -> transcript.append(message)
            HandshakeType.CertificateRequest.value -> transcript.append(message) // mutual auth — we answer with our cert
            HandshakeType.Certificate.value -> {
                peerCertDer = Tls13Bodies.parseCertificate13(message.body)?.let { copyOf(it) }
                    ?: return fail(DtlsFailureReason.PeerCertificateMissing)
                transcript.append(message)
            }
            HandshakeType.CertificateVerify.value -> {
                if (!verifyPeerCertificateVerify(message, SERVER_CONTEXT)) return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
            }
            HandshakeType.Finished.value -> {
                if (!verifyPeerFinished(message, serverHsSecret!!)) return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
                deriveApplicationSecrets() // over CH…server Finished (excludes our own flight)
                sendClientAuthFlight(out, now)
                establish()
            }
            else -> Unit
        }
    }

    private fun sendClientHelloFlight(
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        val extensions =
            listOf(
                supportedGroupsExtension(),
                signatureAlgorithmsExtension(),
                Tls13Bodies.supportedVersionsClientHello(factory),
                Tls13Bodies.keyShareClientHello(ecdhe.localPublicPoint, factory),
            )
        val ch =
            buildBody {
                ClientHello(
                    ProtocolVersion.Dtls12, // legacy_version; the real version is in supported_versions
                    localRandom,
                    empty(),
                    empty(), // no cookie
                    listOf(CipherSuiteId.TlsAes128GcmSha256),
                    extensions,
                ).bodyInto(it)
            }
        emitFlight(listOf(queueHandshake(HandshakeType.ClientHello, ch, EPOCH_0)), out, now)
    }

    private fun sendClientAuthFlight(
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        val flight = mutableListOf<FlightItem>()
        val certBody = buildBody { Tls13Bodies.certificate13Body(certificate.derEncoded, it) }
        flight += queueHandshake(HandshakeType.Certificate, certBody, EPOCH_HANDSHAKE)
        flight += buildCertificateVerify(CLIENT_CONTEXT)
        flight += buildFinished(clientHsSecret!!)
        emitFlight(flight, out, now)
    }

    // ── server role ────────────────────────────────────────────────────────────────────────────

    private fun handleAsServer(
        message: HandshakeMessage,
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        when (message.msgType.value) {
            HandshakeType.ClientHello.value -> {
                val ch = ClientHello.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                if (ch.cipherSuites.none { it.value == CipherSuiteId.TlsAes128GcmSha256.value }) {
                    return fail(
                        DtlsFailureReason.HandshakeFailure,
                    )
                }
                val ksExt =
                    ch.extensions.firstOrNull { it.type.value == ExtensionType.KeyShare.value }
                        ?: return fail(DtlsFailureReason.HandshakeFailure)
                peerPoint = Tls13Bodies.parseKeyShareClientHello(ksExt.body)?.let { copyOf(it) }
                    ?: return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
                sendServerFlight(out, now)
            }
            HandshakeType.Certificate.value -> {
                peerCertDer = Tls13Bodies.parseCertificate13(message.body)?.let { copyOf(it) }
                    ?: return fail(DtlsFailureReason.PeerCertificateMissing)
                transcript.append(message)
            }
            HandshakeType.CertificateVerify.value -> {
                if (!verifyPeerCertificateVerify(message, CLIENT_CONTEXT)) return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
            }
            HandshakeType.Finished.value -> {
                if (!verifyPeerFinished(message, clientHsSecret!!)) return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
                establish()
            }
            else -> Unit
        }
    }

    private fun sendServerFlight(
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        // ServerHello is plaintext (epoch 0); it triggers the handshake keys.
        val sh =
            buildBody {
                ServerHello(
                    ProtocolVersion.Dtls12,
                    localRandom,
                    empty(),
                    CipherSuiteId.TlsAes128GcmSha256,
                    listOf(
                        Tls13Bodies.supportedVersionsServerHello(factory),
                        Tls13Bodies.keyShareServerHello(ecdhe.localPublicPoint, factory),
                    ),
                ).bodyInto(it)
            }
        val flight = mutableListOf<FlightItem>()
        flight += queueHandshake(HandshakeType.ServerHello, sh, EPOCH_0)
        deriveHandshakeSecrets(client = false)
        // The rest of the flight is protected under the handshake traffic keys (epoch 2).
        flight += queueHandshake(HandshakeType.EncryptedExtensions, Tls13Bodies.encryptedExtensionsEmpty(factory), EPOCH_HANDSHAKE)
        flight += queueHandshake(HandshakeType.CertificateRequest, Tls13Bodies.certificateRequest13Body(factory), EPOCH_HANDSHAKE)
        val certBody = buildBody { Tls13Bodies.certificate13Body(certificate.derEncoded, it) }
        flight += queueHandshake(HandshakeType.Certificate, certBody, EPOCH_HANDSHAKE)
        flight += buildCertificateVerify(SERVER_CONTEXT)
        flight += buildFinished(serverHsSecret!!)
        deriveApplicationSecrets() // over CH…server Finished
        emitFlight(flight, out, now)
    }

    // ── key schedule ─────────────────────────────────────────────────────────────────────────────

    private fun deriveHandshakeSecrets(client: Boolean) {
        val ecdheSecret = ecdhe.premasterSecret(peerPoint!!)
        val hs =
            try {
                val early = schedule.earlySecret()
                schedule.handshakeSecret(early, ecdheSecret)
            } finally {
                ecdheSecret.freeNativeMemory()
            }
        handshakeSecret = hs
        val thChSh = transcript.currentSha256()
        val cHs = schedule.deriveSecret(hs, Tls13KeySchedule.CLIENT_HANDSHAKE_LABEL, thChSh)
        val sHs = schedule.deriveSecret(hs, Tls13KeySchedule.SERVER_HANDSHAKE_LABEL, thChSh)
        clientHsSecret = cHs
        serverHsSecret = sHs
        masterSecret = schedule.masterSecret(hs)
        val local = if (client) cHs else sHs
        val peer = if (client) sHs else cHs
        handshakeProtection = Dtls13RecordProtection.fromTrafficSecrets(schedule, local, peer, factory)
    }

    private fun deriveApplicationSecrets() {
        if (appSecretsReady) return
        val master = masterSecret!!
        val thChSFin = transcript.currentSha256()
        val cAp = schedule.deriveSecret(master, Tls13KeySchedule.CLIENT_APPLICATION_LABEL, thChSFin)
        val sAp = schedule.deriveSecret(master, Tls13KeySchedule.SERVER_APPLICATION_LABEL, thChSFin)
        val client = role == DtlsRole.Client
        val local = if (client) cAp else sAp
        val peer = if (client) sAp else cAp
        appProtection = Dtls13RecordProtection.fromTrafficSecrets(schedule, local, peer, factory)
        appSecretsReady = true
    }

    private fun buildFinished(baseSecret: ReadBuffer): FlightItem {
        val verifyData = schedule.verifyData(baseSecret, transcript.currentSha256())
        return queueHandshake(HandshakeType.Finished, verifyData, EPOCH_HANDSHAKE)
    }

    private fun verifyPeerFinished(
        message: HandshakeMessage,
        baseSecret: ReadBuffer,
    ): Boolean {
        if (message.length != Tls13KeySchedule.HASH_LEN) return false
        val expected = schedule.verifyData(baseSecret, transcript.currentSha256())
        return constantTimeEquals(expected, message.body)
    }

    // ── CertificateVerify (RFC 8446 §4.4.3) ───────────────────────────────────────────────────────

    private fun buildCertificateVerify(context: String): FlightItem {
        val input = certVerifyInput(context, transcript.currentSha256())
        val raw = signatures().ops.signBlocking(certificate.signingKey, input)
        val derSig = if (ecdsaSignatureEncoding == EcdsaSignatureEncoding.Der) raw else ecdsaSignatureToDer(SignatureScheme.EcdsaP256, raw)
        val body = buildBody { CertificateVerify(SignatureSchemeId.EcdsaSecp256r1Sha256, derSig).bodyInto(it) }
        return queueHandshake(HandshakeType.CertificateVerify, body, EPOCH_HANDSHAKE)
    }

    private fun verifyPeerCertificateVerify(
        message: HandshakeMessage,
        context: String,
    ): Boolean {
        val cv = CertificateVerify.parse(message.body) ?: return false
        val verifyKey = verifyKeyFromCert(peerCertDer ?: return false) ?: return false
        // The signature covers the transcript up to (not including) this CertificateVerify — the current hash.
        val input = certVerifyInput(context, transcript.currentSha256())
        return verifyWireSignature(verifyKey, input, cv.signature)
    }

    /** `64×0x20 ‖ context ‖ 0x00 ‖ transcriptHash` — the CertificateVerify signed content (RFC 8446 §4.4.3). */
    private fun certVerifyInput(
        context: String,
        transcriptHash: ReadBuffer,
    ): ReadBuffer {
        val out = factory.allocate(64 + context.length + 1 + transcriptHash.remaining(), ByteOrder.BIG_ENDIAN)
        repeat(64) { out.writeByte(0x20) }
        for (ch in context) out.writeByte(ch.code.toByte())
        out.writeByte(0) // NUL separator
        writeView(out, transcriptHash)
        out.resetForRead()
        return out
    }

    // ── flight assembly + record emission ─────────────────────────────────────────────────────────

    private fun queueHandshake(
        msgType: HandshakeType,
        body: ReadBuffer,
        epoch: Int,
    ): FlightItem {
        val message = HandshakeMessage(msgType, sendMsgSeq++, body)
        transcript.append(message)
        val wire = factory.allocate(message.wireSize, ByteOrder.BIG_ENDIAN)
        message.encodeInto(wire)
        wire.resetForRead()
        return FlightItem(ContentType.Handshake.value, wire, epoch)
    }

    private fun emitFlight(
        flight: List<FlightItem>,
        out: MutableList<ReadBuffer>,
        now: Long,
    ) {
        for (item in flight) out += emit(item)
        lastFlight = flight
        retransmitBackoffMicros = INITIAL_RETRANSMIT_MICROS
        retransmitDeadline = now + retransmitBackoffMicros
    }

    private fun emit(item: FlightItem): ReadBuffer =
        when (item.epoch) {
            EPOCH_0 -> {
                val seq = epoch0Seq++
                encode(DtlsRecord(ContentType(item.realContentType), ProtocolVersion.Dtls12, EPOCH_0, seq, item.payload))
            }
            EPOCH_APP -> appProtection!!.seal(item.payload, item.realContentType, EPOCH_APP, epoch3Seq++)
            else -> handshakeProtection!!.seal(item.payload, item.realContentType, EPOCH_HANDSHAKE, epoch2Seq++)
        }

    // ── ECDSA sign / verify over a peer certificate ───────────────────────────────────────────────

    private fun verifyKeyFromCert(certDer: ReadBuffer): VerifyKey? {
        val spki = DerReader.extractSpki(certDer, factory) ?: return null
        val point =
            try {
                spkiToEcPublicKey(KeyAgreementCurve.P256, spki, factory)
            } catch (_: Throwable) {
                return null
            }
        return VerifyKey.ecdsaP256(point)
    }

    private fun verifyWireSignature(
        verifyKey: VerifyKey,
        message: ReadBuffer,
        wireSignature: ReadBuffer,
    ): Boolean {
        val sig =
            if (ecdsaSignatureEncoding == EcdsaSignatureEncoding.Der) {
                wireSignature
            } else {
                ecdsaSignatureToP1363(SignatureScheme.EcdsaP256, wireSignature, factory)
            }
        return try {
            signatures().ops.verifyBlocking(verifyKey, message, sig)
        } catch (_: Throwable) {
            false
        }
    }

    private fun signatures(): SignatureSupport.Blocking {
        val support = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256)
        check(support is SignatureSupport.Blocking) { "ECDSA-P256 blocking signatures unavailable on this target" }
        return support
    }

    // ── terminal transitions ──────────────────────────────────────────────────────────────────────

    private fun establish() {
        cancelRetransmit()
        val fp = peerCertDer?.let { SelfSignedCertificate.fingerprintOf(it, factory) }
        if (fp == null) {
            terminal = DtlsState.Failed(DtlsFailureReason.PeerCertificateMissing)
            return
        }
        terminal = DtlsState.Established(fp, DtlsVersion.Dtls13)
    }

    private fun fail(reason: DtlsFailureReason) {
        cancelRetransmit()
        terminal = DtlsState.Failed(reason)
    }

    private fun stateNow(): DtlsState = terminal ?: DtlsState.Handshaking

    private fun step(
        records: List<ReadBuffer>,
        appData: List<ReadBuffer>,
    ): DtlsStep = DtlsStep(records, appData, stateNow())

    private fun cancelRetransmit() {
        retransmitDeadline = null
    }

    // ── extension builders (shared shape with the 1.2 FSM) ─────────────────────────────────────────

    private fun supportedGroupsExtension(): Extension {
        val body = factory.allocate(4, ByteOrder.BIG_ENDIAN)
        body.writeShort(2)
        body.writeShort(
            com.ditchoom.webrtc.dtls.wire.NamedGroup.Secp256r1.value
                .toShort(),
        )
        body.resetForRead()
        return Extension(ExtensionType.SupportedGroups, body)
    }

    private fun signatureAlgorithmsExtension(): Extension {
        val body = factory.allocate(4, ByteOrder.BIG_ENDIAN)
        body.writeShort(2)
        body.writeShort(SignatureSchemeId.EcdsaSecp256r1Sha256.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.SignatureAlgorithms, body)
    }

    // ── small buffer helpers ───────────────────────────────────────────────────────────────────────

    private inline fun buildBody(block: (WriteBuffer) -> Unit): ReadBuffer {
        val b = factory.allocate(MAX_MESSAGE_BYTES, ByteOrder.BIG_ENDIAN)
        block(b)
        b.resetForRead()
        return b
    }

    private fun randomBytes(n: Int): ReadBuffer {
        val b = factory.allocate(n, ByteOrder.BIG_ENDIAN)
        var i = 0
        while (i < n) {
            val r = random.nextInt()
            var shift = 24
            while (i < n && shift >= 0) {
                b.writeByte(((r ushr shift) and 0xFF).toByte())
                i++
                shift -= 8
            }
        }
        b.resetForRead()
        return b
    }

    private fun empty(): ReadBuffer {
        val b = factory.allocate(1, ByteOrder.BIG_ENDIAN)
        b.resetForRead()
        b.setLimit(0)
        return b
    }

    private fun copyOf(src: ReadBuffer): ReadBuffer {
        val p = src.position()
        val out = factory.allocate(maxOf(src.remaining(), 1), ByteOrder.BIG_ENDIAN)
        out.write(src)
        src.position(p)
        out.resetForRead()
        return out
    }

    private fun encode(record: DtlsRecord): ReadBuffer {
        val b = factory.allocate(record.wireSize, ByteOrder.BIG_ENDIAN)
        record.encodeInto(b)
        b.resetForRead()
        return b
    }

    private fun writeView(
        dest: WriteBuffer,
        view: ReadBuffer,
    ) {
        val p = view.position()
        dest.write(view)
        view.position(p)
    }

    private fun sliceOf(
        buf: ReadBuffer,
        start: Int,
        endExclusive: Int,
    ): ReadBuffer {
        val savedPos = buf.position()
        val savedLimit = buf.limit()
        buf.position(0)
        buf.setLimit(endExclusive)
        buf.position(start)
        val view = buf.slice(ByteOrder.BIG_ENDIAN)
        buf.position(0)
        buf.setLimit(savedLimit)
        buf.position(savedPos)
        return view
    }

    private fun constantTimeEquals(
        a: ReadBuffer,
        b: ReadBuffer,
    ): Boolean {
        if (a.remaining() != b.remaining()) return false
        val pa = a.position()
        val pb = b.position()
        var diff = 0
        while (a.remaining() > 0) diff = diff or (a.readByte().toInt() xor b.readByte().toInt())
        a.position(pa)
        b.position(pb)
        return diff == 0
    }

    private companion object {
        const val RANDOM_BYTES = 32
        const val EPOCH_0 = 0
        const val EPOCH_HANDSHAKE = 2
        const val EPOCH_APP = 3
        const val ACK_CONTENT_TYPE = 26 // RFC 9147 §7
        const val DTLS_LENGTH_OFFSET = 11 // uint16 length in the 13-byte plaintext record header
        const val MAX_MESSAGE_BYTES = 4096
        const val INITIAL_RETRANSMIT_MICROS = 1_000_000L
        const val MAX_RETRANSMIT_MICROS = 60_000_000L
        const val SERVER_CONTEXT = "TLS 1.3, server CertificateVerify"
        const val CLIENT_CONTEXT = "TLS 1.3, client CertificateVerify"
    }
}
