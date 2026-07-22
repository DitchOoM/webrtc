@file:OptIn(ExperimentalTime::class)

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
import com.ditchoom.webrtc.dtls.crypto.Dtls12RecordProtection
import com.ditchoom.webrtc.dtls.crypto.EcdheKeyExchange
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.crypto.Tls12KeySchedule
import com.ditchoom.webrtc.dtls.wire.CertificateMessage
import com.ditchoom.webrtc.dtls.wire.CertificateVerify
import com.ditchoom.webrtc.dtls.wire.CipherSuiteId
import com.ditchoom.webrtc.dtls.wire.ClientHello
import com.ditchoom.webrtc.dtls.wire.ClientKeyExchange
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.Extension
import com.ditchoom.webrtc.dtls.wire.ExtensionType
import com.ditchoom.webrtc.dtls.wire.HandshakeFragment
import com.ditchoom.webrtc.dtls.wire.HandshakeMessage
import com.ditchoom.webrtc.dtls.wire.HandshakeReassembler
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.NamedGroup
import com.ditchoom.webrtc.dtls.wire.ProtocolVersion
import com.ditchoom.webrtc.dtls.wire.ServerHello
import com.ditchoom.webrtc.dtls.wire.ServerKeyExchange
import com.ditchoom.webrtc.dtls.wire.SignatureSchemeId
import com.ditchoom.webrtc.dtls.wire.SrtpProtectionProfile
import com.ditchoom.webrtc.dtls.wire.u16
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The sans-io DTLS 1.2 handshake state machine for `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 6347 +
 * RFC 5246 + RFC 8422) — the pure-Kotlin core the [com.ditchoom.webrtc.dtls.DtlsEngine] drives. Caller
 * clocked (`now`), no coroutine, no I/O, no wall clock; the driver feeds it inbound datagrams and
 * a virtual clock and puts the returned records on the wire.
 *
 * WebRTC is **mutually authenticated** (RFC 8827: each peer presents a certificate and both fingerprints
 * are in the SDP), so both sides send a Certificate + CertificateVerify. Flights (the server skips the
 * optional stateless-cookie HelloVerifyRequest; the client still handles an inbound one for interop):
 * ```
 *   client → ClientHello
 *   server → ServerHello, Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone
 *   client → Certificate, ClientKeyExchange, CertificateVerify, [ChangeCipherSpec], Finished
 *   server → [ChangeCipherSpec], Finished
 * ```
 * Uses the RFC 7627 extended master secret when both peers advertise it. The record layer is plaintext
 * in epoch 0 and AES-128-GCM in epoch 1 (from the ChangeCipherSpec on).
 */
internal class Dtls12Handshake(
    private val config: DtlsConfig,
    private val role: DtlsRole,
    // The engine's long-lived identity: generated once at [DtlsEngine] construction (so its
    // fingerprint is readable before the role is known) and reused for every handshake attempt. The
    // engine owns its lifecycle, so this class never closes it.
    private val certificate: SelfSignedCertificate,
) : DtlsHandshakeFsm {
    private val factory: BufferFactory = config.bufferFactory
    private val random = config.random
    private val keySchedule = Tls12KeySchedule(factory)
    private val reassembler = HandshakeReassembler(factory)
    private val transcript = TranscriptHash(factory)

    private val ecdhe: EcdheKeyExchange = EcdheKeyExchange.generate()

    // ── negotiated / captured handshake material ─────────────────────────────────────────────────
    private lateinit var localRandom: ReadBuffer
    private var clientRandom: ReadBuffer? = null
    private var serverRandom: ReadBuffer? = null
    private var peerCertDer: ReadBuffer? = null
    private var peerEcdhPoint: ReadBuffer? = null
    private var useExtendedMasterSecret = false
    private var peerAdvertisedRenegotiation = false
    private var negotiatedSrtpProfile: SrtpProtectionProfile? = null

    // The master secret and its record protection are derived together and only make sense together
    // (DESIGN §4: no nullable soup) — one sealed value, so "master set but protection null" is
    // unrepresentable. Read-only accessors below keep the [masterSecret]/[protection] names.
    private var keys: Keys = Keys.Pending

    // ── record send state: monotonic seq per epoch (retransmits reuse epochs, get fresh seqs) ─────
    private var epoch0Seq = 0L
    private var epoch1Seq = 0L

    private var sendMsgSeq = 0
    private var started = false
    private var terminal: DtlsState? = null

    // ── retransmission (RFC 6347 §4.2.4): last flight + a backoff timer ───────────────────────────
    private var lastFlight: List<FlightItem>? = null
    private var retransmitDeadline: Instant? = null
    private var retransmitBackoff = INITIAL_RETRANSMIT

    // Set within one onDatagram when a handshake record arrives AFTER we reached Established — the peer is
    // still handshaking and retransmitting, i.e. our final flight was lost (in DTLS 1.2 the SERVER sends the
    // last flight, so this is the server side). RFC 6347 §4.2.4: retain + retransmit the last flight, else a
    // lost final flight deadlocks. onDatagram re-emits lastFlight when this is set.
    private var peerRetransmitAfterEstablished = false

    // The clock instant of our most recent post-Established last-flight retransmit. Rate-limits that
    // response (below) to at most once per INITIAL_RETRANSMIT so two finished peers cannot echo each other's
    // re-sent flights forever: a genuinely lost final flight draws the peer's timer-spaced (≥ 1 s) retransmit
    // — each still answered — but the peer's immediate echo of our own re-send (sub-RTT ≪ 1 s) is suppressed,
    // so the mutual handshake-record storm dies after one exchange instead of starving the SCTP handshake
    // riding above (the impaired-lane stall the DTLS+SCTP repro caught).
    private var lastEstablishedResendAt: Instant? = null

    /** Master secret + record protection, derived together (a ChangeCipherSpec), so neither exists alone. */
    private sealed interface Keys {
        data object Pending : Keys

        class Derived(
            val master: ReadBuffer,
            val protection: Dtls12RecordProtection,
        ) : Keys
    }

    private val masterSecret: ReadBuffer? get() = (keys as? Keys.Derived)?.master
    private val protection: Dtls12RecordProtection? get() = (keys as? Keys.Derived)?.protection

    private class FlightItem(
        val contentType: Int,
        val payload: ReadBuffer,
        val epoch: Int,
        val encrypted: Boolean,
    )

    // ── public sans-io surface (mirrors DtlsEngine) ──────────────────────────────────────────────

    override fun start(now: Instant): DtlsStep {
        check(!started) { "start() called twice" }
        started = true
        localRandom = randomBytes(RANDOM_BYTES)
        if (role == DtlsRole.Client) {
            clientRandom = localRandom
            val out = mutableListOf<ReadBuffer>()
            beginClientHelloFlight(out, now)
            return step(out, emptyList())
        }
        serverRandom = localRandom // set now; the server also uses it in flight 2
        return step(emptyList(), emptyList()) // server waits for ClientHello
    }

    override fun onDatagram(
        datagram: ReadBuffer,
        now: Instant,
    ): DtlsStep {
        // A dead transport stops processing; an Established one keeps decrypting application data.
        (terminal as? DtlsState.Failed)?.let { return DtlsStep(emptyList(), emptyList(), it) }
        (terminal as? DtlsState.Closed)?.let { return DtlsStep(emptyList(), emptyList(), it) }
        val records = DtlsRecord.decodeAll(datagram) ?: return step(emptyList(), emptyList())
        val out = mutableListOf<ReadBuffer>()
        val appData = mutableListOf<ReadBuffer>()
        peerRetransmitAfterEstablished = false
        for (rec in records) {
            when (rec.contentType.value) {
                ContentType.Handshake.value -> {
                    // A handshake record after we finished = the peer retransmitting (our last flight was
                    // lost). Flag it so we re-send below, instead of dedup-swallowing it and deadlocking.
                    if (terminal is DtlsState.Established) peerRetransmitAfterEstablished = true
                    processHandshakeRecord(rec, out, now)
                }
                ContentType.ChangeCipherSpec.value -> Unit // epoch is read from each record's own header
                ContentType.ApplicationData.value -> decryptApplicationData(rec)?.let { appData += it }
                ContentType.Alert.value -> fail(DtlsFailureReason.HandshakeFailure)
                else -> Unit // unknown content type — drop (RFC 6347)
            }
            // Stop on a terminal FAILURE/CLOSE, but not on Established — we still append any re-send below.
            if (terminal is DtlsState.Failed || terminal is DtlsState.Closed) return DtlsStep(out, appData, terminal!!)
        }
        // Retransmit our last flight if the peer is still handshaking after we established (RFC 6347 §4.2.4),
        // rate-limited to once per INITIAL_RETRANSMIT so two finished peers don't echo forever (see the field).
        if (peerRetransmitAfterEstablished) {
            val last = lastEstablishedResendAt
            if (last == null || now - last >= INITIAL_RETRANSMIT) {
                lastFlight?.let { flight ->
                    for (item in flight) out += emit(item)
                    lastEstablishedResendAt = now
                }
            }
        }
        // Keep our retransmit timer armed while still handshaking with an unacked flight: cancelRetransmit()
        // (after processing) drops it, so a PARTIAL peer flight would otherwise leave us with progress but no
        // timer — we would stop retransmitting and deadlock on a lost final message. Reset to the initial
        // interval since new handshake bytes are genuine progress.
        if (terminal == null && lastFlight != null && retransmitDeadline == null) {
            retransmitBackoff = INITIAL_RETRANSMIT
            retransmitDeadline = now + retransmitBackoff
        }
        terminal?.let { return DtlsStep(out, appData, it) }
        return DtlsStep(out, appData, stateNow())
    }

    override fun onTimeout(now: Instant): DtlsStep {
        terminal?.let { return DtlsStep(emptyList(), emptyList(), it) }
        val deadline = retransmitDeadline ?: return step(emptyList(), emptyList())
        if (now < deadline) return step(emptyList(), emptyList())
        val flight = lastFlight ?: return step(emptyList(), emptyList())
        val out = flight.map { emit(it) }.toMutableList()
        retransmitBackoff = minOf(retransmitBackoff * 2, MAX_RETRANSMIT)
        retransmitDeadline = now + retransmitBackoff
        return step(out, emptyList())
    }

    override fun sealApplicationData(
        applicationData: ReadBuffer,
        now: Instant,
    ): DtlsStep {
        val prot = protection
        if (terminal !is DtlsState.Established || prot == null) {
            return DtlsStep(emptyList(), emptyList(), terminal ?: DtlsState.Handshaking)
        }
        val seq = epoch1Seq++
        val fragment = prot.seal(applicationData, EPOCH_1, seq, ContentType.ApplicationData.value, DTLS12)
        val record = DtlsRecord(ContentType.ApplicationData, ProtocolVersion.Dtls12, EPOCH_1, seq, fragment)
        return DtlsStep(listOf(encode(record)), emptyList(), terminal!!)
    }

    /**
     * Begin an orderly close: queue a `close_notify` alert (encrypted once we have keys) and transition
     * to [DtlsState.Closed]. Best-effort per RFC 6347 §4.1 — DTLS does not wait for the peer's reply.
     */
    override fun beginClose(now: Instant): DtlsStep {
        if (terminal is DtlsState.Closed) return DtlsStep(emptyList(), emptyList(), DtlsState.Closed)
        val out = mutableListOf<ReadBuffer>()
        val prot = protection
        if (prot != null && terminal is DtlsState.Established) {
            val alert =
                buildBody {
                    it.writeByte(1) // level = warning
                    it.writeByte(0) // description = close_notify
                }
            val seq = epoch1Seq++
            val fragment = prot.seal(alert, EPOCH_1, seq, ContentType.Alert.value, DTLS12)
            out += encode(DtlsRecord(ContentType.Alert, ProtocolVersion.Dtls12, EPOCH_1, seq, fragment))
        }
        cancelRetransmit()
        terminal = DtlsState.Closed
        return DtlsStep(out, emptyList(), DtlsState.Closed)
    }

    override fun nextDeadline(now: Instant): Instant? = if (terminal != null) null else retransmitDeadline

    override fun exportKeyingMaterial(
        label: String,
        context: ReadBuffer?,
        length: Int,
    ): ReadBuffer? {
        if (terminal !is DtlsState.Established) return null
        val master = masterSecret ?: return null
        val cr = clientRandom ?: return null
        val sr = serverRandom ?: return null
        return keySchedule.exportKeyingMaterial(master, label, cr, sr, context, length)
    }

    override fun close() {
        ecdhe.close()
        protection?.close()
    }

    // ── handshake record processing ──────────────────────────────────────────────────────────────

    private fun processHandshakeRecord(
        record: DtlsRecord,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        val handshakeBytes =
            if (record.epoch >= EPOCH_1) {
                val prot = protection ?: return // encrypted before keys — drop
                prot.open(record.fragment, record.epoch, record.sequenceNumber, ContentType.Handshake.value, DTLS12)
                    ?: return // undecryptable handshake record — drop (RFC 6347)
            } else {
                record.fragment
            }
        val fragments = HandshakeFragment.decodeAll(handshakeBytes) ?: return
        for (fragment in fragments) {
            for (message in reassembler.offer(fragment)) {
                handleHandshakeMessage(message, out, now)
                if (terminal != null) return
            }
        }
    }

    private fun handleHandshakeMessage(
        message: HandshakeMessage,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        cancelRetransmit()
        when (role) {
            DtlsRole.Client -> handleAsClient(message, out, now)
            DtlsRole.Server -> handleAsServer(message, out, now)
        }
    }

    // ── client role ──────────────────────────────────────────────────────────────────────────────

    private fun handleAsClient(
        message: HandshakeMessage,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        when (message.msgType.value) {
            HandshakeType.ServerHello.value -> {
                val sh = ServerHello.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                if (sh.cipherSuite.value != CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256.value) {
                    return fail(DtlsFailureReason.HandshakeFailure)
                }
                serverRandom = copyOf(sh.random)
                useExtendedMasterSecret = sh.extensions.any { it.type.value == ExtensionType.ExtendedMasterSecret.value }
                transcript.append(message)
            }
            HandshakeType.Certificate.value -> {
                val cert = CertificateMessage.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                peerCertDer = cert.certificates.firstOrNull()?.let { copyOf(it) }
                    ?: return fail(DtlsFailureReason.PeerCertificateMissing)
                transcript.append(message)
            }
            HandshakeType.ServerKeyExchange.value -> {
                val ske = ServerKeyExchange.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                if (!verifyServerKeyExchange(ske)) return fail(DtlsFailureReason.HandshakeFailure)
                peerEcdhPoint = copyOf(ske.publicPoint)
                transcript.append(message)
            }
            HandshakeType.CertificateRequest.value -> {
                // WebRTC is mutually authenticated (RFC 8827): the request means we send our own
                // Certificate + CertificateVerify in the next flight. Only the type matters here.
                transcript.append(message)
            }
            HandshakeType.ServerHelloDone.value -> {
                transcript.append(message)
                sendClientFinishFlight(out, now)
            }
            HandshakeType.Finished.value -> {
                if (!verifyPeerFinished(message, Tls12KeySchedule.SERVER_FINISHED_LABEL)) {
                    return fail(DtlsFailureReason.HandshakeFailure)
                }
                transcript.append(message)
                establish()
            }
            HandshakeType.HelloVerifyRequest.value -> Unit // handled pre-reassembly in a full impl; server skips it here
            else -> Unit
        }
    }

    private fun sendClientFinishFlight(
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        val flight = mutableListOf<FlightItem>()
        // Certificate (our own — WebRTC mutual auth), then ClientKeyExchange.
        val certMsg = buildBody { CertificateMessage(listOf(certificate.derEncoded)).bodyInto(it) }
        flight += queueHandshake(HandshakeType.Certificate, certMsg, EPOCH_0, encrypted = false)
        val cke = buildBody { ClientKeyExchange(ecdhe.localPublicPoint).bodyInto(it) }
        flight += queueHandshake(HandshakeType.ClientKeyExchange, cke, EPOCH_0, encrypted = false)
        // Derive keys now that both points are known — session_hash (RFC 7627) is the transcript through
        // ClientKeyExchange, so this MUST run before CertificateVerify is appended.
        deriveKeys(client = true)
        // CertificateVerify proves we own the cert whose fingerprint is in our SDP — sign the transcript
        // so far (ClientHello … ClientKeyExchange) with our identity key.
        flight += buildCertificateVerify()
        // ChangeCipherSpec then the encrypted Finished.
        flight += FlightItem(ContentType.ChangeCipherSpec.value, singleByte(1), EPOCH_0, encrypted = false)
        flight += buildFinished(Tls12KeySchedule.CLIENT_FINISHED_LABEL)
        emitFlight(flight, out, now)
    }

    private fun buildCertificateVerify(): FlightItem {
        val message = transcript.currentBytes()
        val raw = signatures().ops.signBlocking(certificate.signingKey, message)
        val derSig = if (ecdsaSignatureEncoding == EcdsaSignatureEncoding.Der) raw else ecdsaSignatureToDer(SignatureScheme.EcdsaP256, raw)
        val body = buildBody { CertificateVerify(SignatureSchemeId.EcdsaSecp256r1Sha256, derSig).bodyInto(it) }
        return queueHandshake(HandshakeType.CertificateVerify, body, EPOCH_0, encrypted = false)
    }

    // ── server role ──────────────────────────────────────────────────────────────────────────────

    private fun handleAsServer(
        message: HandshakeMessage,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        when (message.msgType.value) {
            HandshakeType.ClientHello.value -> {
                val ch = ClientHello.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                if (ch.cipherSuites.none { it.value == CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256.value }) {
                    return fail(DtlsFailureReason.HandshakeFailure)
                }
                clientRandom = copyOf(ch.random)
                useExtendedMasterSecret = ch.extensions.any { it.type.value == ExtensionType.ExtendedMasterSecret.value }
                // RFC 5746 secure-renegotiation indication: the client signals support with an (empty)
                // renegotiation_info extension or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV. OpenSSL aborts a
                // server that doesn't echo it ("unsafe legacy renegotiation disabled"), so track + echo it.
                peerAdvertisedRenegotiation =
                    ch.extensions.any { it.type.value == ExtensionType.RenegotiationInfo.value } ||
                    ch.cipherSuites.any { it.value == RENEGOTIATION_SCSV }
                // RFC 5764 DTLS-SRTP: a WebRTC peer always offers `use_srtp`, and a strict client (pion/dtls)
                // sends a fatal alert if the server does not echo it, even for a data-channel-only session
                // (BoringSSL/OpenSSL tolerate the omission — the same lenient-vs-strict split as RFC 5746
                // above). Select a mutually-supported profile to echo in the ServerHello. We negotiate the
                // extension but don't derive SRTP keys until media (Phase 2, via the DTLS exporter).
                negotiatedSrtpProfile = selectSrtpProfile(ch)
                transcript.append(message)
                sendServerHelloFlight(out, now)
            }
            HandshakeType.Certificate.value -> {
                val cert = CertificateMessage.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                peerCertDer = cert.certificates.firstOrNull()?.let { copyOf(it) }
                    ?: return fail(DtlsFailureReason.PeerCertificateMissing)
                transcript.append(message)
            }
            HandshakeType.ClientKeyExchange.value -> {
                val cke = ClientKeyExchange.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                peerEcdhPoint = copyOf(cke.publicPoint)
                transcript.append(message)
                deriveKeys(client = false)
            }
            HandshakeType.CertificateVerify.value -> {
                // Verify the client owns the cert it presented (signature over the transcript so far).
                if (!verifyCertificateVerify(message)) return fail(DtlsFailureReason.HandshakeFailure)
                transcript.append(message)
            }
            HandshakeType.Finished.value -> {
                if (!verifyPeerFinished(message, Tls12KeySchedule.CLIENT_FINISHED_LABEL)) {
                    return fail(DtlsFailureReason.HandshakeFailure)
                }
                transcript.append(message)
                sendServerFinishFlight(out, now)
                establish()
            }
            else -> Unit
        }
    }

    private fun sendServerHelloFlight(
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        val flight = mutableListOf<FlightItem>()
        val extensions = mutableListOf<Extension>()
        if (useExtendedMasterSecret) extensions += Extension(ExtensionType.ExtendedMasterSecret, empty())
        // Echo an empty renegotiation_info when the client indicated RFC 5746 support (initial handshake:
        // renegotiated_connection is zero-length). Required by OpenSSL; browsers/BoringSSL send it too.
        if (peerAdvertisedRenegotiation) extensions += renegotiationInfoExtension()
        // Echo the selected DTLS-SRTP profile (RFC 5764 §4.1.2) when the client offered use_srtp — required
        // by pion/dtls, which fatally alerts a server that omits it. Server response = one selected profile.
        negotiatedSrtpProfile?.let { extensions += useSrtpServerExtension(it) }
        val sh =
            buildBody {
                ServerHello(
                    ProtocolVersion.Dtls12,
                    serverRandom!!,
                    empty(),
                    CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256,
                    extensions,
                ).bodyInto(it)
            }
        flight += queueHandshake(HandshakeType.ServerHello, sh, EPOCH_0, encrypted = false)

        val certMsg = buildBody { CertificateMessage(listOf(certificate.derEncoded)).bodyInto(it) }
        flight += queueHandshake(HandshakeType.Certificate, certMsg, EPOCH_0, encrypted = false)

        val ske = buildBody { serverKeyExchange().bodyInto(it) }
        flight += queueHandshake(HandshakeType.ServerKeyExchange, ske, EPOCH_0, encrypted = false)

        // CertificateRequest — WebRTC mutual auth (RFC 8827): ask the client for its certificate.
        flight += queueHandshake(HandshakeType.CertificateRequest, certificateRequestBody(), EPOCH_0, encrypted = false)

        flight += queueHandshake(HandshakeType.ServerHelloDone, empty(), EPOCH_0, encrypted = false)
        emitFlight(flight, out, now)
    }

    private fun sendServerFinishFlight(
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        val flight = mutableListOf<FlightItem>()
        flight += FlightItem(ContentType.ChangeCipherSpec.value, singleByte(1), EPOCH_0, encrypted = false)
        flight += buildFinished(Tls12KeySchedule.SERVER_FINISHED_LABEL)
        emitFlight(flight, out, now)
    }

    private fun serverKeyExchange(): ServerKeyExchange {
        val point = copyOf(ecdhe.localPublicPoint)
        val unsigned = ServerKeyExchange(NamedGroup.Secp256r1, point, SignatureSchemeId.EcdsaSecp256r1Sha256, empty())
        val signed = signServerParams(unsigned)
        return ServerKeyExchange(NamedGroup.Secp256r1, point, SignatureSchemeId.EcdsaSecp256r1Sha256, signed)
    }

    // ── key schedule + Finished ──────────────────────────────────────────────────────────────────

    private fun deriveKeys(client: Boolean) {
        val cr = clientRandom!!
        val sr = serverRandom!!
        val sessionHash = if (useExtendedMasterSecret) transcript.currentSha256() else null
        val premaster = ecdhe.premasterSecret(peerEcdhPoint!!)
        val master =
            try {
                keySchedule.masterSecret(premaster, cr, sr, sessionHash)
            } finally {
                premaster.freeNativeMemory()
            }
        val keyBlock = keySchedule.keyBlock(master, sr, cr, Dtls12RecordProtection.KEY_BLOCK_BYTES)
        keys = Keys.Derived(master, Dtls12RecordProtection.fromKeyBlock(keyBlock, client = client, factory))
    }

    private fun buildFinished(label: String): FlightItem {
        val verifyData = keySchedule.verifyData(masterSecret!!, label, transcript.currentSha256())
        return queueHandshake(HandshakeType.Finished, verifyData, EPOCH_1, encrypted = true)
    }

    private fun verifyPeerFinished(
        message: HandshakeMessage,
        label: String,
    ): Boolean {
        if (message.length != Tls12KeySchedule.VERIFY_DATA_BYTES) return false
        val expected = keySchedule.verifyData(masterSecret!!, label, transcript.currentSha256())
        return constantTimeEquals(expected, message.body)
    }

    // ── ECDSA sign / verify over the ServerKeyExchange params ─────────────────────────────────────

    private fun signServerParams(ske: ServerKeyExchange): ReadBuffer {
        val message = signedParamsBytes(ske)
        val support = signatures()
        val raw = support.ops.signBlocking(certificate.signingKey, message)
        return if (ecdsaSignatureEncoding == EcdsaSignatureEncoding.Der) raw else ecdsaSignatureToDer(SignatureScheme.EcdsaP256, raw)
    }

    private fun verifyServerKeyExchange(ske: ServerKeyExchange): Boolean {
        val verifyKey = verifyKeyFromCert(peerCertDer ?: return false) ?: return false
        return verifyWireSignature(verifyKey, signedParamsBytes(ske), ske.signature)
    }

    private fun verifyCertificateVerify(message: HandshakeMessage): Boolean {
        val cv = CertificateVerify.parse(message.body) ?: return false
        val verifyKey = verifyKeyFromCert(peerCertDer ?: return false) ?: return false
        // The signature covers the handshake_messages up to (not including) this CertificateVerify —
        // which is exactly the current transcript, since it is verified before being appended.
        return verifyWireSignature(verifyKey, transcript.currentBytes(), cv.signature)
    }

    /** Lifts a P-256 [VerifyKey] out of an X.509 certificate DER, or null if it doesn't parse. */
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

    /** Verifies a DER-on-the-wire ECDSA-P256 signature, transcoding to the platform encoding if needed. */
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

    /** CertificateRequest body: `ecdsa_sign` type, `ecdsa_secp256r1_sha256` sig-alg, no CA hints. */
    private fun certificateRequestBody(): ReadBuffer =
        buildBody {
            it.writeByte(1) // certificate_types length
            it.writeByte(64) // ecdsa_sign
            it.writeShort(2) // supported_signature_algorithms length
            it.writeShort(SignatureSchemeId.EcdsaSecp256r1Sha256.value.toShort())
            it.writeShort(0) // certificate_authorities length (empty)
        }

    /** `client_random ‖ server_random ‖ ServerECDHParams` — the bytes the ServerKeyExchange signs (RFC 8422 §5.4). */
    private fun signedParamsBytes(ske: ServerKeyExchange): ReadBuffer {
        val params = buildBody { ske.serverEcdhParamsInto(it) }
        val out = factory.allocate(RANDOM_BYTES * 2 + params.remaining(), ByteOrder.BIG_ENDIAN)
        writeView(out, clientRandom!!)
        writeView(out, serverRandom!!)
        writeView(out, params)
        out.resetForRead()
        return out
    }

    private fun signatures(): SignatureSupport.Blocking {
        val support = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256)
        check(support is SignatureSupport.Blocking) { "ECDSA-P256 blocking signatures unavailable on this target" }
        return support
    }

    // ── flight assembly + record emission ────────────────────────────────────────────────────────

    private fun beginClientHelloFlight(
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        val extensions =
            listOf(
                supportedGroupsExtension(),
                ecPointFormatsExtension(),
                signatureAlgorithmsExtension(),
                Extension(ExtensionType.ExtendedMasterSecret, empty()),
                // RFC 5746: advertise secure-renegotiation support so servers that require it (OpenSSL)
                // accept our initial handshake. Empty renegotiated_connection = initial handshake.
                renegotiationInfoExtension(),
                // RFC 5764: offer use_srtp — every WebRTC peer negotiates DTLS-SRTP, and a strict server
                // expects it. Our server (below) echoes the selected profile back.
                useSrtpClientExtension(),
            )
        val ch =
            buildBody {
                ClientHello(
                    ProtocolVersion.Dtls12,
                    clientRandom!!,
                    empty(),
                    empty(), // no cookie on the initial hello
                    listOf(CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256),
                    extensions,
                ).bodyInto(it)
            }
        val item = queueHandshake(HandshakeType.ClientHello, ch, EPOCH_0, encrypted = false)
        emitFlight(listOf(item), out, now)
    }

    private fun queueHandshake(
        msgType: HandshakeType,
        body: ReadBuffer,
        epoch: Int,
        encrypted: Boolean,
    ): FlightItem {
        val message = HandshakeMessage(msgType, sendMsgSeq++, body)
        transcript.append(message)
        val wire = factory.allocate(message.wireSize, ByteOrder.BIG_ENDIAN)
        message.encodeInto(wire)
        wire.resetForRead()
        return FlightItem(ContentType.Handshake.value, wire, epoch, encrypted)
    }

    private fun emitFlight(
        flight: List<FlightItem>,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        for (item in flight) out += emit(item)
        lastFlight = flight
        retransmitBackoff = INITIAL_RETRANSMIT
        retransmitDeadline = now + retransmitBackoff
    }

    private fun emit(item: FlightItem): ReadBuffer {
        val seq = if (item.epoch == EPOCH_0) epoch0Seq++ else epoch1Seq++
        val fragment =
            if (item.encrypted) {
                protection!!.seal(item.payload, item.epoch, seq, item.contentType, DTLS12)
            } else {
                item.payload
            }
        return encode(DtlsRecord(ContentType(item.contentType), ProtocolVersion.Dtls12, item.epoch, seq, fragment))
    }

    private fun decryptApplicationData(record: DtlsRecord): ReadBuffer? {
        if (record.epoch < EPOCH_1) return null
        val prot = protection ?: return null
        return prot.open(record.fragment, record.epoch, record.sequenceNumber, ContentType.ApplicationData.value, DTLS12)
    }

    // ── terminal transitions ─────────────────────────────────────────────────────────────────────

    private fun establish() {
        cancelRetransmit()
        val fp = peerCertDer?.let { SelfSignedCertificate.fingerprintOf(it, factory) }
        if (fp == null) {
            terminal = DtlsState.Failed(DtlsFailureReason.PeerCertificateMissing)
            return
        }
        terminal = DtlsState.Established(fp, DtlsVersion.Dtls12)
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

    // ── extension builders ───────────────────────────────────────────────────────────────────────

    private fun supportedGroupsExtension(): Extension {
        val body = factory.allocate(4, ByteOrder.BIG_ENDIAN)
        body.writeShort(2) // list length
        body.writeShort(NamedGroup.Secp256r1.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.SupportedGroups, body)
    }

    private fun ecPointFormatsExtension(): Extension {
        val body = factory.allocate(2, ByteOrder.BIG_ENDIAN)
        body.writeByte(1) // list length
        body.writeByte(0) // uncompressed
        body.resetForRead()
        return Extension(ExtensionType.EcPointFormats, body)
    }

    private fun signatureAlgorithmsExtension(): Extension {
        val body = factory.allocate(4, ByteOrder.BIG_ENDIAN)
        body.writeShort(2) // list length
        body.writeShort(SignatureSchemeId.EcdsaSecp256r1Sha256.value.toShort())
        body.resetForRead()
        return Extension(ExtensionType.SignatureAlgorithms, body)
    }

    /** RFC 5746 renegotiation_info for an initial handshake: a single zero byte (empty renegotiated_connection). */
    private fun renegotiationInfoExtension(): Extension {
        val body = factory.allocate(1, ByteOrder.BIG_ENDIAN)
        body.writeByte(0) // renegotiated_connection length = 0
        body.resetForRead()
        return Extension(ExtensionType.RenegotiationInfo, body)
    }

    /** ClientHello `use_srtp` (RFC 5764 §4.1.2): our supported profiles, most-preferred first, empty MKI. */
    private fun useSrtpClientExtension(): Extension {
        val body = factory.allocate(2 + SUPPORTED_SRTP_PROFILES.size * 2 + 1, ByteOrder.BIG_ENDIAN)
        body.writeShort((SUPPORTED_SRTP_PROFILES.size * 2).toShort()) // SRTPProtectionProfiles length
        for (p in SUPPORTED_SRTP_PROFILES) body.writeShort(p.toShort())
        body.writeByte(0) // srtp_mki<0..255> = empty
        body.resetForRead()
        return Extension(ExtensionType.UseSrtp, body)
    }

    /** ServerHello `use_srtp` (RFC 5764 §4.1.2): the single selected [profile], empty MKI. */
    private fun useSrtpServerExtension(profile: SrtpProtectionProfile): Extension {
        val body = factory.allocate(2 + 2 + 1, ByteOrder.BIG_ENDIAN)
        body.writeShort(2) // one SRTPProtectionProfile (2 bytes)
        body.writeShort(profile.value.toShort())
        body.writeByte(0) // srtp_mki<0..255> = empty
        body.resetForRead()
        return Extension(ExtensionType.UseSrtp, body)
    }

    /**
     * The first client-offered SRTP profile we support (RFC 5764 §4.1.2 `use_srtp`), or null if the client
     * sent no `use_srtp` extension. Malformed bodies yield null (a lenient no-negotiation, never a throw).
     */
    private fun selectSrtpProfile(ch: ClientHello): SrtpProtectionProfile? {
        val body = ch.extensions.firstOrNull { it.type.value == ExtensionType.UseSrtp.value }?.body ?: return null
        val n = body.remaining()
        if (n < 2) return null
        val profilesLen = body.u16(0)
        if (profilesLen % 2 != 0 || 2 + profilesLen > n) return null
        var off = 2
        while (off + 2 <= 2 + profilesLen) {
            val id = body.u16(off)
            if (id in SUPPORTED_SRTP_PROFILES) return SrtpProtectionProfile(id)
            off += 2
        }
        return null
    }

    // ── small buffer helpers ─────────────────────────────────────────────────────────────────────

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

    private fun singleByte(v: Int): ReadBuffer {
        val b = factory.allocate(1, ByteOrder.BIG_ENDIAN)
        b.writeByte(v.toByte())
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
        const val EPOCH_1 = 1
        const val DTLS12 = 0xFEFD
        const val RENEGOTIATION_SCSV = 0x00FF // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 §3.3)
        const val MAX_MESSAGE_BYTES = 4096

        // DTLS-SRTP profiles we negotiate (RFC 5764), most-preferred first — mirrors the BoringSSL oracle's
        // "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80". We negotiate the extension for interop; SRTP key
        // export is Phase-2 media.
        val SUPPORTED_SRTP_PROFILES =
            listOf(
                SrtpProtectionProfile.AeadAes128Gcm.value,
                SrtpProtectionProfile.Aes128CmHmacSha1_80.value,
            )
        val INITIAL_RETRANSMIT = 1.seconds // RFC 6347/9147 initial retransmit timer
        val MAX_RETRANSMIT = 60.seconds
    }
}
