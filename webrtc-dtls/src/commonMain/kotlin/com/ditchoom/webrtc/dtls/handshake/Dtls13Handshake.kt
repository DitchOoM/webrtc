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
import com.ditchoom.webrtc.dtls.KeyExchangeGroup
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
import com.ditchoom.webrtc.dtls.wire.NamedGroup
import com.ditchoom.webrtc.dtls.wire.ProtocolVersion
import com.ditchoom.webrtc.dtls.wire.ServerHello
import com.ditchoom.webrtc.dtls.wire.SignatureSchemeId
import com.ditchoom.webrtc.dtls.wire.Tls13Bodies
import com.ditchoom.webrtc.dtls.wire.u16
import com.ditchoom.webrtc.dtls.wire.u8
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The sans-io DTLS 1.3 handshake state machine for `TLS_AES_128_GCM_SHA256` (RFC 9147 over RFC 8446) —
 * the pure-Kotlin core the [com.ditchoom.webrtc.dtls.DtlsEngine] drives when 1.3 is negotiated. Caller
 * clocked (`now`), no coroutine, no wall clock. Byte-matched against the BoringSSL oracle.
 *
 * The (EC)DHE group is negotiable: a client advertises **every** supported group — X25519 (default,
 * browser-matching) and P-256 — in `supported_groups`, but key-shares only its preferred group. A server
 * that accepts that group completes in one round trip (the common case); a server that prefers a different
 * (but offered) group answers with a single HelloRetryRequest, and the client retries with a fresh
 * `key_share` (RFC 8446 §4.1.4). A server adopts whichever supported group the peer ends up key-sharing.
 * (ECDSA-P256 identity/signatures are unchanged; only the ephemeral key exchange varies.)
 *
 * WebRTC is **mutually authenticated** (RFC 8827), so both peers send Certificate + CertificateVerify.
 * The flights (the optional HelloRetryRequest exchange, if any, precedes the ServerHello):
 * ```
 *   client → ClientHello                                                        (epoch 0, plaintext)
 *  [server → HelloRetryRequest ; client → ClientHello (retry)                   (epoch 0, plaintext)]
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

    // The (EC)DHE group is negotiated: a client uses its configured group; a server adopts whichever
    // supported group the peer key-shared (set in handleAsServer). The ephemeral keypair is therefore
    // deferred to that point — its curve isn't known until the group is (client: at start; server: on CH).
    private var negotiatedGroup: KeyExchangeGroup = config.keyExchangeGroup
    private var ecdhe: EcdheKeyExchange? = null

    // HelloRetryRequest (RFC 8446 §4.1.4 / RFC 9147). A client offers every supported group in
    // supported_groups but key-shares only [config.keyExchangeGroup]; a server that prefers a different
    // (but client-offered) group answers with one HRR. Exactly one HRR is permitted per handshake.
    private var receivedHrr = false // client: an HRR has been consumed (a second one is fatal)
    private var sentHrr = false // server: an HRR has been emitted (never HRR twice)
    private var hrrRequestedGroup: KeyExchangeGroup? = null // server: the group we asked the client to retry with
    private var hrrCookie: ReadBuffer? = null // client: a cookie extension from the HRR, echoed verbatim in CH2

    private lateinit var localRandom: ReadBuffer
    private var peerCertDer: ReadBuffer? = null
    private var peerPoint: ReadBuffer? = null

    // Key material as a phase progression (DESIGN §4: no nullable soup) — Pending → Handshake (epoch-2
    // traffic keys) → Application (also epoch-3). A partially-derived combination is unrepresentable, so
    // "master set but protection null" cannot occur. Read-only accessors below keep the material's names.
    private var keys: Keys = Keys.Pending

    // Record send state: monotonic per epoch. Epoch 0 = plaintext, 2 = handshake keys, 3 = app keys.
    private var epoch0Seq = 0L
    private var epoch2Seq = 0L
    private var epoch3Seq = 0L

    private var sendMsgSeq = 0
    private var started = false
    private var terminal: DtlsState? = null

    // Retransmission (RFC 9147 §5.8): the last flight + a backoff timer.
    private var lastFlight: List<FlightItem>? = null
    private var retransmitDeadline: Instant? = null
    private var retransmitBackoff = INITIAL_RETRANSMIT

    // Set within one onDatagram when, AFTER we reached Established, a handshake-epoch record arrives from
    // the peer — meaning the peer is still handshaking and retransmitting its flight, i.e. our final flight
    // was lost. RFC 6347 §4.2.4 / RFC 9147 §5.8.1: we must retain our last flight and retransmit it in
    // response, or a single lost final flight deadlocks (we sit Established, the peer retransmits forever
    // and times out). onDatagram re-emits lastFlight when this is set.
    private var peerRetransmitAfterEstablished = false

    // The clock instant of our most recent post-Established last-flight retransmit. We rate-limit that
    // response (below) to at most once per INITIAL_RETRANSMIT so two peers that BOTH finished cannot echo
    // each other's re-sent flights forever: if our final flight was truly lost the peer retransmits on its
    // own timer (spaced ≥ INITIAL_RETRANSMIT) and each retransmit still draws a response, but the peer's
    // immediate echo of OUR re-send (arriving within the interval — sub-RTT ≪ 1 s) is suppressed, so the
    // mutual handshake-record storm dies after one exchange instead of saturating the transport and
    // starving the SCTP handshake that rides above it (the impaired-lane stall the DTLS+SCTP repro caught).
    private var lastEstablishedResendAt: Instant? = null

    private class FlightItem(
        val realContentType: Int,
        val payload: ReadBuffer,
        val epoch: Int,
    )

    /** Derived key material as a phase, so no partial/inconsistent combination is representable. */
    private sealed interface Keys {
        data object Pending : Keys

        /** Epoch-2 handshake traffic keys; [master] is retained to derive the application secrets. */
        class Handshake(
            val master: ReadBuffer,
            val clientHs: ReadBuffer,
            val serverHs: ReadBuffer,
            val protection: Dtls13RecordProtection,
        ) : Keys

        /** Epoch-3 application traffic keys + the RFC 8446 §7.5 exporter_master_secret, over retained hs keys. */
        class Application(
            val handshake: Handshake,
            val protection: Dtls13RecordProtection,
            val exporterMaster: ReadBuffer,
        ) : Keys
    }

    // Read-only views over [keys] so the handshake logic reads named material without any nullable soup.
    private val handshakeKeys: Keys.Handshake?
        get() =
            when (val k = keys) {
                is Keys.Handshake -> k
                is Keys.Application -> k.handshake
                Keys.Pending -> null
            }

    private val clientHsSecret: ReadBuffer? get() = handshakeKeys?.clientHs
    private val serverHsSecret: ReadBuffer? get() = handshakeKeys?.serverHs
    private val masterSecret: ReadBuffer? get() = handshakeKeys?.master
    private val handshakeProtection: Dtls13RecordProtection? get() = handshakeKeys?.protection
    private val appProtection: Dtls13RecordProtection? get() = (keys as? Keys.Application)?.protection

    // ── sans-io surface ──────────────────────────────────────────────────────────────────────────

    override fun start(now: Instant): DtlsStep {
        check(!started) { "start() called twice" }
        started = true
        localRandom = randomBytes(RANDOM_BYTES)
        if (role == DtlsRole.Client) {
            // Offer exactly one group (its curve is now fixed), so the server can never HelloRetryRequest.
            ecdhe = EcdheKeyExchange.generate(negotiatedGroup.agreementCurve)
            val out = mutableListOf<ReadBuffer>()
            sendClientHelloFlight(out, now)
            return step(out, emptyList())
        }
        return step(emptyList(), emptyList()) // server waits for ClientHello (its group + curve chosen then)
    }

    override fun onDatagram(
        datagram: ReadBuffer,
        now: Instant,
    ): DtlsStep {
        (terminal as? DtlsState.Failed)?.let { return DtlsStep(emptyList(), emptyList(), it) }
        (terminal as? DtlsState.Closed)?.let { return DtlsStep(emptyList(), emptyList(), it) }
        val out = mutableListOf<ReadBuffer>()
        val appData = mutableListOf<ReadBuffer>()
        peerRetransmitAfterEstablished = false
        walkRecords(datagram, out, appData, now)
        // The peer retransmitted its handshake flight after we finished → our final flight was lost.
        // Retransmit it (RFC 6347 §4.2.4 / RFC 9147 §5.8.1) so the peer can complete, instead of sitting
        // Established while it retransmits into the void until its handshake budget expires. handshake
        // protection outlives the handshake (closed only in close()), so re-emitting our epoch-2 flight is
        // sound; each retransmit gets fresh record sequence numbers via emit().
        if (peerRetransmitAfterEstablished) {
            val last = lastEstablishedResendAt
            if (last == null || now - last >= INITIAL_RETRANSMIT) {
                lastFlight?.let { flight ->
                    for (item in flight) out += emit(item)
                    lastEstablishedResendAt = now
                }
            }
        }
        // Keep our retransmit timer armed while we are still handshaking with an unacked flight. Every
        // reassembled message calls cancelRetransmit(), so receiving a PARTIAL peer flight (e.g. their
        // Certificate but not yet their Finished — the Finished was lost) leaves us with progress but NO
        // armed timer, and we stop retransmitting our own flight. Without this re-arm a lost final message
        // deadlocks both sides: we go silent, the peer waits. Reset the backoff to the initial interval —
        // receiving new handshake bytes is genuine progress, so retry promptly rather than at a grown delay.
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
        val prot = appProtection
        if (terminal !is DtlsState.Established || prot == null) {
            return DtlsStep(emptyList(), emptyList(), terminal ?: DtlsState.Handshaking)
        }
        val record = prot.seal(applicationData, ContentType.ApplicationData.value, EPOCH_APP, epoch3Seq++)
        return DtlsStep(listOf(record), emptyList(), terminal!!)
    }

    override fun beginClose(now: Instant): DtlsStep {
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

    override fun nextDeadline(now: Instant): Instant? = if (terminal != null) null else retransmitDeadline

    override fun close() {
        ecdhe?.close()
        handshakeProtection?.close()
        appProtection?.close()
    }

    // ── inbound record demux (mixed plaintext epoch-0 + unified-header epoch-2/3 in one datagram) ──

    private fun walkRecords(
        datagram: ReadBuffer,
        out: MutableList<ReadBuffer>,
        appData: MutableList<ReadBuffer>,
        now: Instant,
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
                // A handshake-epoch record arriving after we're Established = the peer retransmitting its
                // flight (it hasn't completed). Flag it (header-only, no decrypt needed) so onDatagram
                // re-sends our lost final flight. Detect BEFORE dispatch: dispatch of an already-seen
                // message dedups to nothing, which is exactly why the deadlock existed.
                if (terminal is DtlsState.Established && epochBits == (EPOCH_HANDSHAKE and 0x3)) {
                    peerRetransmitAfterEstablished = true
                }
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
                    // Same as the epoch-2 case: a plaintext (epoch-0) handshake retransmit after we finished.
                    if (terminal is DtlsState.Established) peerRetransmitAfterEstablished = true
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
        now: Instant,
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
        now: Instant,
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
        now: Instant,
    ) {
        when (message.msgType.value) {
            HandshakeType.ServerHello.value -> {
                val sh = ServerHello.parse(message.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                // A ServerHello whose Random is the HelloRetryRequest sentinel is an HRR, not a real
                // ServerHello — handle the group retry before any key-schedule work (RFC 8446 §4.1.4).
                if (Tls13Bodies.isHelloRetryRandom(sh.random)) return handleHelloRetryRequest(message, sh, out, now)
                val versionExt = sh.extensions.firstOrNull { it.type.value == ExtensionType.SupportedVersions.value }
                if (versionExt == null || Tls13Bodies.selectedVersion(versionExt.body) != ProtocolVersion.Dtls13.value) {
                    // We offered DTLS 1.3 but the peer selected a lower version (checked BEFORE the cipher
                    // suite, so a genuine 1.2 ServerHello is diagnosed as a downgrade, not a cipher mismatch).
                    // RFC 8446 §4.1.3: a 1.3-capable server that negotiates down stamps its Random with the
                    // downgrade sentinel, so its presence means our 1.3 offer was stripped by an attacker.
                    return fail(
                        if (carriesDowngradeSentinel(
                                sh.random,
                            )
                        ) {
                            DtlsFailureReason.DowngradeDetected
                        } else {
                            DtlsFailureReason.HandshakeFailure
                        },
                    )
                }
                if (sh.cipherSuite.value != CipherSuiteId.TlsAes128GcmSha256.value) return fail(DtlsFailureReason.HandshakeFailure)
                val ksExt =
                    sh.extensions.firstOrNull { it.type.value == ExtensionType.KeyShare.value }
                        ?: return fail(DtlsFailureReason.HandshakeFailure)
                val serverShare = Tls13Bodies.parseKeyShareServerHello(ksExt.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                // We offered exactly one group, so a conforming server must echo it (never HRRs). Reject otherwise.
                if (serverShare.group.value != negotiatedGroup.namedGroup.value) return fail(DtlsFailureReason.HandshakeFailure)
                peerPoint = copyOf(serverShare.point)
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
        now: Instant,
    ) {
        val keyShareGroup = negotiatedGroup.namedGroup
        val extensions = mutableListOf<Extension>()
        // Advertise EVERY supported group (the key-shared/preferred one first) but key_share only the
        // preferred group — the browser-matching offer. A server that prefers a later group answers with a
        // HelloRetryRequest for it (handled below); a server that accepts our key_share completes in 1-RTT.
        extensions += Tls13Bodies.supportedGroupsClientHello(offeredGroups(), factory)
        extensions += signatureAlgorithmsExtension()
        extensions += Tls13Bodies.supportedVersionsClientHello(factory)
        extensions += Tls13Bodies.keyShareClientHello(keyShareGroup, ecdhe!!.localPublicPoint, factory)
        // RFC 8446 §4.2.2: the second ClientHello MUST echo any cookie the HelloRetryRequest carried.
        hrrCookie?.let { extensions += Extension(ExtensionType.Cookie, it) }
        val ch =
            buildBody {
                ClientHello(
                    ProtocolVersion.Dtls12, // legacy_version; the real version is in supported_versions
                    localRandom,
                    empty(),
                    empty(), // DTLS 1.3 carries no legacy cookie; return-routability is the cookie extension
                    listOf(CipherSuiteId.TlsAes128GcmSha256),
                    extensions,
                ).bodyInto(it)
            }
        emitFlight(listOf(queueHandshake(HandshakeType.ClientHello, ch, EPOCH_0)), out, now)
    }

    /** Our offered `supported_groups`, preferred (key-shared) group first — the browser-matching order. */
    private fun offeredGroups(): List<NamedGroup> {
        val preferred = negotiatedGroup.namedGroup
        val rest = ALL_GROUPS.filter { it.value != preferred.value }
        return listOf(preferred) + rest
    }

    /**
     * Consume a HelloRetryRequest (RFC 8446 §4.1.4): the server accepted DTLS 1.3 but wants a different
     * (EC)DHE group than we key-shared. Collapse the transcript over ClientHello1 into the synthetic
     * message_hash, adopt the requested group, regenerate our ephemeral key, and re-send a second
     * ClientHello. Exactly one HRR is allowed, and the requested group must be one we offered but did not
     * already key_share — otherwise it is fatal.
     */
    private fun handleHelloRetryRequest(
        message: HandshakeMessage,
        sh: ServerHello,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        if (receivedHrr) return fail(DtlsFailureReason.HandshakeFailure) // a second HRR is illegal
        val versionExt = sh.extensions.firstOrNull { it.type.value == ExtensionType.SupportedVersions.value }
        if (versionExt == null || Tls13Bodies.selectedVersion(versionExt.body) != ProtocolVersion.Dtls13.value) {
            return fail(DtlsFailureReason.HandshakeFailure)
        }
        val ksExt =
            sh.extensions.firstOrNull { it.type.value == ExtensionType.KeyShare.value }
                ?: return fail(DtlsFailureReason.HandshakeFailure)
        val selected = Tls13Bodies.parseKeyShareSelectedGroup(ksExt.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
        val requested = selected.toKeyExchangeGroupOrNull() ?: return fail(DtlsFailureReason.HandshakeFailure)
        // The requested group must be one we advertised, and MUST differ from the one we already key-shared
        // (a HRR for a group we already offered a share for is a protocol error — RFC 8446 §4.1.4).
        if (requested.namedGroup.value == negotiatedGroup.namedGroup.value) return fail(DtlsFailureReason.HandshakeFailure)
        receivedHrr = true
        hrrCookie = sh.extensions.firstOrNull { it.type.value == ExtensionType.Cookie.value }?.let { copyOf(it.body) }
        // Transcript: message_hash(ClientHello1) ‖ HelloRetryRequest ‖ ClientHello2 ‖ … (RFC 8446 §4.4.1).
        transcript.collapseToMessageHash()
        transcript.append(message)
        // Adopt the requested group and regenerate the ephemeral key for its curve.
        ecdhe?.close()
        negotiatedGroup = requested
        ecdhe = EcdheKeyExchange.generate(negotiatedGroup.agreementCurve)
        sendClientHelloFlight(out, now)
    }

    private fun sendClientAuthFlight(
        out: MutableList<ReadBuffer>,
        now: Instant,
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
        now: Instant,
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
                val clientShare = Tls13Bodies.parseKeyShareClientHello(ksExt.body) ?: return fail(DtlsFailureReason.HandshakeFailure)
                // We prefer config.keyExchangeGroup. If the client key-shared a different group but DID
                // advertise our preferred one in supported_groups, ask it to retry with a HelloRetryRequest
                // (RFC 8446 §4.1.4). Only once — a second ClientHello is answered with a real ServerHello.
                if (!sentHrr) {
                    val preferred = config.keyExchangeGroup
                    val sgExt = ch.extensions.firstOrNull { it.type.value == ExtensionType.SupportedGroups.value }
                    val clientOffersPreferred = sgExt != null && Tls13Bodies.supportedGroupsContains(sgExt.body, preferred.namedGroup)
                    if (clientShare.group.value != preferred.namedGroup.value && clientOffersPreferred) {
                        sentHrr = true
                        hrrRequestedGroup = preferred
                        // Transcript over CH1 collapses to message_hash before the HRR (RFC 8446 §4.4.1).
                        transcript.append(message)
                        transcript.collapseToMessageHash()
                        sendHelloRetryRequest(preferred, out, now)
                        return
                    }
                } else {
                    // Second ClientHello after our HRR: it MUST key_share the group we requested.
                    if (clientShare.group.value != hrrRequestedGroup?.namedGroup?.value) return fail(DtlsFailureReason.HandshakeFailure)
                }
                // Adopt whichever supported group the client key-shared (X25519 or P-256) and match its curve.
                negotiatedGroup = clientShare.group.toKeyExchangeGroupOrNull() ?: return fail(DtlsFailureReason.HandshakeFailure)
                peerPoint = copyOf(clientShare.point)
                ecdhe = EcdheKeyExchange.generate(negotiatedGroup.agreementCurve)
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

    /**
     * Emit a HelloRetryRequest (RFC 8446 §4.1.4): a plaintext ServerHello (epoch 0) whose `Random` is the
     * fixed HRR sentinel, carrying `supported_versions` (DTLS 1.3) and a `key_share` naming the group we
     * want. No key schedule runs — the real ServerHello follows the client's retried ClientHello.
     */
    private fun sendHelloRetryRequest(
        group: KeyExchangeGroup,
        out: MutableList<ReadBuffer>,
        now: Instant,
    ) {
        val hrr =
            buildBody {
                ServerHello(
                    ProtocolVersion.Dtls12,
                    Tls13Bodies.helloRetryRandom(factory),
                    empty(),
                    CipherSuiteId.TlsAes128GcmSha256,
                    listOf(
                        Tls13Bodies.supportedVersionsServerHello(factory),
                        Tls13Bodies.keyShareHelloRetryRequest(group.namedGroup, factory),
                    ),
                ).bodyInto(it)
            }
        emitFlight(listOf(queueHandshake(HandshakeType.ServerHello, hrr, EPOCH_0)), out, now)
    }

    private fun sendServerFlight(
        out: MutableList<ReadBuffer>,
        now: Instant,
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
                        Tls13Bodies.keyShareServerHello(negotiatedGroup.namedGroup, ecdhe!!.localPublicPoint, factory),
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
        val ecdheSecret = ecdhe!!.premasterSecret(peerPoint!!)
        val hs =
            try {
                val early = schedule.earlySecret()
                schedule.handshakeSecret(early, ecdheSecret)
            } finally {
                ecdheSecret.freeNativeMemory()
            }
        val thChSh = transcript.currentSha256()
        val cHs = schedule.deriveSecret(hs, Tls13KeySchedule.CLIENT_HANDSHAKE_LABEL, thChSh)
        val sHs = schedule.deriveSecret(hs, Tls13KeySchedule.SERVER_HANDSHAKE_LABEL, thChSh)
        val local = if (client) cHs else sHs
        val peer = if (client) sHs else cHs
        val protection = Dtls13RecordProtection.fromTrafficSecrets(schedule, local, peer, factory)
        keys = Keys.Handshake(schedule.masterSecret(hs), cHs, sHs, protection)
    }

    private fun deriveApplicationSecrets() {
        val hk = handshakeKeys ?: return
        if (keys is Keys.Application) return
        val thChSFin = transcript.currentSha256()
        val cAp = schedule.deriveSecret(hk.master, Tls13KeySchedule.CLIENT_APPLICATION_LABEL, thChSFin)
        val sAp = schedule.deriveSecret(hk.master, Tls13KeySchedule.SERVER_APPLICATION_LABEL, thChSFin)
        // The exporter_master_secret is bound to the SAME transcript point (CH…server Finished, RFC 8446 §7.5).
        val exporterMaster = schedule.exporterMasterSecret(hk.master, thChSFin)
        val client = role == DtlsRole.Client
        val local = if (client) cAp else sAp
        val peer = if (client) sAp else cAp
        val protection = Dtls13RecordProtection.fromTrafficSecrets(schedule, local, peer, factory)
        keys = Keys.Application(hk, protection, exporterMaster)
    }

    override fun exportKeyingMaterial(
        label: String,
        context: ReadBuffer?,
        length: Int,
    ): ReadBuffer? {
        if (terminal !is DtlsState.Established) return null
        val exporterMaster = (keys as? Keys.Application)?.exporterMaster ?: return null
        return schedule.exportKeyingMaterial(exporterMaster, label, context, length)
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
        now: Instant,
    ) {
        for (item in flight) out += emit(item)
        lastFlight = flight
        retransmitBackoff = INITIAL_RETRANSMIT
        retransmitDeadline = now + retransmitBackoff
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

    // ── downgrade protection (RFC 8446 §4.1.3) ─────────────────────────────────────────────────────

    /** True if the last 8 bytes of a ServerHello [random] are a TLS-1.3 downgrade sentinel (`DOWNGRD\x01`/`\x00`). */
    private fun carriesDowngradeSentinel(random: ReadBuffer): Boolean {
        if (random.remaining() != RANDOM_BYTES) return false
        val base = random.position() + RANDOM_BYTES - DOWNGRADE_SENTINEL_PREFIX.size - 1
        for (i in DOWNGRADE_SENTINEL_PREFIX.indices) {
            if (random.u8(base + i) != DOWNGRADE_SENTINEL_PREFIX[i]) return false
        }
        val last = random.u8(base + DOWNGRADE_SENTINEL_PREFIX.size)
        return last == 0x01 || last == 0x00
    }

    // ── (EC)DHE group ⇄ wire NamedGroup / buffer-crypto curve mapping ──────────────────────────────

    private val KeyExchangeGroup.namedGroup: NamedGroup
        get() =
            when (this) {
                KeyExchangeGroup.X25519 -> NamedGroup.X25519
                KeyExchangeGroup.Secp256r1 -> NamedGroup.Secp256r1
            }

    private val KeyExchangeGroup.agreementCurve: KeyAgreementCurve
        get() =
            when (this) {
                KeyExchangeGroup.X25519 -> KeyAgreementCurve.X25519
                KeyExchangeGroup.Secp256r1 -> KeyAgreementCurve.P256
            }

    /** The negotiable group for a supported wire [NamedGroup] (used by the server on the ClientHello), or null. */
    private fun NamedGroup.toKeyExchangeGroupOrNull(): KeyExchangeGroup? =
        when (value) {
            NamedGroup.X25519.value -> KeyExchangeGroup.X25519
            NamedGroup.Secp256r1.value -> KeyExchangeGroup.Secp256r1
            else -> null
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
        val INITIAL_RETRANSMIT = 1.seconds // RFC 6347/9147 initial retransmit timer
        val MAX_RETRANSMIT = 60.seconds
        const val SERVER_CONTEXT = "TLS 1.3, server CertificateVerify"
        const val CLIENT_CONTEXT = "TLS 1.3, client CertificateVerify"

        // Every (EC)DHE group this stack offers, in preference order (X25519 first, browser-matching). The
        // client lists all of these in supported_groups; the key_share carries only the configured group.
        val ALL_GROUPS: List<NamedGroup> = listOf(NamedGroup.X25519, NamedGroup.Secp256r1)

        // "DOWNGRD" — the fixed prefix of the RFC 8446 §4.1.3 downgrade sentinel; the final byte is 0x01
        // (server negotiated TLS/DTLS 1.2) or 0x00 (≤ 1.1). Modelled as a List (no primitive array, directive #1).
        val DOWNGRADE_SENTINEL_PREFIX: List<Int> = listOf(0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44)
    }
}
