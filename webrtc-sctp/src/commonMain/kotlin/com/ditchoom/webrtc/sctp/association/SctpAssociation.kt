@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.ErrorCauseCode
import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpErrorCause
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **sans-io SCTP association** (RFC 4960 subset per RFC 8831 / RFC §11.2 — dcSCTP-style: one path,
 * no multihoming, no stream interleaving) — a pure `handle(event, now): List<Output>` plus
 * [nextDeadline], with **no dispatcher, clock, RNG, or I/O inside** (RFC §5.1). It owns the four-way
 * handshake, TSN assignment, SACK-driven reliability, RTO/congestion control, fragmentation and
 * ordered/unordered reassembly, RFC 3758 partial reliability, and graceful/abort shutdown. The driver
 * ([SctpEvent.DatagramReceived] in over the DTLS transport, [SctpOutput.Transmit] out) owns all I/O; the
 * same machine therefore establishes and drains a full session under `runTest` virtual time on every
 * platform.
 *
 * Entropy is injected once ([random], directive #2): it seeds the Verification Tag and the initial TSN,
 * so a scenario replays bit-for-bit. Production wires `CryptoRandom`; tests wire a seeded [Random].
 *
 * **Path liveness** is intentionally delegated, not duplicated: this subset sends no SCTP HEARTBEATs, so
 * an association with no outstanding data does not itself detect a silently-dead peer. In WebRTC that is
 * covered a layer down by ICE consent freshness (RFC 7675, W3), which tears down the transport on a dead
 * path and thereby closes the association — so a redundant SCTP heartbeat timer is deliberately omitted.
 */
public class SctpAssociation(
    private val config: SctpConfig = SctpConfig(),
    @Suppress("UnseamedEntropy") private val random: Random = Random.Default,
    private val localPort: UShort = SCTP_DATA_CHANNEL_PORT,
    private val remotePort: UShort = SCTP_DATA_CHANNEL_PORT,
) {
    private var _state: SctpAssociationState = SctpAssociationState.Closed

    /** The current lifecycle phase (RFC 4960 §4). */
    public val state: SctpAssociationState get() = _state

    // ── Association control block (populated as the handshake completes) ──
    // Visibility is `internal` (not public — absent from the .api) purely so regression fixtures can
    // craft packets carrying the correct tags; the setters stay private.
    internal var localVerificationTag: VerificationTag = VerificationTag(0u) // tag the peer must echo to us
        private set
    internal var peerVerificationTag: VerificationTag = VerificationTag(0u) // tag we stamp on packets to the peer
        private set
    private var localInitialTsn: Tsn = Tsn(0u)
    private var nextTsn: Tsn = Tsn(0u)
    private var peerSupportsForwardTsn: Boolean = false

    private val orderedSendSsn = HashMap<StreamId, Int>()
    private val pendingSend = ArrayDeque<OutstandingData>()

    // User-data bytes accepted by send() but not yet handed to the wire — i.e. the depth of [pendingSend].
    // Tracked as a running counter rather than summed on demand: this is read once per drive-loop item, and
    // walking the deque there would make a full send buffer quadratic in the number of queued fragments.
    //
    // INTERNAL, deliberately. This is the truth the *driver* needs to apply backpressure (see
    // SctpDataChannelStack), not a consumer-facing `bufferedAmount` — the data-channel API stays
    // suspend-only, so nothing above this module observes a byte count.
    private var pendingSendBytes: Int = 0

    /** Bytes queued for transmission but not yet sent — the driver's backpressure signal. */
    internal val bufferedBytes: Int get() = pendingSendBytes

    private var retransmissionQueue: RetransmissionQueue? = null
    private var reassemblyQueue: ReassemblyQueue? = null
    private var congestion: CongestionControl? = null
    private val rtt = RttEstimator(config)

    // Retained handshake artifacts (rebuilt-identical retransmits).
    private var localInit: SctpChunk.Init? = null
    private var cookieEcho: SctpChunk.CookieEcho? = null

    // ── Timers as absolute deadlines (RFC §5.1: nextDeadline is the whole clock contract) ──
    private var handshakeDeadline: Instant? = null
    private var handshakeRetransmits = 0
    private var t3Deadline: Instant? = null
    private var sackDeadline: Instant? = null
    private var shutdownDeadline: Instant? = null
    private var shutdownRetransmits = 0
    private var consecutiveRtxErrors = 0
    private var packetsSinceSack = 0

    /**
     * The earliest armed timer's deadline, or null when no timer is armed (RFC §5.1). The driver waits
     * until here, then feeds [SctpEvent.TimerFired]; every due timer fires in that one call.
     */
    public fun nextDeadline(now: Instant): Instant? =
        listOfNotNull(handshakeDeadline, t3Deadline, sackDeadline, shutdownDeadline).minOrNull()

    /** Feed one event; returns the side effects for the driver to apply (RFC §5.1). Never throws. */
    public fun handle(
        event: SctpEvent,
        now: Instant,
    ): List<SctpOutput> {
        val out = ArrayList<SctpOutput>()
        when (event) {
            SctpEvent.Associate -> onAssociate(now, out)
            is SctpEvent.DatagramReceived -> onDatagram(event.payload, now, out)
            is SctpEvent.SendMessage -> onSendMessage(event, now, out)
            SctpEvent.Shutdown -> onShutdownRequested(now, out)
            SctpEvent.Abort -> onAbortRequested(out)
            SctpEvent.TimerFired -> onTimers(now, out)
        }
        return out
    }

    // ────────────────────────────────── handshake ──────────────────────────────────

    private fun onAssociate(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (_state != SctpAssociationState.Closed) return
        localVerificationTag = randomTag()
        localInitialTsn = randomTsn()
        nextTsn = localInitialTsn
        val init =
            SctpChunk.Init(
                initiateTag = localVerificationTag,
                advertisedReceiverWindow = config.receiveWindowBytes,
                outboundStreams = config.outboundStreams,
                inboundStreams = config.inboundStreams,
                initialTsn = localInitialTsn,
                parameters =
                    listOf(
                        SctpParameter.forwardTsnSupported(),
                        SctpParameter.supportedExtensions(listOf(com.ditchoom.webrtc.sctp.SctpChunkType.ForwardTsn)),
                    ),
            )
        localInit = init
        emitPacket(listOf(init), VerificationTag(0u), out)
        transition(SctpAssociationState.CookieWait, out)
        handshakeRetransmits = 0
        armHandshake(now)
    }

    private fun onInit(
        init: SctpChunk.Init,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (init.outboundStreams == 0u.toUShort() || init.inboundStreams == 0u.toUShort()) {
            abortWith(SctpFailureReason.ProtocolViolation(ProtocolViolationKind.ZeroStreams), reflectTag = init.initiateTag, out)
            return
        }
        val advertised =
            when (val response = initResponse()) {
                // RFC 4960 §9.2: an INIT while we are SHUTDOWN-ACK-SENT is not a new association — our
                // SHUTDOWN COMPLETE was lost. Discard the INIT and retransmit the SHUTDOWN ACK.
                InitResponse.ResendShutdownAck -> {
                    emitPacket(listOf(SctpChunk.ShutdownAck), peerVerificationTag, out)
                    return
                }
                is InitResponse.Advertise -> response
            }
        val cookie =
            encodeCookie(
                StateCookie(
                    magic = StateCookie.MAGIC,
                    peerTag = init.initiateTag,
                    peerInitialTsn = init.initialTsn,
                    peerRwnd = init.advertisedReceiverWindow,
                    peerForwardTsn = init.supportsForwardTsn(),
                    ourTag = advertised.ourTag,
                    ourInitialTsn = advertised.ourInitialTsn,
                    localTieTag = advertised.localTieTag,
                    peerTieTag = advertised.peerTieTag,
                ),
            )
        val initAck =
            SctpChunk.InitAck(
                initiateTag = advertised.ourTag,
                advertisedReceiverWindow = config.receiveWindowBytes,
                outboundStreams = config.outboundStreams,
                inboundStreams = config.inboundStreams,
                initialTsn = advertised.ourInitialTsn,
                parameters =
                    listOf(
                        SctpParameter.ofValue(com.ditchoom.webrtc.sctp.ParameterType.StateCookie, cookie),
                        SctpParameter.forwardTsnSupported(),
                        SctpParameter.supportedExtensions(listOf(com.ditchoom.webrtc.sctp.SctpChunkType.ForwardTsn)),
                    ),
            )
        emitPacket(listOf(initAck), init.initiateTag, out)
        // "the existing association, including its current state, and the corresponding TCB MUST NOT be
        // changed" (§5.2.1 / §5.2.2) — nothing above touches state, and the T1-init timer keeps running.
    }

    /** What an inbound INIT is answered with. A phase decides it, so it is a type, not a pair of flags. */
    private sealed interface InitResponse {
        /** RFC 4960 §9.2 — SHUTDOWN-ACK-SENT: the peer missed our SHUTDOWN COMPLETE, so repeat the ACK. */
        data object ResendShutdownAck : InitResponse

        /** The TCB the INIT ACK advertises, plus the Tie-Tags its State Cookie carries. */
        data class Advertise(
            val ourTag: VerificationTag,
            val ourInitialTsn: Tsn,
            val localTieTag: VerificationTag,
            val peerTieTag: VerificationTag,
        ) : InitResponse
    }

    /**
     * Which TCB to advertise in an INIT ACK, decided by an exhaustive `when` over the phase (RFC 4960
     * §5.2.1, §5.2.2, §9.2). Three genuinely different answers hide behind "respond to an INIT":
     *
     * - **Closed** — no TCB. Mint a tag and TSN and bake the whole thing into the State Cookie; nothing
     *   is retained until the COOKIE ECHO returns (§5.1.3, the stateless-responder mechanism). The
     *   Tie-Tags stay zero, which is the cookie saying "no previous TCB existed" (§5.2.2 note).
     * - **COOKIE-WAIT / COOKIE-ECHOED** — an initialization collision (§5.2.1), which is now the norm
     *   rather than the exception since both roles associate (see SctpDataChannelStack). The INIT ACK
     *   MUST repeat the Initiate Tag and initial TSN of *our own* INIT. Minting fresh ones instead is
     *   exactly what deadlocks a collision: the peer echoes a cookie naming a tag we no longer stamp on
     *   our packets, so each side's COOKIE ECHO fails the other's Verification Tag check and both
     *   handshakes time out with nothing on the wire to explain it. Tie-Tags are populated in
     *   COOKIE-ECHOED only (§5.2.1 last paragraph, and the §5.2.2 note excluding COOKIE-WAIT).
     * - **Established / shutting down** — an unexpected INIT while a TCB exists (§5.2.2): the INIT ACK
     *   MUST carry a *new* random Initiate Tag, and the Tie-Tags carry the tags of the association we
     *   keep running. That pairing — new tags, Tie-Tags naming the live association — is precisely what
     *   lets the returning COOKIE ECHO be recognised as a peer restart in §5.2.4's Table 2.
     */
    private fun initResponse(): InitResponse =
        when (_state) {
            SctpAssociationState.Closed ->
                InitResponse.Advertise(randomTag(), randomTsn(), ZERO_TAG, ZERO_TAG)
            SctpAssociationState.CookieWait ->
                InitResponse.Advertise(localVerificationTag, localInitialTsn, ZERO_TAG, ZERO_TAG)
            SctpAssociationState.CookieEchoed ->
                InitResponse.Advertise(localVerificationTag, localInitialTsn, localVerificationTag, peerVerificationTag)
            SctpAssociationState.Established,
            SctpAssociationState.ShutdownPending,
            SctpAssociationState.ShutdownSent,
            SctpAssociationState.ShutdownReceived,
            -> InitResponse.Advertise(randomTag(), randomTsn(), localVerificationTag, peerVerificationTag)
            SctpAssociationState.ShutdownAckSent -> InitResponse.ResendShutdownAck
        }

    private fun onInitAck(
        initAck: SctpChunk.InitAck,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (_state != SctpAssociationState.CookieWait) return
        val cookieParam = initAck.stateCookie()
        if (cookieParam == null) {
            abortWith(SctpFailureReason.ProtocolViolation(ProtocolViolationKind.MissingStateCookie), reflectTag = initAck.initiateTag, out)
            return
        }
        peerVerificationTag = initAck.initiateTag
        peerSupportsForwardTsn = initAck.parameters.any { it.type == com.ditchoom.webrtc.sctp.ParameterType.ForwardTsnSupported }
        establishControlBlocks(peerInitialTsn = initAck.initialTsn, peerRwnd = initAck.advertisedReceiverWindow)
        val echo = SctpChunk.CookieEcho(copyOf(cookieParam.value))
        cookieEcho = echo
        emitPacket(listOf(echo), peerVerificationTag, out)
        transition(SctpAssociationState.CookieEchoed, out)
        handshakeRetransmits = 0
        armHandshake(now)
    }

    private fun onCookieEcho(
        echo: SctpChunk.CookieEcho,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val cookie = decodeCookie(echo.cookie) ?: return // silently drop a cookie we did not mint (RFC 4960 §5.1.5)
        // No TCB yet: the ordinary passive open (RFC 4960 §5.1.5) — unpack the cookie and come up.
        if (_state == SctpAssociationState.Closed) {
            adoptCookie(cookie, now, out)
            return
        }
        // A TCB exists, so RFC 4960 §5.2.4's Table 2 decides — see [CookieEchoAction].
        when (cookieEchoAction(cookie)) {
            CookieEchoAction.Restart -> onPeerRestart(cookie, now, out)
            CookieEchoAction.Collision ->
                if (_state == SctpAssociationState.Established) {
                    // Established already: take only the peer's new tag. Re-deriving TSNs and queues
                    // underneath a live association would strand data that is already in flight.
                    peerVerificationTag = cookie.peerTag
                    emitPacket(listOf(SctpChunk.CookieAck), peerVerificationTag, out)
                } else {
                    adoptCookie(cookie, now, out)
                }
            CookieEchoAction.Complete -> {
                // Duplicate/late-but-valid cookie for the association we already have (action D, and the
                // retransmit case where our COOKIE ACK was lost). Ack it and finish the handshake.
                emitPacket(listOf(SctpChunk.CookieAck), peerVerificationTag, out)
                if (_state == SctpAssociationState.CookieEchoed) {
                    transition(SctpAssociationState.Established, out)
                    cancelHandshake()
                    cookieEcho = null
                    trySend(now, out)
                }
            }
            // Actions C and "any case not shown in Table 2": discard the cookie, change no state, and
            // leave every timer running.
            CookieEchoAction.Discard -> Unit
        }
    }

    /**
     * The action RFC 4960 §5.2.4 Table 2 prescribes for a COOKIE ECHO that arrives when a TCB already
     * exists. The row is chosen by how the cookie's two tags and two Tie-Tags compare with the live TCB.
     */
    private enum class CookieEchoAction {
        /** (A) `X X M M` — new tags, but Tie-Tags naming our live association: the peer restarted. */
        Restart,

        /** (B) `M X` / `M 0` — an initialization collision; adopt the peer's Verification Tag. */
        Collision,

        /** (D) `M M` — the cookie describes the association we already have; ack and finish. */
        Complete,

        /** (C) `X M 0 0` — our own cookie arrived late — and every combination the table omits. */
        Discard,
    }

    /** How one tag in a returning cookie relates to the live TCB — the `M` / `X` / `0` of Table 2. */
    private enum class TagMatch { Matches, Differs, Absent }

    private fun match(
        inCookie: VerificationTag,
        inTcb: VerificationTag,
    ): TagMatch =
        when {
            inCookie == ZERO_TAG -> TagMatch.Absent
            inCookie == inTcb -> TagMatch.Matches
            else -> TagMatch.Differs
        }

    private fun cookieEchoAction(cookie: StateCookie): CookieEchoAction {
        val local = match(cookie.ourTag, localVerificationTag)
        val peer = match(cookie.peerTag, peerVerificationTag)
        val tieTags = match(cookie.localTieTag, localVerificationTag) to match(cookie.peerTieTag, peerVerificationTag)
        return when {
            // | Local | Peer | Local-Tie | Peer-Tie | Action |
            // |   M   |  M   |     A     |    A     |  (D)   |
            local == TagMatch.Matches && peer == TagMatch.Matches -> CookieEchoAction.Complete
            // |   M   |  X   |     A     |    A     |  (B)   |   and   |  M  |  0  |  A  |  A  |  (B)  |
            local == TagMatch.Matches -> CookieEchoAction.Collision
            // |   X   |  X   |     M     |    M     |  (A)   |
            local == TagMatch.Differs &&
                peer == TagMatch.Differs &&
                tieTags == (TagMatch.Matches to TagMatch.Matches) -> CookieEchoAction.Restart
            // |   X   |  M   |     0     |    0     |  (C)   |  — and "any case not shown".
            else -> CookieEchoAction.Discard
        }
    }

    /**
     * RFC 4960 §5.2.4 action A — the peer restarted and is opening a brand-new association over the same
     * transport. "The existing session is treated the same as if it received an ABORT followed by a new
     * COOKIE ECHO": every stream, TSN and congestion variable resets to its initial value, and the upper
     * layer is told this was a RESTART rather than a lost association ([SctpOutput.PeerRestarted]) — the
     * data channels it had open are gone, because the peer no longer knows about them.
     */
    private fun onPeerRestart(
        cookie: StateCookie,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        // "If the endpoint is in the SHUTDOWN-ACK-SENT state and recognizes that the peer has restarted,
        // it MUST NOT set up a new association but instead resend the SHUTDOWN ACK and send an ERROR."
        if (_state == SctpAssociationState.ShutdownAckSent) {
            emitPacket(
                listOf(
                    SctpChunk.ShutdownAck,
                    SctpChunk.Error(listOf(SctpErrorCause.empty(ErrorCauseCode.CookieReceivedWhileShuttingDown))),
                ),
                peerVerificationTag,
                out,
            )
            return
        }
        clearControlBlocks() // drop the old association's queues, stream state and unsent messages
        cancelAllTimers()
        consecutiveRtxErrors = 0
        packetsSinceSack = 0
        // Adopt first, notify second: the COOKIE ACK is queued before the driver acts on the
        // notification, so the peer's handshake completes even when the driver tears its channels down.
        adoptCookie(cookie, now, out)
        out += SctpOutput.PeerRestarted
    }

    /** Bring the association up on the TCB carried by [cookie], and acknowledge it. */
    private fun adoptCookie(
        cookie: StateCookie,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        localVerificationTag = cookie.ourTag
        localInitialTsn = cookie.ourInitialTsn
        nextTsn = cookie.ourInitialTsn
        peerVerificationTag = cookie.peerTag
        peerSupportsForwardTsn = cookie.peerForwardTsn
        establishControlBlocks(peerInitialTsn = cookie.peerInitialTsn, peerRwnd = cookie.peerRwnd)
        emitPacket(listOf(SctpChunk.CookieAck), peerVerificationTag, out)
        transition(SctpAssociationState.Established, out)
        cancelHandshake()
        cookieEcho = null
        trySend(now, out)
    }

    private fun onCookieAck(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (_state != SctpAssociationState.CookieEchoed) return
        transition(SctpAssociationState.Established, out)
        cancelHandshake()
        cookieEcho = null
        trySend(now, out)
    }

    private fun establishControlBlocks(
        peerInitialTsn: Tsn,
        peerRwnd: UInt,
    ) {
        retransmissionQueue = RetransmissionQueue(config, localInitialTsn)
        reassemblyQueue = ReassemblyQueue(peerInitialTsn, config)
        congestion = CongestionControl(config, peerRwnd)
        retransmissionQueue!!.setPeerReceiveWindow(peerRwnd)
    }

    // ────────────────────────────────── receive path ──────────────────────────────────

    private fun onDatagram(
        payload: ReadBuffer,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val packet = (SctpPacket.decode(payload) as? SctpDecodeResult.Success)?.packet ?: return
        // Integrity: over DTLS the transport authenticates, but the SCTP CRC32c is still on the wire —
        // a mismatch is a corrupt datagram we drop (T0: never a throw).
        if (!packet.verifyChecksum()) return
        if (!verificationTagOk(packet)) return

        // A SACK is owed for any chunk that advances the receiver's cumulative TSN — DATA *or* a
        // FORWARD-TSN (RFC 3758 §3.6 requires an immediate SACK in reply to FORWARD-TSN, even when it
        // rides alone with no bundled DATA; otherwise the peer's advanced-ack point is never confirmed).
        var sackOwed = false
        for (chunk in packet.chunks) {
            when (chunk) {
                is SctpChunk.Init -> onInit(chunk, now, out)
                is SctpChunk.InitAck -> onInitAck(chunk, now, out)
                is SctpChunk.CookieEcho -> onCookieEcho(chunk, now, out)
                SctpChunk.CookieAck -> onCookieAck(now, out)
                is SctpChunk.Data -> {
                    sackOwed = true
                    onData(chunk, out)
                }
                is SctpChunk.Sack -> onSack(chunk, now, out)
                is SctpChunk.ForwardTsn -> {
                    sackOwed = true
                    onForwardTsn(chunk, out)
                }
                is SctpChunk.Heartbeat -> emitPacket(listOf(SctpChunk.HeartbeatAck(chunk.info)), peerVerificationTag, out)
                is SctpChunk.HeartbeatAck -> Unit
                is SctpChunk.Abort -> {
                    fail(SctpFailureReason.AbortReceived, out)
                    return
                }
                is SctpChunk.Shutdown -> onShutdown(chunk, now, out)
                SctpChunk.ShutdownAck -> onShutdownAck(out)
                is SctpChunk.ShutdownComplete -> onShutdownComplete(out)
                is SctpChunk.Error -> Unit
                is SctpChunk.Unrecognized -> Unit
            }
        }
        if (sackOwed) maybeSack(now, out)
    }

    private fun onData(
        chunk: SctpChunk.Data,
        out: MutableList<SctpOutput>,
    ) {
        val reassembly = reassemblyQueue ?: return
        for (message in reassembly.receive(chunk)) {
            out += SctpOutput.MessageReceived(message.streamId, message.ppid, message.unordered, message.payload)
        }
    }

    private fun onSack(
        sack: SctpChunk.Sack,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = retransmissionQueue ?: return
        val cc = congestion ?: return
        val wasCwndLimited = rq.outstandingBytes >= cc.cwnd
        val gapsAbsolute =
            sack.gapAckBlocks.map { block ->
                Tsn(sack.cumulativeTsnAck.value + block.start.toUInt()) to Tsn(sack.cumulativeTsnAck.value + block.end.toUInt())
            }
        val outcome = rq.onSack(sack.cumulativeTsnAck, sack.advertisedReceiverWindow, gapsAbsolute, now)
        if (outcome.rttSample != null) rtt.observe(outcome.rttSample)
        cc.onDataAcked(outcome.bytesNewlyAcked, wasCwndLimited)
        if (outcome.fastRetransmitTriggered) cc.onFastRetransmit()
        if (outcome.cumulativeAdvanced) consecutiveRtxErrors = 0

        if (outcome.allDataAcknowledged) {
            t3Deadline = null
        } else if (outcome.cumulativeAdvanced) {
            t3Deadline = now + rtt.rto
        }
        // RFC 3758: expiry is also checked here, not only on T3 — a partially-reliable message can spend
        // its retransmit/lifetime budget while OTHER data keeps advancing the cum ack (so T3 is
        // perpetually restarted and never fires); without this it would be fast-retransmitted forever
        // instead of being abandoned and skipped via FORWARD-TSN.
        abandonExpired(now, out)
        trySend(now, out)
        maybeCompleteShutdown(now, out)
    }

    private fun onForwardTsn(
        chunk: SctpChunk.ForwardTsn,
        out: MutableList<SctpOutput>,
    ) {
        val reassembly = reassemblyQueue ?: return
        for (message in reassembly.onForwardTsn(chunk.newCumulativeTsn, chunk.streams)) {
            out += SctpOutput.MessageReceived(message.streamId, message.ppid, message.unordered, message.payload)
        }
    }

    // ────────────────────────────────── send path ──────────────────────────────────

    private fun onSendMessage(
        event: SctpEvent.SendMessage,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (_state != SctpAssociationState.Established) return
        val options = event.options
        val fragments = fragment(event.payload)
        val ssn: StreamSequenceNumber =
            if (options.delivery == DeliveryOrder.Unordered) {
                StreamSequenceNumber(0u)
            } else {
                val current = orderedSendSsn[options.streamId] ?: 0
                orderedSendSsn[options.streamId] = current + 1
                StreamSequenceNumber(current.toUShort())
            }
        for ((index, fragmentPayload) in fragments.withIndex()) {
            val beginning = index == 0
            val ending = index == fragments.lastIndex
            val flags =
                DataChunkFlags.of(beginning = beginning, ending = ending, unordered = options.delivery == DeliveryOrder.Unordered)
            // Encode the whole packet now, while the caller's payload is still borrowed-valid: this single
            // copy into the datagram *is* the owned copy the retransmission queue needs (directive #6), so
            // the fragment views above never have to be materialized into buffers of their own.
            val chunk =
                SctpChunk.Data(
                    flags = flags,
                    tsn = nextTsn,
                    streamId = options.streamId,
                    streamSequenceNumber = ssn,
                    payloadProtocolId = options.payloadProtocolId,
                    userData = fragmentPayload,
                )
            val data =
                OutstandingData(
                    tsn = nextTsn,
                    streamId = options.streamId,
                    ssn = ssn,
                    flags = flags,
                    bytes = fragmentPayload.remaining(),
                    packet = encodePacket(listOf(chunk), peerVerificationTag),
                    reliability = options.reliability,
                    firstSentAt = now,
                )
            pendingSend.addLast(data)
            pendingSendBytes += data.bytes
            nextTsn = nextTsn.next()
        }
        trySend(now, out)
    }

    // The RFC 4960 §6.1 send routine: flush retransmits first, then new data while cwnd and the peer
    // receive window allow, arming the T3-rtx timer whenever data is outstanding.
    private fun trySend(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = retransmissionQueue ?: return
        val cc = congestion ?: return

        // Retransmit the lost flight, but PACED BY cwnd (RFC 4960 §6.3.3 E3): after a T3 collapse to one
        // MTU we must not dump 100 outstanding chunks back onto the wire at once. Always send at least the
        // earliest one (flight size is 0 right after a T3 marked everything for retransmit); the remainder
        // stays NeedsRetransmit and goes out on the next SACK/timer as cwnd re-opens.
        for (data in rq.retransmittable()) {
            if (rq.outstandingBytes > 0 && rq.outstandingBytes + data.bytes > cc.cwnd) break
            rq.markRetransmitted(data, now)
            out += SctpOutput.Transmit(data.wirePacket())
        }

        while (pendingSend.isNotEmpty()) {
            val next = pendingSend.first()
            val projected = rq.outstandingBytes + next.bytes
            val cwndOk = projected <= cc.cwnd
            val zeroWindowProbe = rq.peerReceiveWindow == 0u && rq.outstandingBytes == 0
            val rwndOk = projected.toUInt() <= rq.peerReceiveWindow || zeroWindowProbe
            if (!cwndOk || !rwndOk) break
            pendingSend.removeFirst()
            pendingSendBytes -= next.bytes
            next.lastSentAt = now
            rq.onSent(next)
            out += SctpOutput.Transmit(next.wirePacket())
        }

        if (rq.outstandingBytes > 0 && t3Deadline == null) t3Deadline = now + rtt.rto
    }

    // ────────────────────────────────── SACK scheduling ──────────────────────────────────

    private fun maybeSack(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val reassembly = reassemblyQueue ?: return
        packetsSinceSack += 1
        // RFC 4960 §6.2: SACK on every second packet, or immediately on out-of-order / duplicate data.
        if (reassembly.sackImmediatelyRequested || packetsSinceSack >= SACK_EVERY) {
            emitSack(out)
        } else if (sackDeadline == null) {
            sackDeadline = now + config.sackDelay
        }
    }

    private fun emitSack(out: MutableList<SctpOutput>) {
        val reassembly = reassemblyQueue ?: return
        emitPacket(listOf(reassembly.buildSack()), peerVerificationTag, out)
        packetsSinceSack = 0
        sackDeadline = null
    }

    // ────────────────────────────────── shutdown ──────────────────────────────────

    private fun onShutdownRequested(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (_state != SctpAssociationState.Established) return
        transition(SctpAssociationState.ShutdownPending, out)
        maybeCompleteShutdown(now, out)
    }

    private fun maybeCompleteShutdown(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = retransmissionQueue ?: return
        val reassembly = reassemblyQueue ?: return
        val drained = rq.isEmpty && pendingSend.isEmpty()
        when (_state) {
            SctpAssociationState.ShutdownPending ->
                if (drained) {
                    emitPacket(listOf(SctpChunk.Shutdown(reassembly.cumulativeTsn)), peerVerificationTag, out)
                    transition(SctpAssociationState.ShutdownSent, out)
                    armShutdown(now)
                }
            SctpAssociationState.ShutdownReceived ->
                if (drained) {
                    emitPacket(listOf(SctpChunk.ShutdownAck), peerVerificationTag, out)
                    transition(SctpAssociationState.ShutdownAckSent, out)
                    armShutdown(now)
                }
            else -> Unit
        }
    }

    private fun onShutdown(
        shutdown: SctpChunk.Shutdown,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = retransmissionQueue ?: return
        // The SHUTDOWN carries a cumulative TSN ack for our outbound data — process it like a SACK.
        rq.onSack(shutdown.cumulativeTsnAck, rq.peerReceiveWindow, emptyList(), now)
        if (_state == SctpAssociationState.Established || _state == SctpAssociationState.ShutdownPending) {
            transition(SctpAssociationState.ShutdownReceived, out)
        }
        maybeCompleteShutdown(now, out)
    }

    private fun onShutdownAck(out: MutableList<SctpOutput>) {
        if (_state != SctpAssociationState.ShutdownSent && _state != SctpAssociationState.ShutdownAckSent) return
        emitPacket(listOf(SctpChunk.ShutdownComplete(verificationTagReflected = false)), peerVerificationTag, out)
        closeGracefully(out)
    }

    private fun onShutdownComplete(out: MutableList<SctpOutput>) {
        if (_state != SctpAssociationState.ShutdownAckSent) return
        closeGracefully(out)
    }

    private fun onAbortRequested(out: MutableList<SctpOutput>) {
        if (retransmissionQueue == null && _state == SctpAssociationState.Closed) return
        emitPacket(listOf(SctpChunk.Abort(verificationTagReflected = false, causes = emptyList())), peerVerificationTag, out)
        transition(SctpAssociationState.Closed, out)
        clearControlBlocks()
    }

    private fun closeGracefully(out: MutableList<SctpOutput>) {
        transition(SctpAssociationState.Closed, out)
        cancelAllTimers()
        clearControlBlocks()
    }

    // ────────────────────────────────── timers ──────────────────────────────────

    private fun onTimers(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        handshakeDeadline?.let { if (now >= it) onHandshakeTimeout(now, out) }
        t3Deadline?.let { if (now >= it) onT3Timeout(now, out) }
        sackDeadline?.let { if (now >= it) emitSack(out) }
        shutdownDeadline?.let { if (now >= it) onShutdownTimeout(now, out) }
    }

    private fun onHandshakeTimeout(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        handshakeRetransmits += 1
        if (handshakeRetransmits > config.maxInitRetransmits) {
            fail(SctpFailureReason.HandshakeTimeout, out)
            return
        }
        rtt.backoff()
        when (_state) {
            SctpAssociationState.CookieWait -> localInit?.let { emitPacket(listOf(it), VerificationTag(0u), out) }
            SctpAssociationState.CookieEchoed -> cookieEcho?.let { emitPacket(listOf(it), peerVerificationTag, out) }
            else -> return
        }
        armHandshake(now)
    }

    private fun onT3Timeout(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq =
            retransmissionQueue ?: run {
                t3Deadline = null
                return
            }
        val cc =
            congestion ?: run {
                t3Deadline = null
                return
            }
        val hadOutstanding = rq.onT3Timeout()
        if (!hadOutstanding) {
            t3Deadline = null
            return
        }
        cc.onTimeout()
        rtt.backoff()
        consecutiveRtxErrors += 1
        if (consecutiveRtxErrors > config.maxAssociationRetransmits) {
            fail(SctpFailureReason.RetransmissionLimitReached, out)
            return
        }
        // RFC 3758: abandon partially-reliable chunks past their budget before retransmitting.
        abandonExpired(now, out)
        trySend(now, out)
        t3Deadline = now + rtt.rto
    }

    private fun onShutdownTimeout(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        shutdownRetransmits += 1
        if (shutdownRetransmits > config.maxShutdownRetransmits) {
            fail(SctpFailureReason.RetransmissionLimitReached, out)
            return
        }
        val reassembly = reassemblyQueue
        when (_state) {
            SctpAssociationState.ShutdownSent ->
                if (reassembly != null) emitPacket(listOf(SctpChunk.Shutdown(reassembly.cumulativeTsn)), peerVerificationTag, out)
            SctpAssociationState.ShutdownAckSent -> emitPacket(listOf(SctpChunk.ShutdownAck), peerVerificationTag, out)
            else -> return
        }
        armShutdown(now)
    }

    private fun abandonExpired(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = retransmissionQueue ?: return
        if (!peerSupportsForwardTsn) return
        val skips = rq.abandonExpired(now)
        val advanced = rq.advancedPeerAckPoint
        if (skips.isNotEmpty() || rq.cumulativeAckPoint.sackPrecedes(advanced)) {
            val streams = skips.map { (id, ssn) -> ForwardTsnStream(id, ssn) }
            emitPacket(listOf(SctpChunk.ForwardTsn(advanced, streams)), peerVerificationTag, out)
            rq.purgeAbandonedThrough(advanced)
        }
    }

    private fun armHandshake(now: Instant) {
        handshakeDeadline = now + rtt.rto
    }

    private fun cancelHandshake() {
        handshakeDeadline = null
        localInit = null
    }

    private fun armShutdown(now: Instant) {
        shutdownDeadline = now + rtt.rto
    }

    private fun cancelAllTimers() {
        handshakeDeadline = null
        t3Deadline = null
        sackDeadline = null
        shutdownDeadline = null
    }

    // ────────────────────────────────── helpers ──────────────────────────────────

    private fun fail(
        reason: SctpFailureReason,
        out: MutableList<SctpOutput>,
    ) {
        out += SctpOutput.Aborted(reason)
        transition(SctpAssociationState.Closed, out)
        cancelAllTimers()
        clearControlBlocks()
    }

    private fun abortWith(
        reason: SctpFailureReason,
        reflectTag: VerificationTag,
        out: MutableList<SctpOutput>,
    ) {
        emitPacket(listOf(SctpChunk.Abort(verificationTagReflected = true, causes = emptyList())), reflectTag, out)
        fail(reason, out)
    }

    private fun clearControlBlocks() {
        retransmissionQueue = null
        reassemblyQueue = null
        congestion = null
        pendingSend.clear()
        pendingSendBytes = 0
        orderedSendSsn.clear()
    }

    private fun transition(
        target: SctpAssociationState,
        out: MutableList<SctpOutput>,
    ) {
        if (_state == target) return
        _state = target
        out += SctpOutput.StateChanged(target)
    }

    // The verification tag rule (RFC 4960 §8.5): an inbound packet must carry our Verification Tag —
    // except a packet whose first chunk is INIT (tag 0), or a COOKIE-ECHO/-ACK during setup (keyed by
    // phase), or a reflected ABORT: a peer that lost our TCB (crash/restart) sends an out-of-the-blue
    // ABORT with the T-bit set carrying the tag it saw on OUR packet (= our peerVerificationTag, RFC 4960
    // §8.5.1) — accepting it is what lets a dead-peer restart actually tear us down instead of leaving us
    // Established forever.
    private fun verificationTagOk(packet: SctpPacket): Boolean {
        val first = packet.chunks.firstOrNull() ?: return false
        if (first is SctpChunk.Init) return packet.verificationTag.value == 0u
        if (first is SctpChunk.Abort && first.verificationTagReflected) {
            return packet.verificationTag == peerVerificationTag || packet.verificationTag == localVerificationTag
        }
        // RFC 4960 §8.5.1(D): a COOKIE ECHO carries the tag from the INIT ACK that minted its cookie, and
        // "the receiver of a COOKIE ECHO follows the procedures in Section 5" — i.e. it is authenticated by
        // the cookie, not by this gate. It MUST be exempt: a restarting peer echoes the *new* tag our
        // §5.2.2 INIT ACK gave it, which by construction is not the tag of the association still running
        // here, so gating on it would drop the restart before §5.2.4's Table 2 ever saw it.
        if (first is SctpChunk.CookieEcho) return true
        if (localVerificationTag.value == 0u) return true // pre-TCB (e.g. an INIT-ACK landing)
        return packet.verificationTag == localVerificationTag
    }

    private fun emitPacket(
        chunks: List<SctpChunk>,
        headerTag: VerificationTag,
        out: MutableList<SctpOutput>,
    ) {
        out += SctpOutput.Transmit(encodePacket(chunks, headerTag))
    }

    private fun encodePacket(
        chunks: List<SctpChunk>,
        headerTag: VerificationTag,
    ): PlatformBuffer {
        val builder = SctpPacketBuilder(localPort, remotePort, headerTag)
        for (chunk in chunks) builder.add(chunk)
        return builder.encode(config.bufferFactory)
    }

    /**
     * Split one user message into per-chunk payloads of at most [SctpConfig.maxPayloadBytes] (RFC 4960
     * §6.9). The results are **zero-copy views over the caller's borrowed payload**, valid only for the
     * duration of this `handle` call — [onSendMessage] consumes each one immediately by encoding it into
     * its wire packet, which is the copy that survives. A sub-MTU message is therefore not copied here at
     * all; it is simply the whole payload as one view.
     */
    private fun fragment(payload: ReadBuffer): List<ReadBuffer> {
        val slice = payload.slice()
        val total = slice.remaining()
        if (total <= config.maxPayloadBytes) return listOf(slice)
        val out = ArrayList<ReadBuffer>((total + config.maxPayloadBytes - 1) / config.maxPayloadBytes)
        var offset = 0
        while (offset < total) {
            val len = minOf(config.maxPayloadBytes, total - offset)
            val fragment = slice.slice()
            fragment.position(offset)
            fragment.setLimit(offset + len)
            out += fragment
            offset += len
        }
        return out
    }

    private fun copyOf(view: ReadBuffer): PlatformBuffer {
        val slice = view.slice()
        val len = slice.remaining()
        val copy = config.bufferFactory.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
        copy.write(slice)
        copy.resetForRead()
        copy.setLimit(len)
        return copy
    }

    private fun randomTag(): VerificationTag {
        val v = random.nextInt().toUInt()
        return VerificationTag(if (v == 0u) 1u else v)
    }

    private fun randomTsn(): Tsn = Tsn(random.nextInt().toUInt())

    // ── State Cookie (RFC 4960 §5.1.3) — a self-authenticated TCB snapshot. Over DTLS the transport
    // already authenticates the peer, so the cookie carries a fixed magic rather than an HMAC; a cookie
    // without our magic is one we did not mint and is silently dropped (RFC 4960 §5.1.5). ──
    private fun encodeCookie(cookie: StateCookie): ReadBuffer {
        val buf = config.bufferFactory.allocate(StateCookie.SIZE_BYTES, ByteOrder.BIG_ENDIAN)
        StateCookieCodec.encode(buf, cookie, EncodeContext.Empty)
        buf.resetForRead()
        buf.setLimit(StateCookie.SIZE_BYTES)
        return buf
    }

    /** null for anything that is not a cookie we minted — RFC 4960 §5.1.5 discards those silently. */
    private fun decodeCookie(view: ReadBuffer): StateCookie? {
        val slice = view.slice()
        if (slice.remaining() < StateCookie.SIZE_BYTES) return null
        val cookie = StateCookieCodec.decode(slice, DecodeContext.Empty)
        return cookie.takeIf { it.magic == StateCookie.MAGIC }
    }

    public companion object {
        /** The SCTP port WebRTC data channels use by default (RFC 8831 §6.2). */
        public const val SCTP_DATA_CHANNEL_PORT: UShort = 5000u

        private const val SACK_EVERY = 2

        /** "No tag here" — an unset Tie-Tag, and the Verification Tag of a packet that carries an INIT. */
        private val ZERO_TAG = VerificationTag(0u)
    }
}
