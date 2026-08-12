@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.ErrorCauseCode
import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.ReConfigParameter
import com.ditchoom.webrtc.sctp.ReConfigParameterDecode
import com.ditchoom.webrtc.sctp.ReConfigRequestSequenceNumber
import com.ditchoom.webrtc.sctp.ReConfigResult
import com.ditchoom.webrtc.sctp.SctpChunk
import com.ditchoom.webrtc.sctp.SctpChunkType
import com.ditchoom.webrtc.sctp.SctpDecodeResult
import com.ditchoom.webrtc.sctp.SctpErrorCause
import com.ditchoom.webrtc.sctp.SctpPacket
import com.ditchoom.webrtc.sctp.SctpPacketBuilder
import com.ditchoom.webrtc.sctp.SctpParameter
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.StreamSequenceNumber
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import com.ditchoom.webrtc.sctp.asSupportedExtensions
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The **sans-io SCTP association** (RFC 4960 subset per RFC 8831 / ARCHITECTURE §11.2 — dcSCTP-style: one path,
 * no multihoming, no stream interleaving) — a pure `handle(event, now): List<Output>` plus
 * [nextDeadline], with **no dispatcher, clock, RNG, or I/O inside** (ARCHITECTURE §5.1). It owns the four-way
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
 * covered a layer down by ICE consent freshness (RFC 7675), which tears down the transport on a dead
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

    // Internal-readable for the same reason the verification tags above are: a fixture has to be able to
    // see that a teardown cleared the peer's advertised capabilities, and no output carries that fact.
    internal var peerExtensions: PeerExtensions = PeerExtensions.None
        private set

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

    private var tcb: Tcb = Tcb.NoAssociation

    /**
     * What is measured about the path currently underneath this association — RTT, congestion, the
     * consecutive-error budget, and the epoch that says which path they describe (see [PathRide]).
     *
     * A `var` holding one value rather than four fields, because a migration invalidates all of them
     * together and the reset is then a construction that cannot omit one.
     */
    private var ride: PathRide = PathRide.first(config)

    // Retained handshake artifacts (rebuilt-identical retransmits).
    private var localInit: SctpChunk.Init? = null
    private var cookieEcho: SctpChunk.CookieEcho? = null

    // ── RFC 6525 stream reconfiguration — two state machines, each one field ──
    private var outgoingReset: OutgoingReset = OutgoingReset.Ready(PendingReset.Nothing)
    private var peerRequests: PeerRequests = PeerRequests.NoneYet(ReConfigRequestSequenceNumber(0u))
    private var nextRequestSequence = ReConfigRequestSequenceNumber(0u)

    /**
     * What the upper layer has asked to reset but that is not yet on the wire — a **join semilattice**
     * over [StreamResetScope], so accumulating requests while one is in flight (RFC 6525 §5.1.2 allows
     * only one outstanding at a time) is total and order-independent.
     *
     * [Nothing] is a state of its own rather than an empty [StreamResetScope.Streams], because on the
     * wire an empty stream list means *all* streams — the one confusion this whole type exists to make
     * impossible. An empty request from the caller therefore lands here, as the no-op it reads as.
     */
    private sealed interface PendingReset {
        /** Nothing queued. */
        data object Nothing : PendingReset

        /** [scope] is waiting to go out. */
        data class Some(
            val scope: StreamResetScope,
        ) : PendingReset

        /** This pending set joined with [scope]: "all streams" absorbs, named streams union. */
        fun plus(scope: StreamResetScope): PendingReset =
            when (this) {
                Nothing -> if (scope is StreamResetScope.Streams && scope.ids.isEmpty()) Nothing else Some(scope)
                is Some ->
                    when {
                        this.scope is StreamResetScope.AllStreams || scope is StreamResetScope.AllStreams ->
                            Some(StreamResetScope.AllStreams)
                        else -> {
                            val a = (this.scope as StreamResetScope.Streams).ids
                            val b = (scope as StreamResetScope.Streams).ids
                            Some(StreamResetScope.Streams(a + b))
                        }
                    }
            }
    }

    /**
     * The requester half (RFC 6525 §5.1.2): at most one request may be outstanding, which is why this is
     * one field with two states rather than a nullable "in flight" beside a queue. Both states carry the
     * pending set, so a reset asked for at any moment has exactly one place to go.
     */
    private sealed interface OutgoingReset {
        /** What has piled up behind whatever this state is doing. */
        val pending: PendingReset

        /** Nothing on the wire — [pending] goes out as soon as the association can send it. */
        data class Ready(
            override val pending: PendingReset,
        ) : OutgoingReset

        /**
         * [request] is on the wire and unanswered. Retained whole so the retransmit timer re-emits it
         * byte-identically (a re-derived request would carry a newer last-assigned TSN, which the peer
         * would read as a *different* request at the same sequence number).
         */
        data class InFlight(
            val sequence: ReConfigRequestSequenceNumber,
            val scope: StreamResetScope,
            val request: ReConfigParameter.OutgoingSsnReset,
            override val pending: PendingReset,
        ) : OutgoingReset
    }

    /**
     * The responder half — what this endpoint knows about the peer's request numbering. Sealed rather
     * than a `seen: Boolean` beside two nullables, because the three states have genuinely different
     * data and the invariants between them are exactly what the RFC's rules are made of:
     *
     * - **[NoneYet]** — nothing received yet; [expected] is the RFC 6525 §5.1.1 seed (the peer's Initial TSN).
     * - **[Answered]** — [last] was processed and answered with [response], which §5.2.1 requires be
     *   *repeated verbatim* if the peer retransmits that same request rather than processed again.
     * - **[Deferred]** — §5.2.2 deferred processing: [last] named a TSN we have not received up to, so it
     *   is held and answered "In progress". The cached response is *derived*, not stored, so the
     *   invariant "a deferred request is the one we answered In-progress" cannot drift.
     */
    private sealed interface PeerRequests {
        /** The sequence number the peer's next *new* request must carry (RFC 6525 §5.2). */
        val expected: ReConfigRequestSequenceNumber

        data class NoneYet(
            override val expected: ReConfigRequestSequenceNumber,
        ) : PeerRequests

        /** A request has been received, so both §5.2.1's repeat rule and §5.2's ordering rule apply. */
        sealed interface Seen : PeerRequests {
            val last: ReConfigRequestSequenceNumber

            /** The answer to repeat verbatim if the peer retransmits [last] (§5.2.1). */
            val response: ReConfigParameter.Response

            override val expected: ReConfigRequestSequenceNumber get() = last.next()
        }

        data class Answered(
            override val last: ReConfigRequestSequenceNumber,
            override val response: ReConfigParameter.Response,
        ) : Seen

        data class Deferred(
            override val last: ReConfigRequestSequenceNumber,
            val scope: StreamResetScope,
            val senderLastAssignedTsn: Tsn,
        ) : Seen {
            override val response: ReConfigParameter.Response
                get() = ReConfigParameter.Response(last, ReConfigResult.InProgress)
        }
    }

    /**
     * Whether an inbound RFC 6525 request may be acted on. A sealed decision rather than a nullable
     * response: "process this" and "do not process it, send this instead" are two outcomes, and a null
     * standing for the first would be a second meaning for absence.
     */
    private sealed interface RequestAdmission {
        /** The request is the expected next one — act on it. */
        data object Process : RequestAdmission

        /** Do not act; answer with [response] (a repeat under §5.2.1, or a bad-sequence reject under §5.2). */
        data class Answer(
            val response: ReConfigParameter.Response,
        ) : RequestAdmission
    }

    // ── Timers as absolute deadlines (ARCHITECTURE §5.1: nextDeadline is the whole clock contract) ──
    private var deadlines = AssociationDeadlines()
    private var handshakeRetransmits = 0
    private var shutdownRetransmits = 0
    private var reConfigRetransmits = 0
    private var packetsSinceSack = 0

    /**
     * The earliest armed timer's deadline, or null when no timer is armed (ARCHITECTURE §5.1). The driver waits
     * until here, then feeds [SctpEvent.TimerFired]; every due timer fires in that one call.
     */
    public fun nextDeadline(now: Instant): Instant? =
        when (val earliest = deadlines.earliest()) {
            Deadline.Unarmed -> null
            is Deadline.At -> earliest.instant
        }

    /** Feed one event; returns the side effects for the driver to apply (ARCHITECTURE §5.1). Never throws. */
    public fun handle(
        event: SctpEvent,
        now: Instant,
    ): List<SctpOutput> {
        val out = ArrayList<SctpOutput>()
        when (event) {
            SctpEvent.Associate -> onAssociate(now, out)
            is SctpEvent.DatagramReceived -> onDatagram(event.payload, now, out)
            is SctpEvent.SendMessage -> onSendMessage(event, now, out)
            is SctpEvent.ResetStreams -> onResetStreams(event.scope, now, out)
            SctpEvent.Shutdown -> onShutdownRequested(now, out)
            SctpEvent.Abort -> onAbortRequested(out)
            SctpEvent.TimerFired -> onTimers(now, out)
        }
        return out
    }

    /**
     * Give back everything the association still owns, for a driver that is shutting down (RFC 4960 §8.1
     * abort, a transport that closed under it, or an ordinary `close()`). Puts nothing on the wire and
     * changes no state a peer can observe — an association reaching [SctpAssociationState.Closed] through
     * the protocol has already returned its buffers, and this is what covers the paths that never get
     * there.
     *
     * Returns the same [SctpOutput.ReclaimRetained] entries every other removal site does, and for the
     * same reason: the driver, not this object, knows when the sends it queued have gone out. A driver
     * that has already drained those sends may release them immediately. Idempotent — a second call
     * returns nothing.
     */
    public fun close(): List<SctpOutput> {
        val out = ArrayList<SctpOutput>()
        cancelAllTimers()
        cancelHandshake()
        clearControlBlocks(out)
        _state = SctpAssociationState.Closed
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
                parameters = listOf(SctpParameter.forwardTsnSupported(), supportedExtensions()),
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
                    peerReConfig = init.parameters.advertiseReConfig(),
                    ourTag = advertised.ourTag,
                    ourInitialTsn = advertised.ourInitialTsn,
                    localTieTag = advertised.localTieTag,
                    peerTieTag = advertised.peerTieTag,
                ),
            )
        // `ofValue` copies the cookie into the parameter's own padded buffer, so the encode buffer is dead
        // the moment the parameter exists — released here rather than left for the association to hold,
        // which is why an INIT flood costs nothing lasting even though a stateless responder retains no TCB.
        val cookieParameter = SctpParameter.ofValue(com.ditchoom.webrtc.sctp.ParameterType.StateCookie, cookie)
        cookie.freeIfNeeded()
        val initAck =
            SctpChunk.InitAck(
                initiateTag = advertised.ourTag,
                advertisedReceiverWindow = config.receiveWindowBytes,
                outboundStreams = config.outboundStreams,
                inboundStreams = config.inboundStreams,
                initialTsn = advertised.ourInitialTsn,
                parameters =
                    listOf(
                        cookieParameter,
                        SctpParameter.forwardTsnSupported(),
                        supportedExtensions(),
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
        peerExtensions =
            PeerExtensions(
                forwardTsn = initAck.parameters.any { it.type == com.ditchoom.webrtc.sctp.ParameterType.ForwardTsnSupported },
                reConfig = initAck.parameters.advertiseReConfig(),
            )
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
                    clearCookieEcho()
                    trySend(now, out)
                    maybeSendReset(now, out)
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
        clearControlBlocks(out) // drop the old association's queues, stream state and unsent messages
        cancelAllTimers()
        // A restart invalidates every measurement: the peer's state is gone, so cwnd/SRTT describe a
        // conversation that no longer exists, and the epoch must advance so nothing from the previous
        // association can be mistaken for this one's.
        ride = ride.onRestart()
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
        peerExtensions = PeerExtensions(forwardTsn = cookie.peerForwardTsn, reConfig = cookie.peerReConfig)
        establishControlBlocks(peerInitialTsn = cookie.peerInitialTsn, peerRwnd = cookie.peerRwnd)
        emitPacket(listOf(SctpChunk.CookieAck), peerVerificationTag, out)
        transition(SctpAssociationState.Established, out)
        cancelHandshake()
        clearCookieEcho()
        trySend(now, out)
        maybeSendReset(now, out)
    }

    private fun onCookieAck(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (_state != SctpAssociationState.CookieEchoed) return
        transition(SctpAssociationState.Established, out)
        cancelHandshake()
        clearCookieEcho()
        trySend(now, out)
        maybeSendReset(now, out)
    }

    private fun establishControlBlocks(
        peerInitialTsn: Tsn,
        peerRwnd: UInt,
    ) {
        val retransmission = RetransmissionQueue(config, localInitialTsn)
        retransmission.setPeerReceiveWindow(peerRwnd)
        tcb =
            Tcb.Live(
                retransmission = retransmission,
                reassembly = ReassemblyQueue(peerInitialTsn, config),
            )
        // The peer's advertised window is the RFC 4960 §7.2.1 seed for ssthresh, and it only becomes known
        // here. The epoch and any handshake RTT sample survive: this is the same path it always was.
        ride = ride.established(peerRwnd)
        // RFC 6525 §5.1.1: both endpoints seed their Re-configuration Request Sequence Number from their
        // own Initial TSN, so each side can predict where the other's numbering starts before a single
        // request has been exchanged — which is what lets §4.1's Response Sequence Number field be filled
        // in ("next expected minus 1") on the very first request we originate.
        nextRequestSequence = ReConfigRequestSequenceNumber(localInitialTsn.value)
        peerRequests = PeerRequests.NoneYet(ReConfigRequestSequenceNumber(peerInitialTsn.value))
    }

    // ────────────────────────────────── receive path ──────────────────────────────────

    private fun onDatagram(
        payload: ReadBuffer,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val packet = (SctpPacket.decode(payload) as? SctpDecodeResult.Success)?.packet ?: return
        // `finally`, because the two drops just below — a bad CRC32c and a bad verification tag — are the
        // paths a corrupt or spoofed datagram takes, and each one is an exit that owes the decode's views
        // (see [SctpPacket.release]). Releasing only on the path that processed the packet would give the
        // chunk back for well-formed traffic and pin it for everything else, which is backwards.
        //
        // Safe because nothing survives the call: chunks are read into value types, and the two things
        // that must outlive it are copied out explicitly — inbound user data in `ReassemblyQueue` and the
        // INIT-ACK cookie, both via `copyOf`. The datagram itself is NOT freed here; the drive loop still
        // owns it and releases it after `handle`.
        try {
            onDecodedPacket(packet, now, out)
        } finally {
            packet.release()
        }
    }

    private fun onDecodedPacket(
        packet: SctpPacket,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
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
                is SctpChunk.ReConfig -> onReConfig(chunk, now, out)
                is SctpChunk.Unrecognized -> Unit
            }
        }
        // A deferred reset (RFC 6525 §5.2.2) completes on cumulative-TSN progress, and the only thing that
        // advances the cumulative TSN is inbound DATA or FORWARD-TSN — both of which land in the loop
        // above. Checked once here rather than per chunk so a packet bundling several DATA chunks does not
        // re-evaluate it for each of them.
        maybeCompleteDeferredReset(out)
        if (sackOwed) maybeSack(now, out)
    }

    private fun onData(
        chunk: SctpChunk.Data,
        out: MutableList<SctpOutput>,
    ) {
        val reassembly = tcb.liveOrElse { return }.reassembly
        for (message in reassembly.receive(chunk)) {
            out += SctpOutput.MessageReceived(message.streamId, message.ppid, message.unordered, message.payload)
        }
    }

    private fun onSack(
        sack: SctpChunk.Sack,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = tcb.liveOrElse { return }.retransmission
        val cc = ride.congestion
        val wasCwndLimited = rq.outstandingBytes >= cc.cwnd
        val gapsAbsolute =
            sack.gapAckBlocks.map { block ->
                Tsn(sack.cumulativeTsnAck.value + block.start.toUInt()) to Tsn(sack.cumulativeTsnAck.value + block.end.toUInt())
            }
        val outcome = rq.onSack(sack.cumulativeTsnAck, sack.advertisedReceiverWindow, gapsAbsolute, now, ride.epoch)
        reclaim(outcome.reclaimed, out)
        if (outcome.rttSample != null) ride.rtt.observe(outcome.rttSample)
        cc.onDataAcked(outcome.bytesNewlyAcked, wasCwndLimited)
        if (outcome.fastRetransmitTriggered) cc.onFastRetransmit()
        if (outcome.cumulativeAdvanced) ride.onProgress()

        if (outcome.allDataAcknowledged) {
            deadlines = deadlines.copy(t3 = Deadline.Unarmed)
        } else if (outcome.cumulativeAdvanced) {
            deadlines = deadlines.copy(t3 = Deadline.At(now + ride.rtt.rto))
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
        val reassembly = tcb.liveOrElse { return }.reassembly
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
                    enqueuedAt = now,
                )
            pendingSend.addLast(data)
            pendingSendBytes += data.bytes
            nextTsn = nextTsn.next()
        }
        // The views are spent the moment their bytes are inside the encoded packets above. They must be
        // *released*, not merely dropped: each is a `slice()` of the caller's payload, and on a pooled
        // buffer that is a reference — so a message sent from a pooled factory would pin one chunk per
        // fragment however carefully the caller freed the payload itself.
        for (fragmentPayload in fragments) fragmentPayload.freeIfNeeded()
        trySend(now, out)
    }

    // The RFC 4960 §6.1 send routine: flush retransmits first, then new data while cwnd and the peer
    // receive window allow, arming the T3-rtx timer whenever data is outstanding.
    private fun trySend(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = tcb.liveOrElse { return }.retransmission
        val cc = ride.congestion

        // Retransmit the lost flight, but PACED BY cwnd (RFC 4960 §6.3.3 E3): after a T3 collapse to one
        // MTU we must not dump 100 outstanding chunks back onto the wire at once. Always send at least the
        // earliest one (flight size is 0 right after a T3 marked everything for retransmit); the remainder
        // stays NeedsRetransmit and goes out on the next SACK/timer as cwnd re-opens.
        for (data in rq.retransmittable()) {
            if (rq.outstandingBytes > 0 && rq.outstandingBytes + data.bytes > cc.cwnd) break
            rq.markRetransmitted(data)
            out += SctpOutput.Transmit.Retained(data.wirePacket())
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
            rq.onSent(next, now, ride.epoch)
            out += SctpOutput.Transmit.Retained(next.wirePacket())
        }

        if (rq.outstandingBytes > 0 && deadlines.t3 is Deadline.Unarmed) deadlines = deadlines.copy(t3 = Deadline.At(now + ride.rtt.rto))
    }

    // ─────────────────── stream reconfiguration (RFC 6525) — the requester half ───────────────────

    private fun onResetStreams(
        scope: StreamResetScope,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        outgoingReset =
            when (val current = outgoingReset) {
                is OutgoingReset.Ready -> OutgoingReset.Ready(current.pending.plus(scope))
                is OutgoingReset.InFlight -> current.copy(pending = current.pending.plus(scope))
            }
        maybeSendReset(now, out)
    }

    /**
     * Put the pending reset on the wire, if anything is pending and nothing else is outstanding (RFC 6525
     * §5.1.2). Called both when the upper layer asks and whenever the previous request is answered, so a
     * queue of channel closes drains one request at a time without the driver having to sequence them.
     */
    private fun maybeSendReset(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val ready = outgoingReset as? OutgoingReset.Ready ?: return
        val pending = ready.pending as? PendingReset.Some ?: return
        if (_state != SctpAssociationState.Established) return
        val scope = pending.scope
        // A peer that never advertised RE-CONFIG cannot be sent one (RFC 6525 §5.1). Answer the caller
        // rather than dropping the request: a channel close that is unanswerable still has to complete.
        if (!peerExtensions.reConfig) {
            outgoingReset = OutgoingReset.Ready(PendingReset.Nothing)
            out += SctpOutput.OutgoingStreamsReset(scope, StreamResetOutcome.Unsupported)
            return
        }
        val sequence = nextRequestSequence
        nextRequestSequence = sequence.next()
        val request =
            ReConfigParameter.OutgoingSsnReset(
                requestSequenceNumber = sequence,
                // RFC 6525 §4.1: when a request is not itself answering an incoming one it carries "the
                // next expected Re-configuration Request Sequence Number minus 1".
                responseSequenceNumber = peerRequests.expected.previous(),
                // The last TSN we have assigned anywhere (RFC 6525 §4.1). Assignment happens when a
                // message is *queued*, not when it is sent, so this covers data still sitting in the send
                // buffer — the peer defers its reset until it has received all of it (§5.2.2), which is
                // what stops a close from truncating data the caller already handed us.
                senderLastAssignedTsn = Tsn(nextTsn.value - 1u),
                streams = scope.streamList(),
            )
        outgoingReset = OutgoingReset.InFlight(sequence, scope, request, PendingReset.Nothing)
        reConfigRetransmits = 0
        emitPacket(listOf(SctpChunk.ReConfig.of(request)), peerVerificationTag, out)
        armReConfig(now)
    }

    private fun onReConfigResponse(
        response: ReConfigParameter.Response,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val inFlight = outgoingReset as? OutgoingReset.InFlight ?: return
        // A response for anything other than the request actually outstanding is stale (a duplicate of an
        // already-completed one, or a peer answering a sequence number we never sent) — discard it rather
        // than completing the live request on someone else's answer.
        if (response.responseSequenceNumber != inFlight.sequence) return
        if (response.result == ReConfigResult.InProgress) {
            // RFC 6525 §5.2.2: the peer is holding the reset until its cumulative TSN catches up. The
            // request stays outstanding and the timer is restarted from scratch — the peer sends the final
            // response itself, and our retransmit is what recovers it if that response is lost.
            reConfigRetransmits = 0
            armReConfig(now)
            return
        }
        outgoingReset = OutgoingReset.Ready(inFlight.pending)
        cancelReConfig()
        val outcome =
            if (response.result.isSuccess) {
                // Our outgoing SSN state for these streams is now reset on both sides, so the next ordered
                // message on such a stream starts again at SSN 0 — which is what makes the stream id
                // reusable for a brand-new data channel (RFC 8831 §6.7).
                resetOutgoingSsn(inFlight.scope)
                StreamResetOutcome.Performed
            } else {
                StreamResetOutcome.Refused(response.result)
            }
        out += SctpOutput.OutgoingStreamsReset(inFlight.scope, outcome)
        maybeSendReset(now, out)
    }

    private fun resetOutgoingSsn(scope: StreamResetScope) {
        when (scope) {
            StreamResetScope.AllStreams -> orderedSendSsn.clear()
            is StreamResetScope.Streams -> for (id in scope.ids) orderedSendSsn.remove(id)
        }
    }

    // ─────────────────── stream reconfiguration (RFC 6525) — the responder half ───────────────────

    private fun onReConfig(
        chunk: SctpChunk.ReConfig,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        // Before the TCB exists there is no SSN state to reset and no sequence space to check against, so
        // a RE-CONFIG arriving mid-handshake is dropped rather than answered on guessed state.
        tcb.liveOrElse { return }
        val responses = ArrayList<ReConfigParameter>()
        for (decoded in chunk.reConfigParameters()) {
            when (decoded) {
                is ReConfigParameterDecode.Interpreted -> onReConfigParameter(decoded.parameter, responses, now, out)
                // Not an RFC 6525 §4 parameter at all — an unknown TLV riding in a RE-CONFIG chunk. The
                // chunk's own type bits already say what to do with something unrecognized: skip it.
                ReConfigParameterDecode.NotReConfig -> Unit
                // The type IS an RFC 6525 one but its body is malformed, so its Request Sequence Number
                // cannot be trusted — and a response is *addressed* by that number. There is nothing
                // truthful to answer, so it is dropped; the peer's own retransmit timer is what surfaces
                // the problem to it (RFC 6525 §5.1.1), and inventing a sequence number would corrupt the
                // one piece of state both sides must agree on.
                is ReConfigParameterDecode.Malformed -> Unit
            }
        }
        if (responses.isNotEmpty()) emitReConfig(responses, out)
    }

    private fun onReConfigParameter(
        parameter: ReConfigParameter,
        responses: MutableList<ReConfigParameter>,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        when (parameter) {
            is ReConfigParameter.OutgoingSsnReset -> onIncomingStreamReset(parameter, responses, out)
            is ReConfigParameter.Response -> onReConfigResponse(parameter, now, out)
            // The four requests this subset decodes but will not perform (see ReConfig.kt's header): an
            // Incoming SSN Reset would have us reset streams the peer does not own the sequencing of, an
            // SSN/TSN reset would have to unwind the retransmission queue and FORWARD-TSN together, and
            // adding streams is meaningless when INIT already advertised 1024 of them. Each is REFUSED,
            // explicitly and in sequence, rather than ignored — an ignored request is retransmitted until
            // the peer's error counter aborts the whole association.
            is ReConfigParameter.IncomingSsnReset -> refuse(parameter.requestSequenceNumber, responses)
            is ReConfigParameter.SsnTsnReset -> refuse(parameter.requestSequenceNumber, responses)
            is ReConfigParameter.AddOutgoingStreams -> refuse(parameter.requestSequenceNumber, responses)
            is ReConfigParameter.AddIncomingStreams -> refuse(parameter.requestSequenceNumber, responses)
        }
    }

    private fun refuse(
        sequence: ReConfigRequestSequenceNumber,
        responses: MutableList<ReConfigParameter>,
    ) {
        when (val admission = admit(sequence)) {
            is RequestAdmission.Answer -> responses += admission.response
            RequestAdmission.Process -> {
                val response = ReConfigParameter.Response(sequence, ReConfigResult.Denied)
                responses += response
                peerRequests = PeerRequests.Answered(sequence, response)
            }
        }
    }

    /**
     * The peer is resetting **its** outgoing streams — this endpoint's incoming half, and RFC 8831 §6.7's
     * "the peer closed a data channel".
     */
    private fun onIncomingStreamReset(
        request: ReConfigParameter.OutgoingSsnReset,
        responses: MutableList<ReConfigParameter>,
        out: MutableList<SctpOutput>,
    ) {
        when (val admission = admit(request.requestSequenceNumber)) {
            is RequestAdmission.Answer -> {
                responses += admission.response
                return
            }
            RequestAdmission.Process -> Unit
        }
        val reassembly = tcb.liveOrElse { return }.reassembly
        val scope = request.scope()
        // RFC 6525 §5.2.2: a reset whose Sender's Last Assigned TSN is still above our cumulative point
        // would tear the SSN state out from under data that is in flight and about to be reassembled. Hold
        // it and answer "In progress"; it completes in maybeCompleteDeferredReset when the gap fills.
        if (reassembly.cumulativeTsn.sackPrecedes(request.senderLastAssignedTsn)) {
            val deferred = PeerRequests.Deferred(request.requestSequenceNumber, scope, request.senderLastAssignedTsn)
            peerRequests = deferred
            responses += deferred.response
            return
        }
        performIncomingReset(scope, out)
        val response = ReConfigParameter.Response(request.requestSequenceNumber, ReConfigResult.SuccessPerformed)
        responses += response
        peerRequests = PeerRequests.Answered(request.requestSequenceNumber, response)
    }

    private fun maybeCompleteDeferredReset(out: MutableList<SctpOutput>) {
        val deferred = peerRequests as? PeerRequests.Deferred ?: return
        val reassembly = tcb.liveOrElse { return }.reassembly
        if (reassembly.cumulativeTsn.sackPrecedes(deferred.senderLastAssignedTsn)) return
        performIncomingReset(deferred.scope, out)
        val response = ReConfigParameter.Response(deferred.last, ReConfigResult.SuccessPerformed)
        // Replace the cached "In progress" so a retransmit of this same request now gets the final answer
        // (RFC 6525 §5.2.1) — otherwise the peer would be told In-progress forever by its own retries.
        peerRequests = PeerRequests.Answered(deferred.last, response)
        emitReConfig(listOf(response), out)
    }

    private fun performIncomingReset(
        scope: StreamResetScope,
        out: MutableList<SctpOutput>,
    ) {
        when (val current = tcb) {
            Tcb.NoAssociation -> Unit
            is Tcb.Live -> current.reassembly.resetStreams(scope)
        }
        out += SctpOutput.IncomingStreamsReset(scope)
    }

    /**
     * RFC 6525 §5.2 / §5.2.1's two sequence rules, in one place: a repeat of the last request is answered
     * with the same response instead of being performed twice, and a request out of sequence is rejected
     * as such.
     *
     * One deliberate leniency: the **first** request the peer ever sends is accepted whatever its
     * sequence number, and the numbering is adopted from it. §5.1.1 says both endpoints seed from their
     * Initial TSN and every implementation we interoperate with does (pion, werift, dcSCTP), so the seed
     * is what [PeerRequests.NoneYet] holds — but if a peer seeded differently, rejecting its first request
     * would fail every channel close for the life of the association, with nothing to renegotiate. There
     * is nothing to protect here that DTLS has not already authenticated, so the strict check starts once
     * the peer has told us where it is counting from.
     */
    private fun admit(sequence: ReConfigRequestSequenceNumber): RequestAdmission =
        when (val requests = peerRequests) {
            is PeerRequests.NoneYet -> RequestAdmission.Process
            is PeerRequests.Seen ->
                when (sequence) {
                    requests.last -> RequestAdmission.Answer(requests.response)
                    requests.expected -> RequestAdmission.Process
                    else -> RequestAdmission.Answer(badSequence(sequence))
                }
        }

    private fun badSequence(sequence: ReConfigRequestSequenceNumber) =
        ReConfigParameter.Response(sequence, ReConfigResult.ErrorBadSequenceNumber)

    private fun emitReConfig(
        parameters: List<ReConfigParameter>,
        out: MutableList<SctpOutput>,
    ) {
        emitPacket(listOf(SctpChunk.ReConfig(parameters.map { it.toParameter() })), peerVerificationTag, out)
    }

    private fun onReConfigTimeout(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val inFlight =
            outgoingReset as? OutgoingReset.InFlight ?: run {
                deadlines = deadlines.copy(reConfig = Deadline.Unarmed)
                return
            }
        reConfigRetransmits += 1
        // RFC 6525 §5.1.1 puts a retransmitted request under the association's error threshold, the same
        // as DATA and SHUTDOWN: a peer that advertised RE-CONFIG and then answers none of them across a
        // full exponential backoff is not a peer whose association is worth keeping.
        if (reConfigRetransmits > config.maxAssociationRetransmits) {
            fail(SctpFailureReason.RetransmissionLimitReached, out)
            return
        }
        ride.rtt.backoff()
        emitPacket(listOf(SctpChunk.ReConfig.of(inFlight.request)), peerVerificationTag, out)
        armReConfig(now)
    }

    private fun armReConfig(now: Instant) {
        deadlines = deadlines.copy(reConfig = Deadline.At(now + ride.rtt.rto))
    }

    private fun cancelReConfig() {
        deadlines = deadlines.copy(reConfig = Deadline.Unarmed)
        reConfigRetransmits = 0
    }

    // The wire's stream list for a scope: RFC 6525 §4.1 encodes "every stream" as the empty list.
    private fun StreamResetScope.streamList(): List<StreamId> =
        when (this) {
            StreamResetScope.AllStreams -> emptyList()
            is StreamResetScope.Streams -> ids.toList()
        }

    // …and the inverse, which is the only place an empty inbound stream list is allowed to mean "all".
    private fun ReConfigParameter.OutgoingSsnReset.scope(): StreamResetScope =
        if (resetsAllStreams) StreamResetScope.AllStreams else StreamResetScope.Streams(streams.toSet())

    // ────────────────────────────────── SACK scheduling ──────────────────────────────────

    private fun maybeSack(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val reassembly = tcb.liveOrElse { return }.reassembly
        packetsSinceSack += 1
        // RFC 4960 §6.2: SACK on every second packet, or immediately on out-of-order / duplicate data.
        if (reassembly.sackImmediatelyRequested || packetsSinceSack >= SACK_EVERY) {
            emitSack(out)
        } else if (deadlines.sack is Deadline.Unarmed) {
            deadlines = deadlines.copy(sack = Deadline.At(now + config.sackDelay))
        }
    }

    private fun emitSack(out: MutableList<SctpOutput>) {
        val reassembly = tcb.liveOrElse { return }.reassembly
        emitPacket(listOf(reassembly.buildSack()), peerVerificationTag, out)
        packetsSinceSack = 0
        deadlines = deadlines.copy(sack = Deadline.Unarmed)
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
        val live = tcb.liveOrElse { return }
        val rq = live.retransmission
        val reassembly = live.reassembly
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
        val rq = tcb.liveOrElse { return }.retransmission
        // The SHUTDOWN carries a cumulative TSN ack for our outbound data — process it like a SACK.
        reclaim(rq.onSack(shutdown.cumulativeTsnAck, rq.peerReceiveWindow, emptyList(), now, ride.epoch).reclaimed, out)
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
        if (tcb is Tcb.NoAssociation && _state == SctpAssociationState.Closed) return
        emitPacket(listOf(SctpChunk.Abort(verificationTagReflected = false, causes = emptyList())), peerVerificationTag, out)
        transition(SctpAssociationState.Closed, out)
        clearControlBlocks(out)
    }

    private fun closeGracefully(out: MutableList<SctpOutput>) {
        transition(SctpAssociationState.Closed, out)
        cancelAllTimers()
        clearControlBlocks(out)
    }

    // ────────────────────────────────── timers ──────────────────────────────────

    private fun onTimers(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (deadlines.handshake.dueAt(now)) onHandshakeTimeout(now, out)
        if (deadlines.t3.dueAt(now)) onT3Timeout(now, out)
        if (deadlines.sack.dueAt(now)) emitSack(out)
        if (deadlines.shutdown.dueAt(now)) onShutdownTimeout(now, out)
        if (deadlines.reConfig.dueAt(now)) onReConfigTimeout(now, out)
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
        ride.rtt.backoff()
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
            tcb
                .liveOrElse {
                    deadlines = deadlines.copy(t3 = Deadline.Unarmed)
                    return
                }.retransmission
        val cc = ride.congestion
        val hadOutstanding = rq.onT3Timeout()
        if (!hadOutstanding) {
            deadlines = deadlines.copy(t3 = Deadline.Unarmed)
            return
        }
        cc.onTimeout()
        ride.rtt.backoff()
        if (ride.retransmitFailed()) {
            fail(SctpFailureReason.RetransmissionLimitReached, out)
            return
        }
        // RFC 3758: abandon partially-reliable chunks past their budget before retransmitting.
        abandonExpired(now, out)
        trySend(now, out)
        deadlines = deadlines.copy(t3 = Deadline.At(now + ride.rtt.rto))
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
        val current = tcb
        when (_state) {
            SctpAssociationState.ShutdownSent ->
                when (current) {
                    Tcb.NoAssociation -> Unit
                    is Tcb.Live ->
                        emitPacket(listOf(SctpChunk.Shutdown(current.reassembly.cumulativeTsn)), peerVerificationTag, out)
                }
            SctpAssociationState.ShutdownAckSent -> emitPacket(listOf(SctpChunk.ShutdownAck), peerVerificationTag, out)
            else -> return
        }
        armShutdown(now)
    }

    private fun abandonExpired(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val rq = tcb.liveOrElse { return }.retransmission
        if (!peerExtensions.forwardTsn) return
        val skips = rq.abandonExpired(now)
        val advanced = rq.advancedPeerAckPoint
        if (skips.isNotEmpty() || rq.cumulativeAckPoint.sackPrecedes(advanced)) {
            val streams = skips.map { (id, ssn) -> ForwardTsnStream(id, ssn) }
            emitPacket(listOf(SctpChunk.ForwardTsn(advanced, streams)), peerVerificationTag, out)
            reclaim(rq.purgeAbandonedThrough(advanced), out)
        }
    }

    /**
     * Hand encoded DATA packets the retransmission queue has finished with back to the driver
     * ([SctpOutput.ReclaimRetained]). Appended to `out` **after** whatever [SctpOutput.Transmit] entries
     * are already in it, which is what makes the ordering guarantee that type documents hold: a driver
     * that carries outputs through one queue cannot free bytes it is still sending.
     */
    private fun reclaim(
        packets: List<PlatformBuffer>,
        out: MutableList<SctpOutput>,
    ) {
        for (packet in packets) out += SctpOutput.ReclaimRetained(packet)
    }

    private fun armHandshake(now: Instant) {
        deadlines = deadlines.copy(handshake = Deadline.At(now + ride.rtt.rto))
    }

    private fun cancelHandshake() {
        deadlines = deadlines.copy(handshake = Deadline.Unarmed)
        localInit = null
    }

    /**
     * Drop the retained COOKIE ECHO and release the cookie **copy** inside it. The copy is taken from the
     * INIT ACK's borrowed datagram precisely so the chunk survives that `handle` call for the handshake
     * retransmits (see [onInitAck]) — which makes this the one place it stops being needed. Never a view
     * of anything the driver holds, so it frees directly rather than going out as a reclaim.
     */
    private fun clearCookieEcho() {
        cookieEcho?.cookie?.freeIfNeeded()
        cookieEcho = null
    }

    private fun armShutdown(now: Instant) {
        deadlines = deadlines.copy(shutdown = Deadline.At(now + ride.rtt.rto))
    }

    // Total by construction: a timer added to AssociationDeadlines is cancelled here without this
    // function being edited, which is the whole reason the five fields became one value.
    private fun cancelAllTimers() {
        deadlines = deadlines.cancelAll()
        reConfigRetransmits = 0
    }

    // ────────────────────────────────── helpers ──────────────────────────────────

    private fun fail(
        reason: SctpFailureReason,
        out: MutableList<SctpOutput>,
    ) {
        out += SctpOutput.Aborted(reason)
        transition(SctpAssociationState.Closed, out)
        cancelAllTimers()
        clearControlBlocks(out)
    }

    private fun abortWith(
        reason: SctpFailureReason,
        reflectTag: VerificationTag,
        out: MutableList<SctpOutput>,
    ) {
        emitPacket(listOf(SctpChunk.Abort(verificationTagReflected = true, causes = emptyList())), reflectTag, out)
        fail(reason, out)
    }

    /**
     * Drop the TCB, returning everything it owned. The send-side packets go back through `out` as
     * [SctpOutput.ReclaimRetained] rather than being freed here — a retransmission-queue entry has been
     * lent to the driver as a view, and `pendingSend` entries travel the same route so that one rule
     * covers the whole queue rather than two that differ by whether a chunk happened to reach the wire.
     * The receive side has no such hazard and releases itself (see [ReassemblyQueue.drain]).
     */
    private fun clearControlBlocks(out: MutableList<SctpOutput>) {
        when (val current = tcb) {
            Tcb.NoAssociation -> Unit
            is Tcb.Live -> {
                reclaim(current.retransmission.drain(), out)
                current.reassembly.drain()
            }
        }
        tcb = Tcb.NoAssociation
        reclaim(pendingSend.map { it.packet }, out)
        pendingSend.clear()
        pendingSendBytes = 0
        orderedSendSsn.clear()
        clearCookieEcho()
        // Both reconfiguration halves belong to the association that is going away: a pending or in-flight
        // request names TSNs and sequence numbers of a TCB that no longer exists, and a peer restart
        // (§5.2.4 action A) re-seeds both sequence spaces in establishControlBlocks.
        outgoingReset = OutgoingReset.Ready(PendingReset.Nothing)
        peerRequests = PeerRequests.NoneYet(ReConfigRequestSequenceNumber(0u))
        // Both extension facts belong to the association going away — cleared as one value, so neither
        // can survive into the next peer's association (a half-cleared pair was invisible at the read).
        peerExtensions = PeerExtensions.None
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

    // Every packet that leaves through here is encoded for this one transmission and retained by nobody,
    // so it is the driver's outright ([SctpOutput.Transmit.Owned]). The DATA path is the sole exception and
    // does not come through here — see [trySend].
    private fun emitPacket(
        chunks: List<SctpChunk>,
        headerTag: VerificationTag,
        out: MutableList<SctpOutput>,
    ) {
        out += SctpOutput.Transmit.Owned(encodePacket(chunks, headerTag))
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
        // `slice` was only the measuring view; every returned fragment re-slices from it and a pooled
        // `slice()` re-parents to the ROOT chunk, so the intermediate is not an ancestor anybody needs —
        // just an extra reference. Released here, since the caller only ever sees the fragments.
        slice.freeIfNeeded()
        return out
    }

    private fun copyOf(view: ReadBuffer): PlatformBuffer {
        // The slice is taken only to read `view` without disturbing its cursor, and it is dead the moment
        // the copy is made — but on a pooled datagram `slice()` is `addRef()`, and `TrackedSlice`
        // re-parents to the ROOT chunk, so dropping it pinned the received datagram once per call. The
        // copy itself is genuinely owned by the caller and is NOT released here.
        val slice = view.slice()
        return try {
            val len = slice.remaining()
            val copy = config.bufferFactory.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
            copy.write(slice)
            copy.resetForRead()
            copy.setLimit(len)
            copy
        } finally {
            slice.freeIfNeeded()
        }
    }

    // The Supported Extensions parameter (RFC 5061 §4.2.7) both the INIT and the INIT ACK carry. RE-CONFIG
    // is listed alongside FORWARD-TSN because RFC 6525 §5.1 makes the advertisement the *invitation*: an
    // endpoint sends a RE-CONFIG chunk only to a peer that listed chunk type 130 here.
    private fun supportedExtensions(): SctpParameter =
        SctpParameter.supportedExtensions(listOf(SctpChunkType.ForwardTsn, SctpChunkType.ReConfig))

    // Whether a peer's INIT/INIT-ACK parameters advertise RE-CONFIG. `any` rather than `first`: the
    // parameter is not required to be unique, and a peer that sends two must not have the second ignored.
    private fun List<SctpParameter>.advertiseReConfig(): Boolean =
        any { it.asSupportedExtensions()?.contains(SctpChunkType.ReConfig) == true }

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
        // The slice exists only so the codec can read without disturbing `view`'s cursor, and it is dead
        // when that read returns — `StateCookie` is value types only. But on a pooled datagram `slice()`
        // is `addRef()`, so dropping it pinned the received buffer once per COOKIE-ECHO, including on the
        // early return for a cookie too short to be ours (peer-controlled).
        val slice = view.slice()
        return try {
            if (slice.remaining() < StateCookie.SIZE_BYTES) {
                null
            } else {
                StateCookieCodec.decode(slice, DecodeContext.Empty).takeIf { it.magic == StateCookie.MAGIC }
            }
        } finally {
            slice.freeIfNeeded()
        }
    }

    public companion object {
        /** The SCTP port WebRTC data channels use by default (RFC 8831 §6.2). */
        public const val SCTP_DATA_CHANNEL_PORT: UShort = 5000u

        private const val SACK_EVERY = 2

        /** "No tag here" — an unset Tie-Tag, and the Verification Tag of a packet that carries an INIT. */
        private val ZERO_TAG = VerificationTag(0u)
    }
}
