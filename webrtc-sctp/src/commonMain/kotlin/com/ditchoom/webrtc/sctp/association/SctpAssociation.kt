@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.ChecksumVerdict
import com.ditchoom.webrtc.sctp.DataChunkFlags
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.ErrorCauseCode
import com.ditchoom.webrtc.sctp.ErrorDetectionMethodId
import com.ditchoom.webrtc.sctp.ForwardTsnStream
import com.ditchoom.webrtc.sctp.OutboundChecksum
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
import com.ditchoom.webrtc.sctp.TransportErrorDetection
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import com.ditchoom.webrtc.sctp.ZeroChecksumAcceptance
import com.ditchoom.webrtc.sctp.ZeroChecksumParameterDecode
import com.ditchoom.webrtc.sctp.acceptanceOver
import com.ditchoom.webrtc.sctp.asSupportedExtensions
import com.ditchoom.webrtc.sctp.asZeroChecksumAcceptable
import com.ditchoom.webrtc.sctp.emissionTo
import kotlin.random.Random
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

// The RFC 8899 probe nonce carried in the Heartbeat Info parameter. File-private rather than a
// `const val` in a private companion, which is still emitted as a public static field.
private const val PROBE_NONCE_BYTES = 4
private const val BYTE_MASK = 0xFFu

// RFC 4960 §3.3.10.1: an Invalid Stream Identifier cause value is the 2-byte offending id plus 2 reserved
// bytes. File-private rather than a companion constant — a `const val` in a private companion is still
// emitted as a public static field.
private const val INVALID_STREAM_CAUSE_BYTES = 4

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
 * [errorDetection] is the one thing this machine has to be told about the layer beneath it, and it is
 * told rather than asked because the association owns no transport (ARCHITECTURE §5.1). It is what RFC
 * 9653 negotiation is *about*: a transport that detects errors itself is what makes the CRC32c redundant.
 * Defaults to [TransportErrorDetection.CrcOnly], so an association built without it behaves exactly as it
 * did before RFC 9653 existed.
 *
 * **Path liveness** is intentionally delegated, not duplicated. An association with no outstanding data
 * does not itself detect a silently-dead peer; in WebRTC that is covered a layer down by ICE consent
 * freshness (RFC 7675), which tears down the transport on a dead path and thereby closes the association.
 * So there is no SCTP heartbeat *timer* here, and no liveness use of HEARTBEAT at all.
 *
 * That is now a claim about **why** HEARTBEATs are sent rather than whether they are. RFC 8899 path-MTU
 * probing (see [PathMtuTracker]) originates a HEARTBEAT carrying a nonce, padded to a candidate size, and
 * reads the HEARTBEAT-ACK as confirmation that the size fits — so the chunk type is on the wire, scoped
 * to that one purpose. The distinction is worth keeping sharp: a probe answers "how big may a datagram
 * be", never "is the peer alive", and nothing here arms a timer on the second question.
 */
public class SctpAssociation(
    private val config: SctpConfig = SctpConfig(),
    @Suppress("UnseamedEntropy") private val random: Random = Random.Default,
    private val localPort: UShort = SCTP_DATA_CHANNEL_PORT,
    private val remotePort: UShort = SCTP_DATA_CHANNEL_PORT,
    private val errorDetection: TransportErrorDetection = TransportErrorDetection.CrcOnly,
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

    /**
     * What the handshake settled (see [Negotiated]), or [Negotiated.None] while there is no association.
     *
     * A projection of [Tcb.Live] rather than a field, so there is exactly one copy of these facts and it
     * dies with the control block that learned them. Internal-readable for the same reason the
     * verification tags above are: a fixture has to be able to see that a teardown cleared the peer's
     * advertised capabilities, and no output carries that fact.
     */
    internal val negotiated: Negotiated
        get() =
            when (val current = tcb) {
                Tcb.NoAssociation -> Negotiated.None
                is Tcb.Live -> current.negotiated
            }

    /** The peer's advertised RFC 3758 / RFC 6525 extensions — test-visible, see [negotiated]. */
    internal val peerExtensions: PeerExtensions get() = negotiated.extensions

    /** Inbound streams this association negotiated: `min(our MIS, the peer's OS)` (RFC 4960 §5.1.1). */
    internal val negotiatedInboundStreams: UShort get() = negotiated.incomingStreams.value

    /**
     * How many outgoing streams this endpoint may use (RFC 4960 §5.1.1), for the data-channel layer's
     * stream-id allocator. Also emitted as [SctpOutput.OutgoingCapacityChanged] so a sans-io driver never
     * has to poll for it; this accessor exists because a fixture asserting the *handshake* should not have
     * to reconstruct it from an output list.
     */
    internal val outgoingCapacity: OutgoingStreamCapacity
        get() =
            when (val current = tcb) {
                Tcb.NoAssociation -> OutgoingStreamCapacity.NotNegotiated
                is Tcb.Live -> OutgoingStreamCapacity.Negotiated(current.negotiated.outgoingStreams)
            }

    /**
     * The peer's Maximum Inbound Streams, as its most recent INIT or INIT ACK advertised it — the ceiling
     * RFC 4960 §5.1.1 puts on how many outgoing streams this endpoint may use.
     *
     * Held as a hint rather than derived at establish time because the two roles learn it at different
     * moments. The initiator has the INIT ACK in hand when the control block is built; the **responder**
     * learned it from an INIT it answered statelessly, and the COOKIE ECHO carries no stream counts at
     * all — the State Cookie's own `peerMaxInbound` is the *other* minimum (`min(our MIS, the peer's OS)`),
     * which says nothing about how many streams the peer will accept from us.
     *
     * It is a single scalar, so a stateless responder still retains no TCB per INIT, and it is only ever
     * used to **lower** `config.outboundStreams`: an endpoint that never heard a number keeps its own, and
     * a peer that interleaves INITs can only make us more conservative than its last word or as generous
     * as our own configuration — never more. A peer restart (§5.2.4 action A) clears it with the rest of
     * the control block and therefore falls back to our configured value, which is the safe direction.
     */
    private var peerMaxInboundStreams: StreamCount = StreamCount.Max

    /**
     * RFC 9653 §5.3, the **receive** direction: whether a packet arriving with a zero checksum may be
     * processed on the transport's guarantee instead of the CRC32c.
     *
     * A `val`, and settled before a single byte is exchanged, because §5.3 keys the obligation on what we
     * *sent* — and what we send is decided entirely by our own policy and our own transport, neither of
     * which the peer can influence. Nothing in the handshake can widen it; a peer cannot talk us into
     * accepting an unverifiable packet by advertising anything.
     */
    internal val zeroChecksumAcceptance: ZeroChecksumAcceptance = config.zeroChecksum.acceptanceOver(errorDetection)

    /**
     * RFC 9653 §5.2, the **send** direction: whether this endpoint may leave the checksum field at zero.
     *
     * A `var`, and [OutboundChecksum.Crc32c] until the peer's own advertisement is in hand — restriction 1
     * of §5.2 makes that the only safe starting point, and it is also why this is a separate field from
     * [zeroChecksumAcceptance] rather than a projection of it. Advertising says "I will accept one from
     * you"; it grants nothing in this direction. Collapsing the two into one "zero checksum negotiated"
     * flag is the failure this shape exists to make unrepresentable: read as permission to send, every
     * packet we emit is dropped by a peer that never agreed to receive one, and the association dies
     * looking exactly like a dead path.
     *
     * Internal-readable for the same reason [peerExtensions] is: no output carries it, so a fixture has no
     * other way to see which direction was settled.
     */
    internal var outboundChecksum: OutboundChecksum = OutboundChecksum.Crc32c
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

    /**
     * What the layer below has said about the path it carries us on (RFC 8261 §6.1). [SctpPathProfile]
     * for why this is sealed rather than a nullable, and [SctpEvent.PathChanged] for who sets it.
     *
     * Internal-readable for the same reason the verification tags are: no output carries the profile, so a
     * fixture asserting that a re-statement was adopted without a reset has no other way to see it.
     */
    internal var pathProfile: SctpPathProfile = SctpPathProfile.Unassessed
        private set

    /** RFC 8899 path MTU discovery for the current path — inert under [PathMtuPolicy.Fixed]. */
    private val pathMtu = PathMtuTracker(config.pathMtu)

    /**
     * The largest user-data payload one DATA chunk may carry right now (RFC 4960 §6.9).
     *
     * Three inputs, one rule: **a measurement beats configuration; an assumption does not.**
     *
     * - No profile at all → `config.maxPayloadBytes` exactly, which is the behaviour that shipped before
     *   path events existed. A driver that never sends [SctpEvent.PathChanged] is untouched by any of this.
     * - A profile, nothing probed → the smaller of `config.maxPayloadBytes` and what the family admits
     *   unprobed. The family ceiling may only *lower* the configured value: raising it would put a
     *   fragment size on the wire that nobody asked for, on the strength of a guess about the link.
     * - A probe-confirmed size → that size, whichever way it moves the configured value. It is a
     *   measurement of the path this association is actually on, and measuring it is precisely what the
     *   caller asked for by choosing [PathMtuPolicy.Discover].
     */
    internal val fragmentCeiling: Int
        get() =
            when (val measured = pathMtu.measured) {
                is MeasuredCeiling.Confirmed -> measured.ceiling.value
                MeasuredCeiling.NotMeasured ->
                    when (val profile = pathProfile) {
                        SctpPathProfile.Unassessed -> config.maxPayloadBytes
                        is SctpPathProfile.Assessed -> minOf(config.maxPayloadBytes, profile.unprobedFragmentCeiling.value)
                    }
            }

    // Retained handshake artifacts (rebuilt-identical retransmits).
    private var localInit: SctpChunk.Init? = null
    private var cookieEcho: SctpChunk.CookieEcho? = null

    // ── RFC 6525 stream reconfiguration — two state machines, each one field ──
    private var requester: ReConfigRequester = ReConfigRequester.Ready(PendingRequests())
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
     * How many more outgoing streams the upper layer has asked for but that is not yet on the wire
     * (RFC 6525 §4.5). Sealed rather than a [StreamCount] starting at zero, because zero is a value the
     * request field may not carry — so "nothing asked for" and "asked for none" would be the same number
     * meaning two different things.
     */
    private sealed interface PendingGrowth {
        data object None : PendingGrowth

        data class Streams(
            val count: StreamCount,
        ) : PendingGrowth

        /** Accumulate: several opens waiting on capacity ride one request (§5.1.2 will not overlap two). */
        fun plus(more: StreamCount): PendingGrowth =
            when (this) {
                None -> if (more == StreamCount.None) None else Streams(more)
                is Streams -> Streams(count.plusSaturating(more))
            }
    }

    /** Everything the upper layer has asked for that is waiting for the wire to be free. */
    private data class PendingRequests(
        val reset: PendingReset = PendingReset.Nothing,
        val growth: PendingGrowth = PendingGrowth.None,
    )

    /**
     * A RE-CONFIG request this endpoint originated, retained whole while it is outstanding so the
     * retransmit timer re-emits it **byte-identically** — a re-derived reset would carry a newer
     * last-assigned TSN, which the peer reads as a *different* request at the same sequence number.
     *
     * Sealed over the two kinds this subset originates, because RFC 6525 §5.1.2 allows only one request
     * outstanding at a time across **both** of them: a reset and a stream-count increase share one slot,
     * one sequence number space and one retransmit timer. Modelling them as two independent state
     * machines would let both be on the wire at once, which the peer answers with
     * `ErrorRequestAlreadyInProgress` for whichever it saw second.
     */
    private sealed interface ReConfigRequest {
        val sequence: ReConfigRequestSequenceNumber

        /** The wire form, re-emitted unchanged on every retransmit. */
        val parameter: ReConfigParameter

        data class Reset(
            override val sequence: ReConfigRequestSequenceNumber,
            val scope: StreamResetScope,
            override val parameter: ReConfigParameter.OutgoingSsnReset,
        ) : ReConfigRequest

        data class AddOutgoing(
            override val sequence: ReConfigRequestSequenceNumber,
            val count: StreamCount,
            override val parameter: ReConfigParameter.AddOutgoingStreams,
        ) : ReConfigRequest
    }

    /**
     * The requester half (RFC 6525 §5.1.2): at most one request may be outstanding, which is why this is
     * one field with two states rather than a nullable "in flight" beside a queue. Both states carry the
     * pending set, so anything asked for at any moment has exactly one place to go.
     */
    private sealed interface ReConfigRequester {
        /** What has piled up behind whatever this state is doing. */
        val pending: PendingRequests

        /** Nothing on the wire — [pending] goes out as soon as the association can send it. */
        data class Ready(
            override val pending: PendingRequests,
        ) : ReConfigRequester

        /** [request] is on the wire and unanswered. */
        data class InFlight(
            val request: ReConfigRequest,
            override val pending: PendingRequests,
        ) : ReConfigRequester

        /** The same state with a different pending set — the one mutation both variants share. */
        fun withPending(pending: PendingRequests): ReConfigRequester =
            when (this) {
                is Ready -> copy(pending = pending)
                is InFlight -> copy(pending = pending)
            }
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
            is SctpEvent.PathChanged -> onPathChanged(event.path, now, out)
            is SctpEvent.RequestMoreOutgoingStreams -> onRequestMoreOutgoingStreams(event.count, now, out)
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
                parameters = handshakeParameters(),
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
        // The peer's MIS, kept for the moment the COOKIE ECHO comes home — see [peerMaxInboundStreams].
        // Recorded before the SHUTDOWN-ACK-SENT early return below, because that path answers a *previous*
        // association and never reaches an establish that could read it.
        peerMaxInboundStreams = StreamCount(init.inboundStreams)
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
        // Read once and used twice: the cookie carries it across the handshake the responder holds no TCB
        // through, and it also decides the checksum on the INIT ACK this call is about to emit.
        val peerZeroChecksum = init.parameters.zeroChecksumAdvertised()
        val cookie =
            encodeCookie(
                StateCookie(
                    magic = StateCookie.MAGIC,
                    peerTag = init.initiateTag,
                    peerInitialTsn = init.initialTsn,
                    peerRwnd = init.advertisedReceiverWindow,
                    // RFC 4960 §5.1.1: the association carries min(our MIS, the peer's OS) inbound
                    // streams. Computed here because the COOKIE ECHO carries no stream counts, so this is
                    // the last moment the peer's number is in hand.
                    peerMaxInbound = minOf(config.inboundStreams, init.outboundStreams),
                    capabilities =
                        PeerCapabilities.of(
                            forwardTsn = init.supportsForwardTsn(),
                            reConfig = init.parameters.advertiseReConfig(),
                        ),
                    // RFC 9653 §5.2 restriction 1: permission to emit a zero checksum comes from the
                    // peer's advertisement, which arrives in this INIT and is gone by the time the COOKIE
                    // ECHO returns — the responder keeps no TCB in between. There is nothing to re-derive
                    // it from either; the echo carries no parameters of its own.
                    peerZeroChecksum = peerZeroChecksum,
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
                parameters = listOf(cookieParameter) + handshakeParameters(),
            )
        // The INIT ACK is the one packet whose checksum permission is derived rather than stored. RFC 9653
        // §5.2 does not list the INIT ACK among the chunks that force a CRC32c — by the time we answer an
        // INIT we have already read what it advertised — but a stateless responder has nowhere to keep
        // that answer, so it is computed for this emit and forgotten with everything else.
        emitPacket(listOf(initAck), init.initiateTag, out, config.zeroChecksum.emissionTo(peerZeroChecksum, errorDetection))
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
        // RFC 4960 §3.3.2 forbids zero in either stream field of an INIT **or** an INIT ACK, and the
        // consequence of accepting one is worse on this side: a zero OS means the peer will never send on
        // any stream, and a zero MIS means every id we allocate is out of range, so the association comes
        // up healthy and carries nothing. The INIT arm of this check has always existed; this is its
        // mirror, and without it the initiator was the one side that could not see the violation.
        if (initAck.outboundStreams == 0u.toUShort() || initAck.inboundStreams == 0u.toUShort()) {
            abortWith(SctpFailureReason.ProtocolViolation(ProtocolViolationKind.ZeroStreams), reflectTag = initAck.initiateTag, out)
            return
        }
        val cookieParam = initAck.stateCookie()
        if (cookieParam == null) {
            abortWith(SctpFailureReason.ProtocolViolation(ProtocolViolationKind.MissingStateCookie), reflectTag = initAck.initiateTag, out)
            return
        }
        peerVerificationTag = initAck.initiateTag
        peerMaxInboundStreams = StreamCount(initAck.inboundStreams)
        // RFC 9653 §5.2 restriction 1: the INIT ACK is where the initiator learns whether the peer will
        // accept a zero checksum. Settled here and nowhere else on this path — the COOKIE ECHO we are
        // about to send must carry a real CRC32c regardless (§5.2 restriction 2).
        outboundChecksum = config.zeroChecksum.emissionTo(initAck.parameters.zeroChecksumAdvertised(), errorDetection)
        // The initiator never mints a cookie, so it settles both §5.1.1 minima straight off the INIT ACK.
        // Both sides must reach the same inbound number or they disagree about which stream ids exist.
        establishControlBlocks(
            peerInitialTsn = initAck.initialTsn,
            peerRwnd = initAck.advertisedReceiverWindow,
            negotiated =
                Negotiated(
                    extensions =
                        PeerExtensions(
                            forwardTsn = initAck.parameters.any { it.type == com.ditchoom.webrtc.sctp.ParameterType.ForwardTsnSupported },
                            reConfig = initAck.parameters.advertiseReConfig(),
                        ),
                    outgoingStreams = StreamCount(minOf(config.outboundStreams, initAck.inboundStreams)),
                    incomingStreams = StreamCount(minOf(config.inboundStreams, initAck.outboundStreams)),
                ),
            out = out,
        )
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
                    maybeSendReConfig(now, out)
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
        // The responder's half of RFC 9653 §5.2 restriction 1: the peer's advertisement was read off an
        // INIT this endpoint deliberately kept no state about, so the cookie is the only place it survives.
        outboundChecksum = config.zeroChecksum.emissionTo(cookie.peerZeroChecksum, errorDetection)
        establishControlBlocks(
            peerInitialTsn = cookie.peerInitialTsn,
            peerRwnd = cookie.peerRwnd,
            negotiated =
                Negotiated(
                    extensions =
                        PeerExtensions(forwardTsn = cookie.capabilities.forwardTsn, reConfig = cookie.capabilities.reConfig),
                    // The cookie carries the inbound minimum; the outbound one is bounded by the peer's
                    // MIS, which only the INIT/INIT ACK said — see [peerMaxInboundStreams].
                    outgoingStreams = StreamCount(minOf(config.outboundStreams, peerMaxInboundStreams.value)),
                    incomingStreams = StreamCount(cookie.peerMaxInbound),
                ),
            out = out,
        )
        emitPacket(listOf(SctpChunk.CookieAck), peerVerificationTag, out)
        transition(SctpAssociationState.Established, out)
        cancelHandshake()
        clearCookieEcho()
        trySend(now, out)
        maybeSendReConfig(now, out)
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
        maybeSendReConfig(now, out)
    }

    private fun establishControlBlocks(
        peerInitialTsn: Tsn,
        peerRwnd: UInt,
        negotiated: Negotiated,
        out: MutableList<SctpOutput>,
    ) {
        val retransmission = RetransmissionQueue(config, localInitialTsn)
        retransmission.setPeerReceiveWindow(peerRwnd)
        tcb =
            Tcb.Live(
                retransmission = retransmission,
                reassembly = ReassemblyQueue(peerInitialTsn, config),
                negotiated = negotiated,
            )
        // The stream-id allocator above this layer cannot pick an id until it knows the ceiling, and the
        // ceiling only exists from here on. Emitted rather than polled so the driver stays sans-io.
        out += SctpOutput.OutgoingCapacityChanged(OutgoingStreamCapacity.Negotiated(negotiated.outgoingStreams))
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
        //
        // Written as an exhaustive `when` rather than the Boolean projection so that RFC 9653's
        // `AcceptedZero` cannot be introduced without this site being asked what to do about it. That is
        // the one place in the receive path where getting it wrong is invisible: an accepted-but-
        // unverifiable packet dropped here looks exactly like a peer that went quiet.
        //
        // The acceptance passed is what WE advertised (RFC 9653 §5.3) — never what the peer permitted us
        // to send. A peer we made no promise to gets the RFC 4960 §6.8 rule unchanged, so its zero
        // checksum is a Mismatch and its packet is discarded.
        when (packet.validateChecksum(zeroChecksumAcceptance)) {
            ChecksumVerdict.Verified, ChecksumVerdict.AcceptedZero -> Unit
            ChecksumVerdict.Mismatch, ChecksumVerdict.NotFromWire -> return
        }
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
                is SctpChunk.HeartbeatAck -> onHeartbeatAck(chunk, now, out)
                is SctpChunk.Abort -> {
                    fail(SctpFailureReason.AbortReceived, out)
                    return
                }
                is SctpChunk.Shutdown -> onShutdown(chunk, now, out)
                SctpChunk.ShutdownAck -> onShutdownAck(out)
                is SctpChunk.ShutdownComplete -> onShutdownComplete(out)
                is SctpChunk.Error -> Unit
                is SctpChunk.ReConfig -> onReConfig(chunk, now, out)
                // RFC 4820 §3: padding, by definition carrying nothing. This codec never decodes an
                // inbound type 132 into this variant (it stays Unrecognized — see SctpChunk.Pad), so this
                // arm is only reachable from a hand-built packet in a fixture. Either way the answer is
                // the same one RFC 4960 §3.2 gives for a skippable chunk: ignore it, keep processing.
                is SctpChunk.Pad -> Unit
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
        val live = tcb.liveOrElse { return }
        // RFC 4960 §3.3.10.1: a DATA chunk naming a stream outside the number this association negotiated
        // is refused with an ERROR, not reassembled. Until now the number was settled and then never read,
        // so a peer could open reassembly state on any of 65536 ids regardless of what it agreed to — a
        // peer-paced allocator, reachable before any application ever sees the stream.
        //
        // The TSN is still acknowledged. Dropping it outright leaves our cumulative point below it, so the
        // peer retransmits the same refused chunk until its error counter aborts the association — the
        // exact failure this module already avoids by *answering* the RE-CONFIG requests it will not
        // perform rather than ignoring them.
        //
        // This gate precedes reassembly deliberately: it is the cheaper of the two peer-paced-allocator
        // refusals, and a chunk on a stream that does not exist should never reach the message-size
        // accounting that the other one guards.
        if (!live.negotiated.incomingStreams.admits(chunk.streamId)) {
            live.reassembly.discard(chunk.tsn)
            emitPacket(listOf(SctpChunk.Error(listOf(invalidStreamIdentifier(chunk.streamId)))), peerVerificationTag, out)
            return
        }
        when (val ingest = live.reassembly.receive(chunk)) {
            is ChunkIngest.Delivered ->
                for (message in ingest.messages) {
                    out += SctpOutput.MessageReceived(message.streamId, message.ppid, message.unordered, message.payload)
                }
            // The peer is sending a message larger than we advertised we would take (RFC 8841 §6), which
            // RFC 8831 §6.6 forbids. Nothing was stored, so there is no partial message to release —
            // `fail` below drains the rest — and nothing further in this packet is processed, because
            // every remaining handler unwraps the TCB this tears down.
            is ChunkIngest.MessageTooLarge -> abortOversizedMessage(ingest, out)
        }
    }

    /**
     * ABORT because the peer overran the ceiling we advertised (RFC 4960 §3.3.7 with a §3.3.10 Protocol
     * Violation cause, code 13).
     *
     * Not [abortWith]: that one reflects the peer's own tag (T bit set), which is what an endpoint with
     * no TCB must do. Here there is a live association, so the ABORT carries the peer's verification tag
     * in the header with T clear — an out-of-the-blue-shaped ABORT from an association that exists would
     * be discarded by a correct peer's RFC 4960 §8.5.1 checks, and the peer would keep sending.
     *
     * The cause carries no cause-specific text. RFC 4960 §3.3.10.13 permits some, but a string is a
     * diagnostic and never a discriminant (directive #3) — everything actionable is already in the typed
     * [SctpFailureReason.PeerMessageTooLarge] this endpoint reports upward.
     */
    private fun abortOversizedMessage(
        ingest: ChunkIngest.MessageTooLarge,
        out: MutableList<SctpOutput>,
    ) {
        emitPacket(
            listOf(
                SctpChunk.Abort(
                    verificationTagReflected = false,
                    causes = listOf(SctpErrorCause.empty(ErrorCauseCode.ProtocolViolation)),
                ),
            ),
            peerVerificationTag,
            out,
        )
        fail(SctpFailureReason.PeerMessageTooLarge(ingest.streamId, ingest.ceilingBytes, ingest.observedBytes), out)
    }

    /**
     * The RFC 4960 §3.3.10.1 Invalid Stream Identifier cause: the offending id, then two reserved bytes.
     *
     * The declared value is allocated from the injected factory and released here — `SctpErrorCause.ofValue`
     * copies it into its own padded buffer, so this function is its last reader (directive #6).
     */
    private fun invalidStreamIdentifier(streamId: StreamId): SctpErrorCause {
        val value = config.bufferFactory.allocate(INVALID_STREAM_CAUSE_BYTES, ByteOrder.BIG_ENDIAN)
        return try {
            value.writeByte(((streamId.value shr Byte.SIZE_BITS) and 0xFF).toByte())
            value.writeByte((streamId.value and 0xFF).toByte())
            value.writeByte(0)
            value.writeByte(0)
            value.resetForRead()
            value.setLimit(INVALID_STREAM_CAUSE_BYTES)
            SctpErrorCause.ofValue(ErrorCauseCode.InvalidStreamIdentifier, value)
        } finally {
            value.freeIfNeeded()
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

    // ────────────────────────────────── the path underneath ──────────────────────────────────

    /**
     * RFC 8261 §6.1: the lower layer says the path changed, so *"SCTP SHOULD retest the path MTU and reset
     * the congestion state to the initial state"*.
     *
     * Three cases, decided by [PathIdentity] and nothing else:
     *
     * - **First assessment.** Adopt the profile and reset **nothing**. There was no previous path, so
     *   there is no measurement describing one — and cwnd/SRTT at this point are the initial values a
     *   reset would restore anyway. Resetting here would look harmless and would be: it is skipped
     *   because "a path change resets measurements" and "learning what the path is resets measurements"
     *   are different claims, and only the first is true.
     * - **A re-statement** (the same identity). Adopt the profile — the family or the overhead may have
     *   been recomputed — and reset nothing. This is what lets a session layer republish on every ICE
     *   event without filtering, which is the difference between a fold it can get wrong and one it
     *   cannot.
     * - **A migration.** Everything measured describes a link that is gone: [PathRide.onNewPath] discards
     *   cwnd, ssthresh, SRTT/RTTVAR and the RFC 4960 §8.1 consecutive-error budget as one value, and
     *   advances the epoch so an ack for a chunk sent on the old path cannot contribute an RTT sample
     *   spanning both networks.
     *
     * **T3 is disarmed here and re-armed by [trySend], deliberately.** The timer belongs to
     * [AssociationDeadlines] — the one place every timer lives — rather than beside the measurements, so
     * the migration does both halves rather than moving one timer out to keep them together. Disarming
     * without re-arming would hang an association with data outstanding, so the re-arm is not optional:
     * [trySend]'s own "outstanding data and no T3" rule arms it from the *fresh* RTO, which is precisely
     * the value RFC 8261 §6.1 asks for. Leaving the old deadline in place instead would keep a T3
     * computed from a backed-off RTO on the retired path, i.e. up to `rtoMax` of silence before the new
     * path's first retransmission.
     *
     * The error budget is the half that turns a slow recovery into a dead session: a migration is most
     * often performed *because* the old path was failing, so without this the new path inherits a budget
     * already spent and aborts every data channel on it at the next expiry.
     */
    private fun onPathChanged(
        profile: SctpPathProfile.Assessed,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val previous = pathProfile
        val ceilingBefore = fragmentCeiling
        pathProfile = profile
        // "Retest the path MTU" is the other half of §6.1's sentence, and it runs on a re-statement too:
        // the overhead may have moved (the same route re-measured through a TURN relay) even when the
        // identity has not, and every confirmed size was confirmed against the old arithmetic.
        applyPathMtu(pathMtu.onPathAssessed(profile, now, ride.rtt.rto), ceilingBefore, now, out)
        val migrated =
            when (previous) {
                SctpPathProfile.Unassessed -> false
                is SctpPathProfile.Assessed -> previous.identity != profile.identity
            }
        if (!migrated) return
        ride = ride.onNewPath()
        deadlines = deadlines.copy(t3 = Deadline.Unarmed)
        trySend(now, out)
    }

    /**
     * Apply what [PathMtuTracker] decided: put probes on the wire, publish a moved ceiling, and — when the
     * ceiling *fell* — deal with the DATA chunks that were encoded above it.
     *
     * [ceilingBefore] is measured by the caller before the tracker runs, because "did the ceiling drop" is
     * a question about the association's *effective* fragmentation point (which `SctpConfig.maxPayloadBytes`
     * still bounds while nothing is measured) and not about the raw path ceiling the effect carries.
     */
    private fun applyPathMtu(
        effects: List<PathMtuEffect>,
        ceilingBefore: Int,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        deadlines = deadlines.copy(probe = pathMtu.deadline)
        for (effect in effects) {
            when (effect) {
                is PathMtuEffect.Probe -> emitProbe(effect, out)
                is PathMtuEffect.CeilingChanged -> {
                    val backlog = if (fragmentCeiling < ceilingBefore) abandonOversized(now, out) else OversizedBacklog.None
                    out += SctpOutput.PathMtuChanged(effect.ceiling, effect.cause, backlog)
                }
            }
        }
        // The tracker's deadline moves as effects are produced (a probe arms PROBE_TIMER, a completed
        // search arms PMTU_RAISE_TIMER), so it is read again after the loop rather than only before it.
        deadlines = deadlines.copy(probe = pathMtu.deadline)
    }

    /**
     * An RFC 8899 probe: a HEARTBEAT carrying the probe nonce, followed by an RFC 4820 PAD chunk that
     * brings the datagram to the candidate size.
     *
     * Emitted as an ordinary [SctpOutput.Transmit.Owned] and tracked nowhere else, which is what makes RFC
     * 8899 §3's "a probe's loss is not a congestion signal" structural rather than remembered: it is not
     * DATA, so it never enters the retransmission queue, never counts toward the flight size, and cannot
     * reach cwnd or the RFC 4960 §8.1 error budget.
     */
    private fun emitProbe(
        probe: PathMtuEffect.Probe,
        out: MutableList<SctpOutput>,
    ) {
        val nonce = config.bufferFactory.allocate(PROBE_NONCE_BYTES, ByteOrder.BIG_ENDIAN)
        val info =
            try {
                nonce.writeUInt(probe.nonce.value)
                nonce.resetForRead()
                nonce.setLimit(PROBE_NONCE_BYTES)
                // `ofValue` copies into the parameter's own padded buffer, so the scratch buffer is dead
                // the moment the parameter exists — the same contract the State Cookie relies on.
                SctpParameter.ofValue(com.ditchoom.webrtc.sctp.ParameterType.HeartbeatInfo, nonce)
            } finally {
                nonce.freeIfNeeded()
            }
        emitPacket(listOf(SctpChunk.Heartbeat(info), SctpChunk.Pad(probe.padding)), peerVerificationTag, out)
    }

    /**
     * The path MTU dropped under DATA chunks that are already encoded at the old size, so they can never be
     * delivered (RFC 4960 §6.1 retains the encoded packet; there is no re-fragmentation without RFC 8260
     * I-DATA, which this stack deliberately does not implement).
     *
     * Unsent fragments are **adopted into the retransmission queue as abandoned** rather than dropped: their
     * TSNs were assigned at enqueue, so discarding them would leave a hole the peer's cumulative TSN can
     * never advance past. Adopting them is what lets one FORWARD-TSN cover the whole stranded run.
     *
     * Where the peer never advertised RFC 3758 support there is nothing to be done — a TSN cannot be
     * skipped, so the chunks stay and are reported. That is the honest answer rather than a silent drop:
     * the association will spend its error budget on them, and the backlog is the only warning of it.
     */
    private fun abandonOversized(
        now: Instant,
        out: MutableList<SctpOutput>,
    ): OversizedBacklog {
        val rq = tcb.liveOrElse { return OversizedBacklog.None }.retransmission
        val ceiling = fragmentCeiling
        val queued = pendingSend.count { it.bytes > ceiling }
        val stranded = rq.oversized(ceiling) + queued
        if (stranded == 0) return OversizedBacklog.None
        if (!peerExtensions.forwardTsn) return OversizedBacklog.Present(stranded)
        // Adopt in TSN order: pendingSend is already in that order and every entry is above everything the
        // queue tracks, which is the precondition adoptAbandoned states.
        val remaining = ArrayDeque<OutstandingData>(pendingSend.size)
        while (pendingSend.isNotEmpty()) {
            val next = pendingSend.removeFirst()
            if (next.bytes > ceiling) {
                pendingSendBytes -= next.bytes
                rq.adoptAbandoned(next)
            } else {
                remaining.addLast(next)
            }
        }
        pendingSend.addAll(remaining)
        flushAbandoned(rq.abandonOversized(ceiling), rq, out)
        return OversizedBacklog.Present(stranded)
    }

    // ─────────────────── stream reconfiguration (RFC 6525) — the requester half ───────────────────

    private fun onResetStreams(
        scope: StreamResetScope,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val pending = requester.pending
        requester = requester.withPending(pending.copy(reset = pending.reset.plus(scope)))
        maybeSendReConfig(now, out)
    }

    /**
     * The upper layer wants [count] more outgoing streams than the handshake settled (RFC 6525 §4.5).
     * Queued exactly like a reset, because §5.1.2 gives the two one outstanding-request slot between them.
     */
    private fun onRequestMoreOutgoingStreams(
        count: StreamCount,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        if (count == StreamCount.None) return // asking for none is a no-op; the wire cannot say it at all
        val pending = requester.pending
        requester = requester.withPending(pending.copy(growth = pending.growth.plus(count)))
        maybeSendReConfig(now, out)
    }

    /**
     * Put the pending request on the wire, if anything is pending and nothing else is outstanding (RFC 6525
     * §5.1.2). Called both when the upper layer asks and whenever the previous request is answered, so a
     * queue of channel closes and stream-count increases drains one at a time without the driver having to
     * sequence them.
     *
     * Growth goes first when both are pending. A close has already completed for its caller — the channel
     * is shut, and the reset only frees the id — while an open is *blocked* on the capacity, so putting the
     * reset first would hold a caller for a full extra round trip to no purpose.
     */
    private fun maybeSendReConfig(
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val ready = requester as? ReConfigRequester.Ready ?: return
        if (_state != SctpAssociationState.Established) return
        when (val growth = ready.pending.growth) {
            PendingGrowth.None -> Unit
            is PendingGrowth.Streams -> {
                sendAddOutgoingStreams(growth.count, ready.pending, now, out)
                return
            }
        }
        val pending = ready.pending.reset as? PendingReset.Some ?: return
        val scope = pending.scope
        // A peer that never advertised RE-CONFIG cannot be sent one (RFC 6525 §5.1). Answer the caller
        // rather than dropping the request: a channel close that is unanswerable still has to complete.
        if (!negotiated.extensions.reConfig) {
            requester = ReConfigRequester.Ready(ready.pending.copy(reset = PendingReset.Nothing))
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
        emit(ReConfigRequest.Reset(sequence, scope, request), ready.pending.copy(reset = PendingReset.Nothing), now, out)
    }

    private fun sendAddOutgoingStreams(
        count: StreamCount,
        pending: PendingRequests,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val drained = pending.copy(growth = PendingGrowth.None)
        val refusal =
            when {
                // Same rule as a reset: RFC 6525 §5.1 makes the Supported Extensions advertisement the
                // invitation, so a peer that did not send one is never sent a RE-CONFIG chunk.
                !negotiated.extensions.reConfig -> StreamAddOutcome.NotAdded.Unsupported
                // Both the §4.5 count field and the negotiated total are u16, so there is nothing truthful
                // to ask for past the ceiling. Refused here rather than clamped: a clamp would report
                // success for an increase the caller did not get.
                negotiated.outgoingStreams.wouldOverflow(count) -> StreamAddOutcome.NotAdded.WouldOverflow
                else -> null
            }
        if (refusal != null) {
            requester = ReConfigRequester.Ready(drained)
            out += SctpOutput.OutgoingStreamsAdded(count, refusal)
            return
        }
        val sequence = nextRequestSequence
        nextRequestSequence = sequence.next()
        val request = ReConfigParameter.AddOutgoingStreams(sequence, count.value)
        emit(ReConfigRequest.AddOutgoing(sequence, count, request), drained, now, out)
    }

    // The one place a request this endpoint originated goes on the wire: it becomes the single outstanding
    // request, resets the retransmit budget and arms the timer. Both kinds go through here so neither can
    // acquire a second slot RFC 6525 §5.1.2 does not have.
    private fun emit(
        request: ReConfigRequest,
        pending: PendingRequests,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        requester = ReConfigRequester.InFlight(request, pending)
        reConfigRetransmits = 0
        emitPacket(listOf(SctpChunk.ReConfig.of(request.parameter)), peerVerificationTag, out)
        armReConfig(now)
    }

    private fun onReConfigResponse(
        response: ReConfigParameter.Response,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val inFlight = requester as? ReConfigRequester.InFlight ?: return
        // A response for anything other than the request actually outstanding is stale (a duplicate of an
        // already-completed one, or a peer answering a sequence number we never sent) — discard it rather
        // than completing the live request on someone else's answer.
        if (response.responseSequenceNumber != inFlight.request.sequence) return
        if (response.result == ReConfigResult.InProgress) {
            // RFC 6525 §5.2.2: the peer is holding the reset until its cumulative TSN catches up. The
            // request stays outstanding and the timer is restarted from scratch — the peer sends the final
            // response itself, and our retransmit is what recovers it if that response is lost.
            reConfigRetransmits = 0
            armReConfig(now)
            return
        }
        requester = ReConfigRequester.Ready(inFlight.pending)
        cancelReConfig()
        when (val request = inFlight.request) {
            is ReConfigRequest.Reset -> completeReset(request, response.result, out)
            is ReConfigRequest.AddOutgoing -> completeStreamAdd(request, response.result, out)
        }
        maybeSendReConfig(now, out)
    }

    private fun completeReset(
        request: ReConfigRequest.Reset,
        result: ReConfigResult,
        out: MutableList<SctpOutput>,
    ) {
        val outcome =
            if (result.isSuccess) {
                // Our outgoing SSN state for these streams is now reset on both sides, so the next ordered
                // message on such a stream starts again at SSN 0 — which is what makes the stream id
                // reusable for a brand-new data channel (RFC 8831 §6.7).
                resetOutgoingSsn(request.scope)
                StreamResetOutcome.Performed
            } else {
                StreamResetOutcome.Refused(result)
            }
        out += SctpOutput.OutgoingStreamsReset(request.scope, outcome)
    }

    /**
     * The peer answered our Add Outgoing Streams request (RFC 6525 §4.5).
     *
     * Only `SuccessPerformed` raises the count. `SuccessNothingToDo` is reported as an answered refusal
     * rather than folded in with it: the peer is saying it did nothing, and raising our ceiling on that
     * would have us allocate a stream id it never agreed to accept — an ERROR from the peer that this
     * association discards, for a channel that opens and then delivers nothing.
     */
    private fun completeStreamAdd(
        request: ReConfigRequest.AddOutgoing,
        result: ReConfigResult,
        out: MutableList<SctpOutput>,
    ) {
        val live = tcb.liveOrElse { return }
        val outcome =
            if (result == ReConfigResult.SuccessPerformed) {
                val raised = live.negotiated.outgoingStreams.plusSaturating(request.count)
                live.negotiated = live.negotiated.copy(outgoingStreams = raised)
                out += SctpOutput.OutgoingCapacityChanged(OutgoingStreamCapacity.Negotiated(raised))
                StreamAddOutcome.Performed
            } else {
                StreamAddOutcome.NotAdded.Answered(result)
            }
        out += SctpOutput.OutgoingStreamsAdded(request.count, outcome)
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
            // The two requests this subset decodes but will not perform (see ReConfig.kt's header): an
            // Incoming SSN Reset would have us reset streams the peer does not own the sequencing of, and
            // an SSN/TSN reset would have to unwind the retransmission queue and FORWARD-TSN together.
            // Each is REFUSED, explicitly and in sequence, rather than ignored — an ignored request is
            // retransmitted until the peer's error counter aborts the whole association.
            is ReConfigParameter.IncomingSsnReset -> refuse(parameter.requestSequenceNumber, responses)
            is ReConfigParameter.SsnTsnReset -> refuse(parameter.requestSequenceNumber, responses)
            // RFC 6525 §4.5: the peer wants more streams to send ON, which are the ones we receive on.
            is ReConfigParameter.AddOutgoingStreams ->
                onPeerAddStreams(parameter.requestSequenceNumber, StreamCount(parameter.count), AddedDirection.Incoming, responses, out)
            // RFC 6525 §4.6: the peer wants more streams to receive on, which are the ones we send on.
            is ReConfigParameter.AddIncomingStreams ->
                onPeerAddStreams(parameter.requestSequenceNumber, StreamCount(parameter.count), AddedDirection.Outgoing, responses, out)
        }
    }

    /**
     * Which of **this** endpoint's two stream counts an inbound RFC 6525 add request raises. Named rather
     * than a Boolean because the mapping inverts — the peer's *outgoing* request raises our *incoming*
     * count — and a flag at the call site would read as agreeing with the parameter's own name while
     * meaning the opposite.
     */
    private enum class AddedDirection {
        /** RFC 6525 §4.6 Add Incoming Streams: this endpoint may now send on more streams. */
        Outgoing,

        /** RFC 6525 §4.5 Add Outgoing Streams: this endpoint must now accept data on more streams. */
        Incoming,
    }

    /**
     * The peer is asking this association to grow (RFC 6525 §4.5 / §4.6). Honoured rather than denied: the
     * counts are ours to raise, growing costs nothing, and a peer that has to open more channels than the
     * handshake allowed has no other way to say so.
     *
     * It runs through [admit] like every other inbound request, and that is the load-bearing part. A
     * retransmitted add request answered by *processing* it again would raise the count a second time —
     * silently, since both answers are Success — and leave the two endpoints disagreeing about how many
     * streams exist, which is the disagreement the whole §5.2.1 repeat rule exists to prevent.
     */
    private fun onPeerAddStreams(
        sequence: ReConfigRequestSequenceNumber,
        count: StreamCount,
        direction: AddedDirection,
        responses: MutableList<ReConfigParameter>,
        out: MutableList<SctpOutput>,
    ) {
        when (val admission = admit(sequence)) {
            is RequestAdmission.Answer -> {
                responses += admission.response
                return
            }
            RequestAdmission.Process -> Unit
        }
        val live = tcb.liveOrElse { return }
        val current =
            when (direction) {
                AddedDirection.Outgoing -> live.negotiated.outgoingStreams
                AddedDirection.Incoming -> live.negotiated.incomingStreams
            }
        // RFC 6525 §4.5 forbids a zero count, and neither total can pass what a u16 holds.
        val performed = count != StreamCount.None && !current.wouldOverflow(count)
        if (performed) {
            val raised = current.plusSaturating(count)
            live.negotiated =
                when (direction) {
                    AddedDirection.Outgoing -> live.negotiated.copy(outgoingStreams = raised)
                    AddedDirection.Incoming -> live.negotiated.copy(incomingStreams = raised)
                }
            // Only the outgoing direction is anyone else's business: it is the ceiling the stream-id
            // allocator reads. A larger inbound count is enforced by the guard in onData and by nothing
            // above it.
            if (direction == AddedDirection.Outgoing) {
                out += SctpOutput.OutgoingCapacityChanged(OutgoingStreamCapacity.Negotiated(raised))
            }
        }
        val response =
            ReConfigParameter.Response(sequence, if (performed) ReConfigResult.SuccessPerformed else ReConfigResult.Denied)
        responses += response
        peerRequests = PeerRequests.Answered(sequence, response)
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
            requester as? ReConfigRequester.InFlight ?: run {
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
        emitPacket(listOf(SctpChunk.ReConfig.of(inFlight.request.parameter)), peerVerificationTag, out)
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
        if (deadlines.probe.dueAt(now)) {
            // Read before the tracker runs: `fragmentCeiling` is derived from what the tracker has
            // measured, so evaluating it as an argument would read it *after* the call that changes it.
            val ceilingBefore = fragmentCeiling
            applyPathMtu(pathMtu.onTimer(now, ride.rtt.rto), ceilingBefore, now, out)
        }
    }

    /**
     * A HEARTBEAT-ACK came back. RFC 4960 §3.3.6 requires it echo the Heartbeat Info parameter verbatim,
     * so the probe nonce inside it is what says *which size* the path just demonstrated it carries.
     *
     * An ACK that carries no nonce we minted is discarded silently — it is a peer answering a HEARTBEAT of
     * its own devising, or a probe from a path we have since left. Matching on the nonce rather than
     * merely on "a HEARTBEAT-ACK arrived" is what stops a late answer confirming a size the search has
     * already refuted, which is the one outcome a PMTU search must never produce.
     */
    private fun onHeartbeatAck(
        chunk: SctpChunk.HeartbeatAck,
        now: Instant,
        out: MutableList<SctpOutput>,
    ) {
        val nonce = chunk.info.probeNonce() ?: return
        val ceilingBefore = fragmentCeiling
        applyPathMtu(pathMtu.onProbeAcknowledged(nonce, now, ride.rtt.rto), ceilingBefore, now, out)
    }

    /**
     * The probe nonce inside a Heartbeat Info parameter, or null when this is not one of ours.
     *
     * Null is the honest answer here rather than a typed reject: an unrecognised HEARTBEAT-ACK is not a
     * protocol violation and produces no outcome at all — it is genuinely absent information, which is the
     * one meaning a nullable is allowed to carry.
     */
    private fun SctpParameter.probeNonce(): ProbeNonce? {
        if (type != com.ditchoom.webrtc.sctp.ParameterType.HeartbeatInfo || length < PROBE_NONCE_BYTES) return null
        val view = paddedValue
        val base = view.position()
        var value = 0u
        for (i in 0 until PROBE_NONCE_BYTES) value = (value shl Byte.SIZE_BITS) or (view[base + i].toUInt() and BYTE_MASK)
        return ProbeNonce(value)
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
        val live = tcb.liveOrElse { return }
        val rq = live.retransmission
        if (!live.negotiated.extensions.forwardTsn) return
        flushAbandoned(rq.abandonExpired(now), rq, out)
    }

    /**
     * Tell the peer to stop waiting for whatever was just abandoned (RFC 3758 §3.5), and reclaim the
     * encoded packets the FORWARD-TSN now covers.
     *
     * Shared by the two things that abandon chunks — a partial-reliability budget running out, and a path
     * MTU that dropped underneath already-encoded bytes. They decide *which* chunks for entirely different
     * reasons and the wire consequence is identical, which is exactly the line to draw: a second copy of
     * this would be a second place to get the advanced-ack-point arithmetic wrong.
     */
    private fun flushAbandoned(
        skips: List<Pair<StreamId, StreamSequenceNumber>>,
        rq: RetransmissionQueue,
        out: MutableList<SctpOutput>,
    ) {
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
        requester = ReConfigRequester.Ready(PendingRequests())
        peerRequests = PeerRequests.NoneYet(ReConfigRequestSequenceNumber(0u))
        // Permission to emit a zero checksum was granted by the peer that is going away, and RFC 9653
        // §5.2 restriction 1 forbids carrying it into an association whose peer has not granted it again.
        // A survivor here is the quietest failure in this file: every packet of the next association is
        // discarded by a peer that never agreed, with nothing malformed anywhere to explain it.
        outboundChecksum = OutboundChecksum.Crc32c
        // What the departing peer advertised and how many streams it agreed to now go with the control
        // block that learned them — nothing to reset here, which is the whole reason [Negotiated] lives on
        // [Tcb.Live]. The one fact that outlives it is the hint below, because it is the *input* to the
        // next negotiation rather than its result, and a stale one would quietly cap the next association.
        peerMaxInboundStreams = StreamCount.Max
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
    //
    // [outbound] defaults to what this association negotiated, and is passed explicitly by exactly one
    // caller: the stateless responder answering an INIT, which has the peer's advertisement in hand for
    // the length of that call and stores none of it (RFC 4960 §5.1.3).
    private fun emitPacket(
        chunks: List<SctpChunk>,
        headerTag: VerificationTag,
        out: MutableList<SctpOutput>,
        outbound: OutboundChecksum = outboundChecksum,
    ) {
        out += SctpOutput.Transmit.Owned(encodePacket(chunks, headerTag, outbound))
    }

    private fun encodePacket(
        chunks: List<SctpChunk>,
        headerTag: VerificationTag,
        outbound: OutboundChecksum = outboundChecksum,
    ): PlatformBuffer {
        val builder = SctpPacketBuilder(localPort, remotePort, headerTag)
        for (chunk in chunks) builder.add(chunk)
        return builder.encode(config.bufferFactory, outbound)
    }

    /**
     * Split one user message into per-chunk payloads of at most [fragmentCeiling] (RFC 4960 §6.9). The
     * results are **zero-copy views over the caller's borrowed payload**, valid only for the duration of
     * this `handle` call — [onSendMessage] consumes each one immediately by encoding it into its wire
     * packet, which is the copy that survives. A sub-MTU message is therefore not copied here at all; it
     * is simply the whole payload as one view.
     *
     * The ceiling is read **once** per message rather than per fragment: a path event cannot land
     * mid-`handle` (the core is a serialized state machine), but reading it once is what guarantees every
     * fragment of one message is sized against one path, which the count computed just below assumes.
     */
    private fun fragment(payload: ReadBuffer): List<ReadBuffer> {
        val ceiling = fragmentCeiling
        val slice = payload.slice()
        val total = slice.remaining()
        if (total <= ceiling) return listOf(slice)
        val out = ArrayList<ReadBuffer>((total + ceiling - 1) / ceiling)
        var offset = 0
        while (offset < total) {
            val len = minOf(ceiling, total - offset)
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

    /**
     * The parameters both the INIT and the INIT ACK carry (RFC 9653 §4 allows Zero Checksum Acceptable in
     * exactly those two chunks and nowhere else).
     *
     * One list for both, because advertising in only one of them is an asymmetry with no honest reading:
     * whichever role this endpoint ends up playing, §5.3 binds it to accept what it advertised, and
     * [zeroChecksumAcceptance] does not depend on the role.
     */
    private fun handshakeParameters(): List<SctpParameter> {
        val parameters = mutableListOf(SctpParameter.forwardTsnSupported(), supportedExtensions())
        when (val acceptance = zeroChecksumAcceptance) {
            ZeroChecksumAcceptance.RequireCrc32c -> Unit
            is ZeroChecksumAcceptance.Advertised -> parameters += SctpParameter.zeroChecksumAcceptable(acceptance.method)
        }
        return parameters
    }

    /**
     * The error detection method a peer's INIT/INIT-ACK parameters advertise, or
     * [ErrorDetectionMethodId.Reserved] when they advertise none (RFC 9653 §8 reserves 0 for exactly this
     * — there is no "was it present" Boolean to carry).
     *
     * `first` rather than `any`, the opposite of [advertiseReConfig], because RFC 9653 §4 says the
     * parameter "MUST NOT appear more than once in any chunk". A peer that sends two has contradicted
     * itself and there is no join over method identifiers that would combine them, so the first one wins.
     *
     * A malformed parameter is skipped rather than propagated: type 0x8001's high bits mandate
     * skip-and-continue, so it must not cost the peer its association, and a length we cannot trust is not
     * evidence of a method we should rely on either.
     */
    private fun List<SctpParameter>.zeroChecksumAdvertised(): ErrorDetectionMethodId {
        for (parameter in this) {
            when (val decoded = parameter.asZeroChecksumAcceptable()) {
                ZeroChecksumParameterDecode.NotZeroChecksum -> Unit
                is ZeroChecksumParameterDecode.Malformed -> Unit
                is ZeroChecksumParameterDecode.Advertised -> return decoded.method
            }
        }
        return ErrorDetectionMethodId.Reserved
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
