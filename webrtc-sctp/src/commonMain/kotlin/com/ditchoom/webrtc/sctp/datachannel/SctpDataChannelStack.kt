@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.Receiver
import com.ditchoom.buffer.flow.Sender
import com.ditchoom.buffer.flow.StreamMux
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.OutgoingStreamCapacity
import com.ditchoom.webrtc.sctp.association.SctpAssociation
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpEvent
import com.ditchoom.webrtc.sctp.association.SctpFailureReason
import com.ditchoom.webrtc.sctp.association.SctpOutput
import com.ditchoom.webrtc.sctp.association.SctpPathProfile
import com.ditchoom.webrtc.sctp.association.SctpReliability
import com.ditchoom.webrtc.sctp.association.SctpSendOptions
import com.ditchoom.webrtc.sctp.association.StreamAddOutcome
import com.ditchoom.webrtc.sctp.association.StreamCount
import com.ditchoom.webrtc.sctp.association.StreamGrowthPolicy
import com.ditchoom.webrtc.sctp.association.StreamResetOutcome
import com.ditchoom.webrtc.sctp.association.StreamResetScope
import com.ditchoom.webrtc.sctp.dcep.ChannelType
import com.ditchoom.webrtc.sctp.dcep.DataChannelDecodeResult
import com.ditchoom.webrtc.sctp.dcep.DataChannelMessage
import com.ditchoom.webrtc.sctp.dcep.Reliability
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * A WebRTC **data-channel multiplexer** (RFC 8831 + DCEP RFC 8832) presented as a buffer-flow
 * [StreamMux]<[ReadBuffer]> — [openBidirectional] gives a [Connection] whose `send` is one data-channel
 * message and whose `receive` is the inbound message flow (DESIGN_PRINCIPLES §7: the consumer contract
 * is the mux, WebRTC is one implementation of it).
 *
 * It owns a sans-io [SctpAssociation] and drives it over an injected [SctpDatagramTransport] (the
 * DTLS-shaped seam) on an injected [scope] + [clock] — all I/O and timing are seams, so the whole stack
 * runs under `runTest` virtual time (ARCHITECTURE §5.1). Every `association.handle(...)` call is serialized
 * through the single [driveLoop]; consumer `open`/`send`/`close` calls post commands into the same
 * inbox, so the non-thread-safe core is only ever touched from one coroutine.
 *
 * Stream ids follow RFC 8832 §6: a [SctpRole.Client] opener uses even ids and sends the INIT; a
 * [SctpRole.Server] uses odd ids. Closing one channel is an **SCTP stream reset** (RFC 6525 RE-CONFIG,
 * RFC 8831 §6.7): [Connection.close] resets the outgoing stream, the peer answers by resetting its own
 * outgoing half, and only once both directions are reset is the stream id recycled for a future open —
 * which is what keeps a long-lived session from walking off the end of the 16-bit stream space.
 */
public class SctpDataChannelStack(
    private val transport: SctpDatagramTransport,
    private val scope: CoroutineScope,
    private val clock: () -> Instant,
    private val role: SctpRole,
    config: SctpConfig = SctpConfig(),
    @Suppress("UnseamedEntropy") random: Random = Random.Default,
) : StreamMux<DataChannelPayload> {
    // The association is sans-io and owns no transport, so what the transport guarantees has to be handed
    // to it (ARCHITECTURE §5.1). This is the only place both are in scope, which is why the wiring lives
    // here rather than in SctpConfig: a transport's integrity guarantee is a fact about the transport, not
    // a knob a caller sets beside its RTO bounds.
    private val association = SctpAssociation(config, random, errorDetection = transport.errorDetection)
    private val bufferFactory = config.bufferFactory

    private val inbox = Channel<DriveItem>(Channel.UNLIMITED)

    /**
     * Outgoing work in strict emission order. Carries **releases as well as sends** (see [OutboundItem]):
     * a packet the association has finished with must not be freed while a send of it is still queued
     * ahead, and this queue — which already exists to keep the wire deterministic — is exactly the
     * ordering that makes that impossible.
     */
    private val outbound = Channel<OutboundItem>(Channel.UNLIMITED)
    private val accepted = Channel<DataChannelConnection>(Channel.UNLIMITED)
    private val channels = HashMap<StreamId, DataChannelConnection>()
    private val pendingOpens = ArrayDeque<OpenCommand>()

    // Inbound user messages that arrived before their channel's DCEP OPEN registered the stream — held
    // briefly (bounded) and flushed when the OPEN lands, so an unordered first message that SCTP delivers
    // ahead of the still-in-order OPEN is not silently lost. Bounded to defeat a peer that never OPENs.
    private val pendingInbound = HashMap<StreamId, ArrayDeque<PendingInbound>>()
    private var closed = false

    // The peer's `a=max-message-size` (RFC 8841 §6). Read and written ONLY on the drive loop — the send
    // gate consults it there, and [setPeerMessageLimit] posts rather than assigns — so it needs no
    // synchronization and cannot be observed half-updated by a caller's coroutine.
    private var peerMessageLimit: PeerMessageLimit = PeerMessageLimit.NotYetNegotiated

    /**
     * Which stream ids exist, which are ours to hand out, which are mid-close and which may be reused —
     * one ledger (RFC 8832 §6, RFC 8831 §6.7). It replaces a reuse queue, a half-close map, a parity
     * predicate and a bare `Int` cursor that between them kept the same fact in four places, and it is
     * where an open that cannot be given an id becomes a typed refusal rather than a throw on this loop.
     */
    private val streamIds = StreamIdAllocator(role)

    // How many outgoing streams the association negotiated (RFC 4960 §5.1.1) — the ceiling every stream id
    // this side hands out must sit under. Tracked from SctpOutput.OutgoingCapacityChanged rather than read
    // off the association, because the driver only ever touches the core through the serialized loop and
    // an open parked for want of capacity has to be released by an *event*, not by polling.
    private var outgoingCapacity: OutgoingStreamCapacity = OutgoingStreamCapacity.NotNegotiated

    // Opens that ran out of negotiated stream ids while `streamGrowth` is `AddStreams`: their RFC 6525 §4.5
    // request is on the wire and they are retried when it is answered. The FIRST open to park is what
    // issues the request and the rest ride it — which is also what stops the retry loop from asking again
    // for capacity it is already waiting on.
    private val opensAwaitingCapacity = ArrayDeque<OpenCommand>()

    // Set when an OutgoingCapacityChanged lands inside apply(), drained AFTER the output loop for the same
    // reason reciprocalResets is: dispatching a parked open re-enters the association, and doing that
    // mid-output-list would interleave its packets with the ones already being applied.
    private var capacityGrew = false

    private val streamGrowth = config.streamGrowth

    // Scratch for the reciprocal resets one drive-loop item produced (RFC 8831 §6.7's "when the peer sees
    // that an incoming stream was reset, it also resets its corresponding outgoing stream"). Collected
    // during apply() and issued after it, so the association is never re-entered mid-output-list.
    private val reciprocalResets = LinkedHashSet<StreamId>()

    // Streams we OPENed on which nothing has yet come back. RFC 8832 §6: "before the DATA_CHANNEL_ACK
    // message or any other message has been received on a data channel, all other messages containing
    // user data and belonging to this data channel MUST be sent ordered, no matter whether the data
    // channel is ordered or not." Until the channel is confirmed, user data is therefore forced ordered
    // (see dispatchCommand) — otherwise SCTP may deliver the first payload AHEAD of the still-ordered
    // DCEP OPEN, and a peer that reads the first message on a new stream as necessarily DCEP sees a
    // WebRTC-Binary PPID instead. (Pion does exactly that, and its accept loop dies on the error, so
    // EVERY later channel on that association is lost too — how this was found; see the interop soak.)
    // Only the OPENING side is constrained: on a peer-opened channel we have by definition already
    // received a message on it (the OPEN itself).
    private val unconfirmedOutbound = HashSet<StreamId>()

    // Senders parked by backpressure: their message is already queued in the association, but the send
    // buffer was above the high-water mark when it went in, so their deferred stays incomplete until the
    // buffer drains to the low-water mark. FIFO — the first sender to park is the first released.
    //
    // This is what makes `send()` the ONLY backpressure signal the API needs: no bufferedAmount property,
    // no onBufferedAmountLow callback: a caller that can outrun the association simply stops being resumed.
    private val awaitingDrain = ArrayDeque<SendCommand>()
    private val highWaterBytes = config.sendBufferHighWaterBytes
    private val lowWaterBytes = config.sendBufferLowWaterBytes

    private val _state = MutableStateFlow<SctpAssociationState>(SctpAssociationState.Closed)

    /** The association lifecycle, surfaced for the PeerConnection layer / tests to await. */
    public val state: StateFlow<SctpAssociationState> get() = _state

    /** True once the stack has torn down (transport close / abort) — test-visible, not public API. */
    internal val isTornDown: Boolean get() = closed

    /**
     * Inbound messages dropped without delivery because they could not be parsed into a typed payload —
     * today only a `WebRTC String` whose bytes are not valid UTF-8 (RFC 8831 §6.6). Test-visible; the
     * session layer surfaces this as a diagnostic.
     */
    internal var discardedInbound: Int = 0
        private set

    // Peer DCEP OPENs this stack would not register, counted by reason. Bounded — there are three reasons
    // — and test-visible only: nothing above this layer surfaces them yet, and a decline is not an error
    // (a duplicate OPEN is the ordinary retransmit case).
    private val declinedOpens = HashMap<InboundOpenDecline, Int>()

    /** How many peer DCEP OPENs were declined for [reason] — test-visible, see [admitInboundOpen]. */
    internal fun declinedInboundOpens(reason: InboundOpenDecline): Int = declinedOpens[reason] ?: 0

    /**
     * The outgoing stream capacity the association settled (RFC 4960 §5.1.1) — test-visible only. It is
     * the ceiling on every stream id this side allocates, and nothing a consumer can otherwise observe.
     */
    internal val negotiatedOutgoingCapacity: OutgoingStreamCapacity get() = outgoingCapacity

    /** Queued-but-unsent user bytes, and how many senders are parked on backpressure — test-visible only. */
    internal val bufferedBytes: Int get() = association.bufferedBytes
    internal val parkedSenders: Int get() = awaitingDrain.size

    /**
     * Every [SctpOutput.PathMtuChanged] this stack has seen, in order — test-visible only, and the only
     * place the RFC 8899 search is observable from above the association. Bounded: a search converges in a
     * handful of probes and a raise timer re-opens it at most once every raise interval, so an unbounded
     * list here would still be a slow leak on a session that lives for days.
     */
    internal val pathMtuChanges: List<SctpOutput.PathMtuChanged> get() = pathMtuHistory.toList()
    private val pathMtuHistory = ArrayDeque<SctpOutput.PathMtuChanged>()

    /**
     * Stream ids whose channel closed in both directions and that a future open will reuse — test-visible
     * only. It is the one direct read of "the close finished on the wire": a channel id lands here exactly
     * when its second RFC 6525 reset completes, which no consumer-facing signal reports (the flow closing
     * only means the *local* half is done).
     */
    internal val recycledStreamIds: List<StreamId> get() = streamIds.recycled

    /** The stream-id ledger, so a fixture can assert its invariants (plan residue R5) — test-visible only. */
    internal val streamIdLedger: StreamIdAllocator get() = streamIds

    /** Launch the driver: the transport reader, and the single serialized association drive loop. */
    public fun start() {
        scope.launch { readerLoop() }
        scope.launch { writerLoop() }
        scope.launch { driveLoop() }
    }

    // ── StreamMux<DataChannelPayload> ──

    override suspend fun openBidirectional(): Connection<DataChannelPayload> = open(DataChannelConfig())

    /** Open a data channel with explicit [config] (label / ordering / reliability) — RFC 8832 §5.1. */
    public suspend fun open(config: DataChannelConfig): Connection<DataChannelPayload> {
        val deferred = CompletableDeferred<DataChannelConnection>()
        post(OpenCommand(config, deferred))
        return deferred.await()
    }

    // Hand a command to the drive loop, failing fast with the typed close exception if the stack has torn
    // down (either the `closed` flag is already set, or the inbox was closed under us mid-send) — so a
    // caller never suspends forever on a command that will not be processed.
    private suspend fun post(command: Command) {
        if (closed) throw SctpClosedException(null)
        try {
            inbox.send(DriveItem.Command(command))
        } catch (_: kotlinx.coroutines.channels.ClosedSendChannelException) {
            throw SctpClosedException(null)
        }
    }

    override suspend fun acceptBidirectional(): Connection<DataChannelPayload> = accepted.receive()

    // WebRTC data channels are always bidirectional; a unidirectional view is a bidirectional channel
    // used in one direction (RFC 8831 has no half-open channel type).
    override suspend fun openUnidirectional(): Sender<DataChannelPayload> = open(DataChannelConfig())

    override suspend fun acceptUnidirectional(): Receiver<DataChannelPayload> = accepted.receive()

    /**
     * Tell the association which path it is riding, or that the path moved (RFC 8261 §6.1 — see
     * [SctpEvent.PathChanged]). Routed through the drive loop like every other input, so `handle` stays
     * serialized and a path event can never interleave with a datagram.
     *
     * **Fail-quiet on a torn-down stack**, like [shutdown] and unlike [open]: the session layer publishes
     * this from a path watcher whose cancellation races the teardown it is watching for, so a path event
     * arriving one dispatch late is the ordinary shape of a closing session rather than a caller error
     * worth an exception.
     */
    public suspend fun pathChanged(profile: SctpPathProfile.Assessed) {
        if (closed) return
        try {
            inbox.send(DriveItem.Command(PathChangedCommand(profile)))
        } catch (_: kotlinx.coroutines.channels.ClosedSendChannelException) {
            // already torn down
        }
    }

    /**
     * Tell this stack what the peer's `a=max-message-size` (RFC 8841 §6) said, so a `send` that would
     * overrun it is refused here rather than discovered by the peer (RFC 8831 §6.6 makes exceeding it a
     * MUST NOT). Until told, the stack assumes [PeerMessageLimit.NotYetNegotiated] and applies §6.6's
     * 64 KiB — the only ceiling defensible in the absence of a statement.
     *
     * Non-suspending and posted rather than assigned: the limit is read on the drive loop beside the
     * send it gates, so it is delivered as an ordered item like every other command. Best-effort on a
     * torn-down stack, where nothing will be sent anyway.
     *
     * A session layer that reads SDP (`NativePeerConnection` does) calls this for its consumer. A caller
     * driving this module directly — it is published on its own — is the reason it is public: a peer's
     * ceiling can be known by means other than SDP, and the alternative to saying so is being capped at
     * 64 KiB with no way to raise it.
     */
    public fun setPeerMessageLimit(limit: PeerMessageLimit) {
        if (closed) return
        inbox.trySend(DriveItem.Command(PeerMessageLimitCommand(limit)))
    }

    /** Begin a graceful association shutdown (RFC 4960 §9.2). No-op once the stack has closed. */
    public suspend fun shutdown() {
        if (closed) return
        try {
            inbox.send(DriveItem.Command(ShutdownCommand))
        } catch (_: kotlinx.coroutines.channels.ClosedSendChannelException) {
            // already torn down
        }
    }

    // ── the drive loop (the only place association.handle is called) ──

    private suspend fun readerLoop() {
        // Every send here can race a tearDown that has already closed the inbox — most visibly at the END
        // of a GRACEFUL shutdown, where the association reaches Closed, the stack tears down, and only then
        // does the transport under it close and wake this loop for its final TransportClosed. On a closed
        // inbox that send throws, and an uncaught throw in this launched coroutine takes the whole PROCESS
        // down on Kotlin/Native (the L2 harness caught exactly that: rc=139 at answerer teardown). A closed
        // inbox simply means the drive loop that would consume the item is already gone — the same
        // fail-quiet the other inbox writers (post / shutdown / closeChannel) already implement.
        var undelivered: ReadBuffer? = null
        try {
            while (true) {
                val packet = transport.receive() ?: break
                // Held only across the send: if the inbox is closed the send throws, and this loop is
                // then still the packet's last reader (see [releaseReceived]). Without this, every
                // datagram racing a teardown was lost outright.
                undelivered = packet
                inbox.send(DriveItem.Inbound(packet))
                undelivered = null
            }
            inbox.send(DriveItem.TransportClosed)
        } catch (_: kotlinx.coroutines.channels.ClosedSendChannelException) {
            // already torn down
        } finally {
            undelivered?.releaseReceived()
        }
    }

    // Drain outgoing packets in strict emission order (SCTP tolerates reordering, but a single writer
    // keeps the wire deterministic and avoids a coroutine per datagram). Being the single writer is also
    // what makes it the right place to release: whatever this loop is handed, it is the last reader of,
    // and a Release it reaches is behind every Send of the same bytes by construction.
    private suspend fun writerLoop() {
        // Iterating a CLOSED channel still yields what is buffered in it and only then ends, which is what
        // makes this the single point of release even at teardown: tearDown queues the association's final
        // reclaims and closes, and they arrive here behind the sends they must not overtake. Draining from
        // tearDown instead would race — the writer can be inside `transport.send` holding a view of bytes
        // whose Release is still in the queue.
        for (item in outbound) {
            try {
                // Nothing is worth sending once the stack has torn down; the drain is only about giving
                // the memory back.
                if (item is OutboundItem.Send && !closed) transport.send(item.packet)
            } catch (cancelled: CancellationException) {
                item.packet.freeIfNeeded()
                throw cancelled
            } catch (_: Throwable) {
                // A failed send is not this loop's to escalate. The transport reports its own closure
                // through `receive()` returning null, which reaches the drive loop as TransportClosed; an
                // uncaught throw in a launched coroutine takes the whole PROCESS down on Kotlin/Native
                // (the trap readerLoop documents), and it would strand every packet still queued behind
                // this one — turning one lost datagram into a leak of the entire outbound queue.
            } finally {
                item.packet.freeIfNeeded()
            }
        }
    }

    private suspend fun driveLoop() {
        // Associate from BOTH roles, not just the DTLS client. RFC 8831 makes the DTLS client the natural
        // opener, but the deployed ecosystem does not treat that as exclusive: libwebrtc sends its INIT
        // whichever DTLS role it holds (proven directly — a Chrome *offerer*, i.e. the DTLS server,
        // INITs), and werift picks its SCTP role off the ICE role instead, so as a controlled answerer it
        // never INITs at all. Waiting for the peer to open therefore deadlocks against werift, while
        // opening unconditionally interoperates with everyone — at the cost of a simultaneous open on
        // every path where the peer also opens, which the association resolves per RFC 4960 §5.2.1/§5.2.4.
        // The role still decides stream-id parity (RFC 8832 §6); it no longer decides who initiates.
        apply(association.handle(SctpEvent.Associate, now()))
        while (!closed) {
            val deadline = association.nextDeadline(now())
            val item =
                if (deadline == null) {
                    inbox.receiveCatching().getOrNull() ?: break
                } else {
                    val wait = (deadline - now()).coerceAtLeast(Duration.ZERO)
                    select {
                        inbox.onReceiveCatching { it.getOrNull() }
                        onTimeout(wait) { DriveItem.Timer }
                    } ?: break
                }
            when (item) {
                is DriveItem.Inbound -> {
                    apply(association.handle(SctpEvent.DatagramReceived(item.packet), now()))
                    // This loop is the last reader of a received packet (see [releaseReceived]): the
                    // transport transferred it, and nothing the association kept is a view of it. After
                    // `apply`, deliberately — `apply` transmits, and an outbound chunk echoed from the
                    // inbound view (a HEARTBEAT-ACK's info) is still reading it until then.
                    item.packet.releaseReceived()
                }
                is DriveItem.Command -> onCommand(item.command)
                DriveItem.Timer -> apply(association.handle(SctpEvent.TimerFired, now()))
                DriveItem.TransportClosed -> tearDown(null)
            }
            // A received ABORT (apply → tearDown) or a transport close stops the loop here rather than
            // continuing to drive `handle` on a dead association.
            if (closed) break
            // Every item above can have drained the send buffer — a SACK opening cwnd/rwnd most obviously,
            // but also a timer firing a retransmit. This is the one serialized place that sees all of them,
            // so it is the one place parked senders are released.
            releaseDrainedSenders()
        }
    }

    private fun onCommand(command: Command) {
        when (command) {
            is OpenCommand -> onOpenCommand(command)
            is SendCommand -> {
                // RFC 8841 §6 / RFC 8831 §6.6: a message larger than the peer will accept never reaches
                // the association. Gated HERE, before the ordering override and before `handle`, for the
                // same reason the override is resolved here — the peer's ceiling is drive-loop state.
                // A refusal fails only this send: nothing is queued, no TSN is assigned, the channel
                // stays open, and `sendMessage`'s `finally` frees whatever it allocated.
                val refusal = refuse(command.wireByteCount)
                if (refusal != null) {
                    command.deferred.completeExceptionally(MessageRefusedException(refusal))
                    return
                }
                // RFC 8832 §6: user data on a channel we opened is sent ORDERED until that channel is
                // confirmed, whatever ordering the channel was configured with. Ordered delivery is the
                // stronger guarantee, so an unordered channel is never violated by it — and it is what
                // keeps the DCEP OPEN first on the wire for the peer that requires it. Resolved HERE,
                // on the drive loop, because that is where the confirmation set is mutated; sendMessage
                // runs on the caller's coroutine and must not read it.
                val options =
                    if (command.options.streamId in unconfirmedOutbound) {
                        command.options.copy(delivery = DeliveryOrder.Ordered)
                    } else {
                        command.options
                    }
                apply(association.handle(SctpEvent.SendMessage(options, command.payload), now()))
                // Fast path: while the send buffer is shallow the caller is released immediately, so a
                // well-behaved sender still pipelines at full rate and never pays for the check. Only once
                // the association is genuinely behind does the caller park (released in releaseDrainedSenders).
                if (association.bufferedBytes <= highWaterBytes) {
                    command.deferred.complete(Unit)
                } else {
                    awaitingDrain.addLast(command)
                }
            }
            is CloseChannelCommand -> onCloseChannel(command.streamId)
            is PathChangedCommand -> apply(association.handle(SctpEvent.PathChanged(command.profile), now()))
            is PeerMessageLimitCommand -> peerMessageLimit = command.limit
            ShutdownCommand -> apply(association.handle(SctpEvent.Shutdown, now()))
        }
    }

    /**
     * Why a message of [wireByteCount] bytes may not be sent, or null when it may (RFC 8841 §6).
     *
     * The `when` is the whole gate. Each arm names a ceiling **and** the reason it is that ceiling, so
     * two of them enforce the same 64 KiB and report different things — which is the point: "the peer
     * said nothing" and "the peer has not been heard from" are different situations with different fixes,
     * and a lone "too large" would make them indistinguishable.
     *
     * DCEP control messages do not come through here (see [sendOnStream], which reaches `handle`
     * directly): RFC 8832's OPEN/ACK are protocol, not user data, and are bounded by their own grammar.
     */
    private fun refuse(wireByteCount: Long): MessageRefusedReason? {
        val assumed = PeerMessageLimit.ASSUMED_DEFAULT_BYTES
        return when (val limit = peerMessageLimit) {
            PeerMessageLimit.Unlimited -> null
            is PeerMessageLimit.Advertised ->
                if (wireByteCount > limit.bytes) {
                    MessageRefusedReason.ExceedsAdvertisedLimit(wireByteCount, limit.bytes)
                } else {
                    null
                }
            PeerMessageLimit.AssumedDefault ->
                if (wireByteCount > assumed) MessageRefusedReason.ExceedsAssumedDefault(wireByteCount) else null
            PeerMessageLimit.NotYetNegotiated ->
                if (wireByteCount > assumed) MessageRefusedReason.PeerLimitUnknown(wireByteCount) else null
        }
    }

    // Release parked senders once the association has drained to the low-water mark. All-or-nothing on the
    // mark, not one-per-freed-byte: the hysteresis gap between the two marks is what stops a sender being
    // woken by every SACK only to re-park on its next message.
    private fun releaseDrainedSenders() {
        if (awaitingDrain.isEmpty() || association.bufferedBytes > lowWaterBytes) return
        while (awaitingDrain.isNotEmpty()) awaitingDrain.removeFirst().deferred.complete(Unit)
    }

    // Drop a locally closed channel and reset its outgoing stream — RFC 8831 §6.7's close. Only for a
    // channel still in the routing map: a second close(), or one racing the peer's own reset of the same
    // stream, must not put a duplicate request on the wire, and must never re-reset an id already recycled.
    private fun onCloseChannel(streamId: StreamId) {
        val known = channels.remove(streamId) != null
        forgetStream(streamId)
        if (known) resetOutgoing(setOf(streamId))
    }

    // Everything keyed by a stream id that does not survive its channel. `pendingInbound` above all: data
    // held for a stream id that is later RECYCLED would otherwise be flushed into the next, unrelated
    // channel that reuses the id.
    private fun forgetStream(streamId: StreamId) {
        unconfirmedOutbound -= streamId
        // Held data for a stream that is going away reaches no channel now, so this is its last reader.
        pendingInbound.remove(streamId)?.forEach { it.payload.release() }
    }

    private fun resetOutgoing(streams: Set<StreamId>) {
        apply(association.handle(SctpEvent.ResetStreams(StreamResetScope.Streams(streams)), now()))
    }

    /**
     * An open has reached the drive loop. A negotiated id (RFC 8832 §5) is **reserved here** — before the
     * Established check can park the command — and that ordering is the point: the ledger entry exists
     * from this moment, so no later automatic allocation and no peer DCEP OPEN can take the id, whatever
     * order the dispatches happen in afterwards.
     *
     * Only collision refusals can be answered here. Whether the id fits the association's negotiated
     * stream count cannot be: there may be no association yet, and therefore no count. That check runs at
     * dispatch, which is also where the reservation is given back if it fails.
     */
    private fun onOpenCommand(command: OpenCommand) {
        when (val identity = command.config.identity) {
            ChannelIdentity.InBand -> Unit
            is ChannelIdentity.Negotiated -> {
                val refusal = streamIds.claim(identity.id, ChannelProvenance.OutOfBand)
                if (refusal != null) {
                    refuseOpen(command, refusal)
                    return
                }
            }
        }
        if (association.state == SctpAssociationState.Established) {
            dispatchOpen(command)
        } else {
            pendingOpens.addLast(command)
        }
    }

    private fun dispatchOpen(command: OpenCommand) {
        when (val identity = command.config.identity) {
            ChannelIdentity.InBand -> dispatchInBandOpen(command)
            is ChannelIdentity.Negotiated -> dispatchNegotiatedOpen(command, identity.id)
        }
    }

    /**
     * A negotiated channel is usable the moment the association is: nothing is sent, nothing is awaited,
     * and the peer's half was created independently (RFC 8832 §5). All that is left is the range check
     * that [onOpenCommand] could not make.
     */
    private fun dispatchNegotiatedOpen(
        command: OpenCommand,
        id: StreamId,
    ) {
        val capacity = negotiatedStreams()
        if (!capacity.admits(id)) {
            // Give the reservation back, or the id is spent for the life of the association on an open
            // that never happened — and `allocate` would step over it forever.
            streamIds.relinquish(id)
            refuseOpen(command, DataChannelOpenRefusal.StreamIdOutsideNegotiatedRange(id, capacity))
            return
        }
        command.deferred.complete(registerChannel(id, command.config, ChannelProvenance.OutOfBand))
    }

    private fun dispatchInBandOpen(command: OpenCommand) {
        val streamId =
            when (val grant = streamIds.allocate(negotiatedStreams())) {
                is StreamIdGrant.Granted -> grant.id
                // Both refusals used to be the same line of code walking off the end of the id space, and
                // both used to be an exception thrown on this loop rather than an answer to the caller.
                is StreamIdGrant.NeedsMoreStreams -> {
                    when (val policy = streamGrowth) {
                        StreamGrowthPolicy.Fixed ->
                            refuseOpen(command, DataChannelOpenRefusal.StreamIdOutsideNegotiatedRange(grant.wanted, grant.capacity))
                        is StreamGrowthPolicy.AddStreams -> parkForCapacity(command, policy, grant)
                    }
                    return
                }
                StreamIdGrant.SpaceExhausted -> {
                    refuseOpen(command, DataChannelOpenRefusal.StreamIdSpaceExhausted)
                    return
                }
            }
        val connection = registerChannel(streamId, command.config, ChannelProvenance.LocalInBand)
        val open =
            DataChannelMessage.Open(
                channelType = channelTypeOf(command.config),
                priority = command.config.priority,
                reliabilityParameter = reliabilityParameterOf(command.config.reliability),
                label = command.config.label,
                protocol = command.config.protocol,
            )
        sendOnStream(
            streamId,
            PayloadProtocolId.WebRtcDcep,
            delivery = DeliveryOrder.Ordered,
            reliability = SctpReliability.Reliable,
            payload = open.encode(bufferFactory),
        )
        command.deferred.complete(connection)
    }

    // How many outgoing streams the association negotiated, as a plain count. `NotNegotiated` becomes zero
    // rather than an unbounded default: a capacity that does not exist admits no id, which is the honest
    // reading and is what makes the range check total without a nullable in the middle of it.
    private fun negotiatedStreams(): StreamCount =
        when (val capacity = outgoingCapacity) {
            OutgoingStreamCapacity.NotNegotiated -> StreamCount.None
            is OutgoingStreamCapacity.Negotiated -> capacity.streams
        }

    /**
     * Hold [command] until the association has grown, and — if it is the first to wait — ask the peer for
     * the streams (RFC 6525 §4.5). The ask is `max(policy increment, the shortfall)`: the configured batch
     * amortises the round trip, and the shortfall is the floor below which this very open would park again
     * on the next answer.
     *
     * Only the first waiter asks. §5.1.2 allows one outstanding reconfiguration request anyway, so a second
     * ask would either be merged by the association or queued behind the first; not making it is what keeps
     * the retry in `flushOpensAwaitingCapacity` from re-asking for capacity it is already waiting on.
     */
    private fun parkForCapacity(
        command: OpenCommand,
        policy: StreamGrowthPolicy.AddStreams,
        grant: StreamIdGrant.NeedsMoreStreams,
    ) {
        val first = opensAwaitingCapacity.isEmpty()
        opensAwaitingCapacity.addLast(command)
        if (!first) return
        val ask = if (policy.increment > grant.shortfall) policy.increment else grant.shortfall
        apply(association.handle(SctpEvent.RequestMoreOutgoingStreams(ask), now()))
    }

    // An open that cannot be given a stream id fails its caller with the typed reason. It must complete the
    // deferred — an open left hanging suspends its caller for the life of the process, which is the same
    // leak tearDown exists to prevent on the other paths.
    private fun refuseOpen(
        command: OpenCommand,
        refusal: DataChannelOpenRefusal,
    ) {
        command.deferred.completeExceptionally(DataChannelOpenRefusedException(refusal))
    }

    private fun apply(outputs: List<SctpOutput>) {
        for (output in outputs) {
            when (output) {
                // Both kinds of Transmit are queued the same way and released the same way — the driver's
                // job is identical for a control packet and for a view of a retransmission-queue entry.
                // What differs is what the release *does*, and that is settled by the buffer the
                // association chose to hand over, which is the whole point of the split: the driver never
                // has to decide, and cannot decide wrongly.
                //
                // No extra `slice()` here. Each Transmit already carries its own independent view, and a
                // slice taken to survive the async hand-off is a reference nobody balances — the pooled-
                // chunk pin CLAUDE.md records under "send does not consume".
                is SctpOutput.Transmit -> {
                    output.packet.position(0)
                    enqueue(OutboundItem.Send(output.packet))
                }
                // Ordered behind every Send already queued, which is what makes freeing these safe at all.
                is SctpOutput.ReclaimRetained -> enqueue(OutboundItem.Release(output.packet))
                is SctpOutput.StateChanged -> onStateChanged(output.state)
                is SctpOutput.OutgoingCapacityChanged -> {
                    outgoingCapacity = output.capacity
                    capacityGrew = true
                }
                is SctpOutput.OutgoingStreamsAdded -> onOutgoingStreamsAdded(output.outcome)
                is SctpOutput.MessageReceived -> onMessage(output)
                is SctpOutput.Aborted -> tearDown(output.reason)
                // The association survived the peer's restart, but every channel on it did not: the peer
                // has forgotten each stream, so continuing would be a lie. Tear down with a typed reason
                // and let the session renegotiate (RFC 4960 §5.2.4 action A — see SctpOutput.PeerRestarted).
                SctpOutput.PeerRestarted -> tearDown(SctpFailureReason.PeerRestarted)
                is SctpOutput.IncomingStreamsReset -> onIncomingStreamsReset(output.scope)
                is SctpOutput.OutgoingStreamsReset -> onOutgoingStreamsReset(output.scope, output.outcome)
                // An observation the association has already applied — nothing here has to act on it. It
                // is recorded so a fixture and the session layer can see a black-holed MTU, which is
                // otherwise indistinguishable from a peer that stopped acknowledging.
                is SctpOutput.PathMtuChanged -> onPathMtuChanged(output)
            }
        }
        flushReciprocalResets()
        flushOpensAwaitingCapacity()
    }

    // Retry every open parked for want of stream ids, now that the association has more. A retry that still
    // finds none re-parks — and, being the first to park again, issues the next request — so a peer that
    // grants less than was asked for converges rather than spinning.
    private fun flushOpensAwaitingCapacity() {
        if (!capacityGrew) return
        capacityGrew = false
        val waiting = opensAwaitingCapacity.toList()
        // Cleared BEFORE re-dispatching, so a re-park starts from an empty queue and reads as the first
        // one — the same discipline flushReciprocalResets uses for the same re-entrancy reason.
        opensAwaitingCapacity.clear()
        for (command in waiting) dispatchOpen(command)
    }

    // The growth request came back refused, so every open waiting on it is answered with what the peer
    // said. `Performed` is not handled here: the capacity change that came with it already released them.
    private fun onOutgoingStreamsAdded(outcome: StreamAddOutcome) {
        when (outcome) {
            StreamAddOutcome.Performed -> Unit
            is StreamAddOutcome.NotAdded -> {
                val waiting = opensAwaitingCapacity.toList()
                opensAwaitingCapacity.clear()
                for (command in waiting) refuseOpen(command, DataChannelOpenRefusal.PeerWouldNotAddStreams(outcome))
            }
        }
    }

    // `outbound` is UNLIMITED so this only fails once it is CLOSED — i.e. the stack has torn down and the
    // writer will never run again, which makes this call the item's last reader. Dropping the failure (the
    // shape the send path had before) would leak the packet on every teardown race.
    private fun enqueue(item: OutboundItem) {
        if (outbound.trySend(item).isFailure) item.packet.freeIfNeeded()
    }

    // The peer closed one or more data channels (RFC 8831 §6.7). Close our side, and reset our own
    // outgoing half in return — but only for a channel we still had open. A reset for a stream we already
    // closed is the peer *answering* our close, and reciprocating there would bounce resets forever.
    private fun onIncomingStreamsReset(scope: StreamResetScope) {
        for (streamId in scope.resolve()) {
            val connection = channels.remove(streamId)
            forgetStream(streamId)
            if (connection != null) {
                connection.closeLocal()
                reciprocalResets += streamId
            }
            streamIds.noteResetHalf(streamId, ResetHalf.Peers)
        }
    }

    private fun onOutgoingStreamsReset(
        scope: StreamResetScope,
        outcome: StreamResetOutcome,
    ) {
        for (streamId in scope.resolve()) {
            when (outcome) {
                StreamResetOutcome.Performed -> streamIds.noteResetHalf(streamId, ResetHalf.Ours)
                // The peer refused, or cannot reset at all. It still holds SSN state for the stream, so the
                // channel is closed locally (already done) but the id is spent for the rest of the session.
                is StreamResetOutcome.Refused, StreamResetOutcome.Unsupported -> streamIds.burn(streamId)
            }
        }
    }

    private fun flushReciprocalResets() {
        if (reciprocalResets.isEmpty()) return
        val streams = reciprocalResets.toSet()
        // Cleared BEFORE re-entering the association, so the outputs that reset produces (and the apply()
        // nested inside this one) start from an empty scratch set rather than re-issuing these ids.
        reciprocalResets.clear()
        resetOutgoing(streams)
    }

    // The concrete stream ids a scope names here: "all streams" means every channel still open plus every
    // one already half-closed, since both are ids whose reset bookkeeping is still live.
    private fun StreamResetScope.resolve(): Collection<StreamId> =
        when (this) {
            StreamResetScope.AllStreams -> channels.keys + streamIds.liveIds
            is StreamResetScope.Streams -> ids
        }

    private fun onPathMtuChanged(change: SctpOutput.PathMtuChanged) {
        pathMtuHistory.addLast(change)
        while (pathMtuHistory.size > MAX_PATH_MTU_HISTORY) pathMtuHistory.removeFirst()
    }

    private fun onStateChanged(state: SctpAssociationState) {
        _state.value = state
        if (state == SctpAssociationState.Established) {
            while (pendingOpens.isNotEmpty()) dispatchOpen(pendingOpens.removeFirst())
        }
    }

    private fun onMessage(message: SctpOutput.MessageReceived) {
        // "…the DATA_CHANNEL_ACK message OR ANY OTHER MESSAGE has been received on a data channel"
        // (RFC 8832 §6) — so anything inbound on the stream confirms it, not the ACK alone. A peer that
        // never ACKs but replies with user data still releases us; one that answers nothing keeps us on
        // ordered delivery forever, which is a safe degradation rather than a stall.
        unconfirmedOutbound -= message.streamId
        if (message.payloadProtocolId == PayloadProtocolId.WebRtcDcep) {
            // A DCEP message is decoded and acted on inside this call and nothing keeps a view of it, so
            // this is its last reader. The reassembly copy it rides in came from SctpConfig.bufferFactory
            // like any other (MessageReceived.payload is a transfer), and DCEP is the one class of message
            // no application ever sees — which is exactly why nothing else could free it.
            try {
                onDcep(message)
            } finally {
                message.payload.freeIfNeeded()
            }
            return
        }
        // RFC 8831 §6.6's empty-message marker: the wire carries one 0x00 that is stripped back to nothing
        // here. That byte is still a reassembly buffer, and substituting EMPTY_BUFFER for it drops the only
        // reference to it — so it is released rather than merely replaced.
        val payload =
            when (val inbound = payloadFor(message.payloadProtocolId, message.payload)) {
                is InboundMessage.Discarded -> {
                    // The buffer is already released by payloadFor; a discarded message is never delivered,
                    // and never fabricated into an empty one either. Counted so a fixture — and, once the
                    // session layer carries it, a SessionDiagnostic — can see that it happened.
                    discardedInbound += 1
                    return
                }
                is InboundMessage.Deliver -> inbound.payload
            }
        val connection = channels[message.streamId]
        if (connection != null) {
            connection.deliver(payload)
        } else {
            // User data (an unordered first message) beat its ordered DCEP OPEN — hold it, bounded, until
            // the OPEN registers the channel; drop beyond the cap (a peer sending data on a stream it
            // never OPENs). Dropping means releasing: past the cap this is the message's last reader.
            val queue = pendingInbound.getOrPut(message.streamId) { ArrayDeque() }
            if (queue.size < MAX_PENDING_INBOUND) {
                queue.addLast(PendingInbound(payload))
            } else {
                payload.release()
            }
        }
    }

    private fun onDcep(message: SctpOutput.MessageReceived) {
        when (val decoded = (DataChannelMessage.decode(message.payload) as? DataChannelDecodeResult.Success)?.message) {
            is DataChannelMessage.Open -> {
                when (val admission = admitInboundOpen(message.streamId)) {
                    InboundOpenAdmission.Admit -> {
                        streamIds.adoptPeerOpen(message.streamId)
                        registerChannel(message.streamId, configOf(decoded), ChannelProvenance.PeerInBand)
                    }
                    is InboundOpenAdmission.Decline -> declinedOpens[admission.reason] = declinedInboundOpens(admission.reason) + 1
                }
                // Always ACK a (re-)OPEN so a peer whose ACK was lost converges.
                sendOnStream(
                    message.streamId,
                    PayloadProtocolId.WebRtcDcep,
                    delivery = DeliveryOrder.Ordered,
                    reliability = SctpReliability.Reliable,
                    payload = DataChannelMessage.Ack.encode(bufferFactory),
                )
            }
            DataChannelMessage.Ack -> Unit // our channel is already usable optimistically; ACK just confirms
            null -> Unit
        }
    }

    /**
     * Whether a peer's DCEP OPEN may register a channel on [streamId] (RFC 8832 §6).
     *
     * The third refusal is the one that could not be expressed before. `streamIsPeerParity(id) && id !in
     * channels` is TRUE for an id the application reserved out of band but has not yet registered, so the
     * peer's stray OPEN would take it, publish an in-band channel on `accept`, and the application's own
     * negotiated open would then fail `StreamIdInUse` for a reason nothing reported. The ledger is what
     * can see that reservation; the routing map cannot, because a reserved channel is not in it yet.
     */
    private fun admitInboundOpen(streamId: StreamId): InboundOpenAdmission =
        when {
            streamIds.parityOf(streamId) == StreamParity.Ours -> InboundOpenAdmission.Decline(InboundOpenDecline.OurParity)
            // The ledger is asked BEFORE the routing map, because it is the only one that can see an id
            // the application has reserved but whose channel has not been dispatched yet — and because
            // "the application owns this id" is a sharper answer than "something is already here" even
            // once it has been.
            (streamIds.stateOf(streamId) as? StreamIdState.Claimed)?.origin == ChannelProvenance.OutOfBand ->
                InboundOpenAdmission.Decline(InboundOpenDecline.ReservedOutOfBand)
            streamId in channels -> InboundOpenAdmission.Decline(InboundOpenDecline.AlreadyOpen)
            else -> InboundOpenAdmission.Admit
        }

    /**
     * Register a channel on [streamId]. [provenance] decides the two things that used to be independent
     * Booleans: whether the channel is published to `accept`, and whether user data on it is forced
     * ordered until the peer answers (RFC 8832 §6). Only a channel WE opened in band is both unpublished
     * and force-ordered, and only a peer-opened one is published — a combination two flags could express
     * wrongly and this cannot.
     */
    private fun registerChannel(
        streamId: StreamId,
        config: DataChannelConfig,
        provenance: ChannelProvenance,
    ): DataChannelConnection {
        val connection = DataChannelConnection(streamId, config, this)
        channels[streamId] = connection
        if (provenance == ChannelProvenance.LocalInBand) unconfirmedOutbound += streamId
        // Flush any user data that arrived before this registration, in arrival order.
        pendingInbound.remove(streamId)?.forEach { held ->
            connection.deliver(held.payload)
        }
        when (provenance) {
            ChannelProvenance.PeerInBand -> accepted.trySend(connection)
            // Nothing is sent or expected out of band, so there is no DCEP OPEN to keep first on the wire
            // and nobody to publish it to — the application that named the id already holds the channel.
            ChannelProvenance.LocalInBand, ChannelProvenance.OutOfBand -> Unit
        }
        return connection
    }

    // Called by a DataChannelConnection.send — routes one user message through the association.
    internal suspend fun sendMessage(
        streamId: StreamId,
        config: DataChannelConfig,
        message: DataChannelPayload,
    ) {
        // The wire form of the message, and whether WE allocated it (and therefore owe it a release).
        // A Text is always encoded here — one UTF-8 encode per send, with the stack's injected factory,
        // so no caller has to allocate to send a string. A Binary is the application's own buffer and is
        // borrowed, never freed here.
        val encoded: ReadBuffer
        val encodedIsOurs: Boolean
        when (message) {
            is DataChannelPayload.Binary -> {
                encoded = message.bytes
                encodedIsOurs = false
            }
            is DataChannelPayload.Text -> {
                encoded = encodeUtf8(message.text)
                encodedIsOurs = true
            }
        }

        // The size the RFC 8841 §6 gate measures, taken from the MESSAGE rather than from its encoding:
        // an empty one rides a marker byte the peer's ceiling does not count, and this is the same number
        // a caller can pre-check with `DataChannelPayload.wireByteCount`. That it equals what the encoder
        // actually wrote for a Text is asserted, not assumed — see Utf8ByteCountTest.
        val wireByteCount = message.wireByteCount
        val empty = encoded.remaining() == 0
        val ppid =
            when (message) {
                is DataChannelPayload.Binary ->
                    if (empty) PayloadProtocolId.WebRtcBinaryEmpty else PayloadProtocolId.WebRtcBinary
                is DataChannelPayload.Text ->
                    if (empty) PayloadProtocolId.WebRtcStringEmpty else PayloadProtocolId.WebRtcString
            }
        // SCTP DATA must carry ≥ 1 byte; an empty application message rides a single 0x00 with an
        // empty-marker PPID (RFC 8831 §6.6), stripped back to empty on delivery.
        val payload = if (empty) singleZeroByte() else encoded
        val deferred = CompletableDeferred<Unit>()
        val options = SctpSendOptions(streamId, ppid, delivery = config.delivery, reliability = config.reliability)
        try {
            post(SendCommand(options, payload, wireByteCount, deferred))
            deferred.await()
        } finally {
            // By the time the deferred settles — completed or failed — the association has either encoded
            // the payload into its wire packets or never accepted it, and holds no view of it either way.
            // Release only what this function allocated: the marker byte, and a Text's encoding. A Binary's
            // buffer belongs to the application.
            if (empty) payload.freeIfNeeded()
            if (encodedIsOurs && !empty) encoded.freeIfNeeded()
        }
    }

    /**
     * Send [payload] on [streamId] under a caller-chosen [ppid], bypassing [DataChannelPayload] entirely.
     * [payload] is borrowed for the call and remains the caller's, exactly as a [DataChannelPayload.Binary]
     * buffer is.
     *
     * Exists for one reason, and is `internal` because of it: a `WebRTC String` carrying bytes that are
     * **not** valid UTF-8 is unconstructible through the public API — that is precisely what
     * [DataChannelPayload.Text] holding characters buys — so the receive-side reject path in [payloadFor]
     * has no other way to be reached. A fixture standing in for a non-conforming peer is the only caller;
     * nothing in production sends through here.
     */
    internal suspend fun sendUnencoded(
        streamId: StreamId,
        ppid: PayloadProtocolId,
        config: DataChannelConfig,
        payload: ReadBuffer,
    ) {
        val options = SctpSendOptions(streamId, ppid, delivery = config.delivery, reliability = config.reliability)
        val deferred = CompletableDeferred<Unit>()
        // No `DataChannelPayload` to ask, so the buffer IS the message here — which is exact, since this
        // seam never carries the empty-message marker. It is still gated: a fixture standing in for a
        // non-conforming peer must not be able to walk around the peer's ceiling either.
        post(SendCommand(options, payload, payload.remaining().toLong(), deferred))
        deferred.await()
    }

    // UTF-8 encode a text message with the stack's injected factory (directive #6 — no ambient allocator).
    private fun encodeUtf8(text: CharSequence): ReadBuffer {
        if (text.isEmpty()) return ReadBuffer.EMPTY_BUFFER
        val scratch = bufferFactory.allocate((text.length * Charset.UTF8.maxBytesPerChar).toInt(), ByteOrder.BIG_ENDIAN)
        scratch.writeString(text, Charset.UTF8)
        val written = scratch.position()
        scratch.resetForRead()
        scratch.setLimit(written)
        return scratch
    }

    /**
     * The typed message a received PPID denotes (RFC 8831 §6.6), taking ownership of [buffer].
     *
     * The deprecated "partial" PPIDs 54/55 map to their complete counterparts: they exist only for
     * pre-RFC-8831 implementations that fragmented above SCTP, and our reassembly has already delivered a
     * whole message by the time this is reached, so treating them as a final fragment is what they mean
     * here. An unrecognised PPID is delivered as [DataChannelPayload.Binary] rather than dropped — a peer
     * using a PPID we do not model still sent bytes the application may understand.
     */
    private fun payloadFor(
        ppid: PayloadProtocolId,
        buffer: ReadBuffer,
    ): InboundMessage {
        // The empty markers carry one 0x00 that is stripped back to nothing. That byte is still a
        // reassembly buffer, so it is released here rather than merely dropped on the floor.
        if (isEmptyPpid(ppid)) {
            buffer.freeIfNeeded()
            val emptyPayload =
                if (ppid == PayloadProtocolId.WebRtcStringEmpty) {
                    DataChannelPayload.Text("")
                } else {
                    DataChannelPayload.Binary(ReadBuffer.EMPTY_BUFFER)
                }
            return InboundMessage.Deliver(emptyPayload)
        }
        val isText = ppid == PayloadProtocolId.WebRtcString || ppid == PayloadProtocolId.WebRtcStringPartial
        if (!isText) return InboundMessage.Deliver(DataChannelPayload.Binary(buffer))

        // RFC 8831 §6.6 requires a string message to be UTF-8, but a peer is not obliged to be correct.
        // Decoding is the only place this stack parses attacker-supplied bytes into a higher type, so a
        // failure is contained here and reported as a typed discard — never a throw into the drive loop
        // (T0 discipline), which would take the whole association down with it.
        return try {
            val text = buffer.readString(buffer.remaining(), Charset.UTF8)
            buffer.freeIfNeeded()
            InboundMessage.Deliver(DataChannelPayload.Text(text))
        } catch (_: Throwable) {
            buffer.freeIfNeeded()
            InboundMessage.Discarded(InboundDiscardReason.MalformedUtf8)
        }
    }

    // Post a channel-close so the drive loop drops it from the routing map (called by Connection.close);
    // best-effort — a closed stack has already dropped every channel.
    internal suspend fun closeChannel(streamId: StreamId) {
        if (closed) return
        try {
            inbox.send(DriveItem.Command(CloseChannelCommand(streamId)))
        } catch (_: kotlinx.coroutines.channels.ClosedSendChannelException) {
            // already torn down
        }
    }

    // The DCEP OPEN/ACK path. [payload] is the stack's own encoding, not an application buffer, and the
    // association only BORROWS it for the duration of `handle` — every fragment is encoded into its wire
    // packet before that call returns (see SctpAssociation.fragment). So this is its last reader.
    private fun sendOnStream(
        streamId: StreamId,
        ppid: PayloadProtocolId,
        delivery: DeliveryOrder,
        reliability: SctpReliability,
        payload: ReadBuffer,
    ) {
        val options = SctpSendOptions(streamId, ppid, delivery = delivery, reliability = reliability)
        try {
            apply(association.handle(SctpEvent.SendMessage(options, payload), now()))
        } finally {
            payload.freeIfNeeded()
        }
    }

    // Tear the stack down exactly once (transport close or a received/failed association ABORT). Beyond
    // closing the streams and I/O channels, it MUST complete every outstanding command deferred
    // exceptionally — otherwise an open()/send()/shutdown() awaiting a command that will now never be
    // processed suspends its caller coroutine forever (the leak the review caught).
    private fun tearDown(reason: SctpFailureReason?) {
        if (closed) return
        closed = true
        val cause = SctpClosedException(reason)
        for (connection in channels.values) connection.closeLocal()
        channels.clear()
        // Data that never reached a channel — its stream was never OPENed, so no application has a
        // reference to it and this is its last reader. Anything already `deliver`ed is deliberately NOT
        // touched: closing a channel's flow still emits what is buffered in it, so those messages are the
        // application's (see DataChannelConnection.receive), and draining them here would steal them.
        for (queue in pendingInbound.values) {
            for (held in queue) held.payload.release()
        }
        pendingInbound.clear()
        unconfirmedOutbound.clear()
        streamIds.clear()
        reciprocalResets.clear()
        for (command in pendingOpens) command.deferred.completeExceptionally(cause)
        pendingOpens.clear()
        // …and the ones waiting on a stream-count increase that will now never be answered. Same leak,
        // different queue: a caller suspended on an open the drive loop will never reach stays suspended.
        for (command in opensAwaitingCapacity) command.deferred.completeExceptionally(cause)
        opensAwaitingCapacity.clear()
        accepted.close()
        // Everything the association still owns — the retransmission queue, unsent messages, the retained
        // COOKIE ECHO, the reassembly state. Queued rather than freed on the spot, and queued BEFORE the
        // close: the writer is still the only thing allowed to release, so these land behind any send of
        // the same bytes exactly as they do mid-session. Closing then ends the writer once it has drained.
        for (output in association.close()) {
            if (output is SctpOutput.ReclaimRetained) enqueue(OutboundItem.Release(output.packet))
        }
        outbound.close()
        transport.close()
        inbox.close()
        // Fail every command still queued (and thus every caller suspended on its deferred), and release
        // every packet still queued. Closing the inbox does not free what is sitting in it, and an
        // Inbound item is a transfer whose reader — the drive loop — will now never run, so this drain is
        // its last reader (see [releaseReceived]). Draining after `inbox.close()` is what makes that safe:
        // the close is what guarantees no producer can enqueue behind us.
        while (true) {
            val item = inbox.tryReceive().getOrNull() ?: break
            when (item) {
                is DriveItem.Command -> failCommand(item.command, cause)
                is DriveItem.Inbound -> item.packet.releaseReceived()
                DriveItem.Timer, DriveItem.TransportClosed -> Unit
            }
        }
        // …and every sender parked by backpressure. These are NOT in the inbox — their command was already
        // processed and their message queued; only the resume is outstanding. A tearDown that drained just
        // the inbox would leave them suspended forever on an association that will never drain again,
        // which is the same leak the review caught on the command path (directive: no unbounded suspension).
        while (awaitingDrain.isNotEmpty()) awaitingDrain.removeFirst().deferred.completeExceptionally(cause)
    }

    private fun failCommand(
        command: Command,
        cause: SctpClosedException,
    ) {
        when (command) {
            is OpenCommand -> command.deferred.completeExceptionally(cause)
            is SendCommand -> command.deferred.completeExceptionally(cause)
            is CloseChannelCommand, is PeerMessageLimitCommand, ShutdownCommand, is PathChangedCommand -> Unit
        }
    }

    private fun now(): Instant = clock()

    private fun singleZeroByte(): ReadBuffer {
        val buf = bufferFactory.allocate(1, ByteOrder.BIG_ENDIAN)
        buf.writeByte(0)
        buf.resetForRead()
        buf.setLimit(1)
        return buf
    }

    private fun isEmptyPpid(ppid: PayloadProtocolId): Boolean =
        ppid == PayloadProtocolId.WebRtcStringEmpty || ppid == PayloadProtocolId.WebRtcBinaryEmpty

    private fun channelTypeOf(config: DataChannelConfig): ChannelType =
        ChannelType.of(
            ordered = config.delivery == DeliveryOrder.Ordered,
            reliability =
                when (config.reliability) {
                    SctpReliability.Reliable -> Reliability.Reliable
                    is SctpReliability.MaxRetransmits -> Reliability.PartialReliableRetransmit
                    is SctpReliability.MaxLifetime -> Reliability.PartialReliableTimed
                },
        )

    private fun reliabilityParameterOf(reliability: SctpReliability): UInt =
        when (reliability) {
            SctpReliability.Reliable -> 0u
            is SctpReliability.MaxRetransmits -> reliability.maxRetransmits.toUInt()
            is SctpReliability.MaxLifetime -> reliability.maxLifetime.inWholeMilliseconds.toUInt()
        }

    private fun configOf(open: DataChannelMessage.Open): DataChannelConfig =
        DataChannelConfig(
            label = open.label,
            protocol = open.protocol,
            delivery = if (open.channelType.ordered) DeliveryOrder.Ordered else DeliveryOrder.Unordered,
            reliability =
                when (open.channelType.reliability) {
                    Reliability.Reliable -> SctpReliability.Reliable
                    Reliability.PartialReliableRetransmit -> SctpReliability.MaxRetransmits(open.reliabilityParameter.toInt())
                    Reliability.PartialReliableTimed ->
                        SctpReliability.MaxLifetime(open.reliabilityParameter.toLong().milliseconds)
                    is Reliability.Unknown -> SctpReliability.Reliable
                },
            priority = open.priority,
        )

    // ── driver plumbing ──

    private sealed interface DriveItem {
        class Inbound(
            val packet: ReadBuffer,
        ) : DriveItem

        class Command(
            val command: com.ditchoom.webrtc.sctp.datachannel.Command,
        ) : DriveItem

        data object Timer : DriveItem

        data object TransportClosed : DriveItem
    }

    /**
     * One unit of ordered outgoing work. A release is an item rather than something the drive loop does
     * inline because the two must not be reordered against each other: the association hands back a
     * retransmission-queue packet the moment it is acked, and a [Send] of that same packet may still be
     * sitting in this queue. Both here, FIFO, one consumer — and the hazard is structural rather than
     * something each call site has to remember.
     */
    private sealed interface OutboundItem {
        val packet: ReadBuffer

        /** Put [packet] on the wire, then release it — the driver is its last reader either way. */
        class Send(
            override val packet: ReadBuffer,
        ) : OutboundItem

        /** Release [packet]: bytes the association has finished retransmitting from. */
        class Release(
            override val packet: ReadBuffer,
        ) : OutboundItem
    }

    private companion object {
        // Cap on user messages buffered per stream before its DCEP OPEN arrives — bounds a peer that
        // sends data on a stream it never OPENs (see pendingInbound / onMessage).
        private const val MAX_PENDING_INBOUND = 64

        // How many RFC 8899 ceiling changes stay observable. A search converges in a handful of probes,
        // so this holds several whole searches while staying bounded on a session that lives for days.
        private const val MAX_PATH_MTU_HISTORY = 32
    }
}

// The commands consumer coroutines hand to the drive loop (so association.handle is single-threaded).
internal sealed interface Command

internal class OpenCommand(
    val config: DataChannelConfig,
    val deferred: CompletableDeferred<DataChannelConnection>,
) : Command

/**
 * One user message on its way to the association.
 *
 * [wireByteCount] rides along rather than being re-derived on the drive loop, and it is deliberately not
 * `payload.remaining()`: an EMPTY message travels as RFC 8831 §6.6's single `0x00` marker byte, so the
 * buffer's own length would say one where the message is zero. It is the *message's* size — what
 * `a=max-message-size` bounds — measured once, by the caller, from the payload it was handed.
 */
internal class SendCommand(
    val options: SctpSendOptions,
    val payload: ReadBuffer,
    val wireByteCount: Long,
    val deferred: CompletableDeferred<Unit>,
) : Command

internal class CloseChannelCommand(
    val streamId: StreamId,
) : Command

/** The lower layer named the path, or moved it — RFC 8261 §6.1; see [SctpDataChannelStack.pathChanged]. */
internal class PathChangedCommand(
    val profile: SctpPathProfile.Assessed,
) : Command

/** The peer's `a=max-message-size` (RFC 8841 §6), delivered to the drive loop that gates sends on it. */
internal class PeerMessageLimitCommand(
    val limit: PeerMessageLimit,
) : Command

internal data object ShutdownCommand : Command

/**
 * Which direction of a data channel's two-sided close (RFC 8831 §6.7) has been reset. An enum rather
 * than a sealed hierarchy because neither case carries data — the identity of the half *is* the whole
 * fact — and rather than a `Boolean`, because `ourHalfDone = true` at a call site reads as a flag while
 * a half that has *landed* is one of two named things.
 */
internal enum class ResetHalf {
    /** Our outgoing stream reset completed — the peer acknowledged it. */
    Ours,

    /** The peer reset its outgoing stream, which is our incoming half. */
    Peers,
}

/**
 * What one received DATA message decoded to: a payload to deliver, or a typed refusal.
 *
 * Decoding a `WebRTC String` is the only place this stack turns attacker-supplied bytes into a higher
 * type, so it is the only place that can fail — and it must fail as a value, not as a throw into the
 * serialized drive loop, which would take the association down with it (T0 discipline).
 */
internal sealed interface InboundMessage {
    data class Deliver(
        val payload: DataChannelPayload,
    ) : InboundMessage

    data class Discarded(
        val reason: InboundDiscardReason,
    ) : InboundMessage
}

/**
 * Whether a peer's DCEP OPEN may register a channel here (RFC 8832 §6). A sealed decision rather than the
 * two-predicate `if` it replaces, because the third case — an id the application reserved out of band —
 * is invisible to both of those predicates and was therefore silently admitted.
 */
internal sealed interface InboundOpenAdmission {
    /** Register the channel and publish it on `accept`. */
    data object Admit : InboundOpenAdmission

    /** Do not register it; [reason] says why. The OPEN is still acknowledged, so a lost ACK converges. */
    data class Decline(
        val reason: InboundOpenDecline,
    ) : InboundOpenAdmission
}

/** Why a peer's DCEP OPEN was not registered. */
internal sealed interface InboundOpenDecline {
    /**
     * The id is of **our** parity (RFC 8832 §6), so it is not the peer's to open on. Admitting it would
     * let a misbehaving or duplicated peer OPEN overwrite a local channel.
     */
    data object OurParity : InboundOpenDecline

    /** A channel is already registered here — the ordinary retransmitted-OPEN case. */
    data object AlreadyOpen : InboundOpenDecline

    /**
     * The application reserved this id for a negotiated channel (RFC 8832 §5) and has not registered it
     * yet, so neither the parity test nor the routing map can see it. Admitting the OPEN would publish an
     * in-band channel on `accept` for a stream the application already owns, and the application's own
     * open would then fail as "in use" for a reason nothing reported.
     */
    data object ReservedOutOfBand : InboundOpenDecline
}

/** Why a received message could not be delivered. */
internal sealed interface InboundDiscardReason {
    /** PPID said `WebRTC String`, but the bytes are not valid UTF-8 (RFC 8831 §6.6 requires they are). */
    data object MalformedUtf8 : InboundDiscardReason
}

// One inbound user message held until its channel's DCEP OPEN registers the stream (see pendingInbound).
internal class PendingInbound(
    val payload: DataChannelPayload,
)

/**
 * Thrown to a caller awaiting [SctpDataChannelStack.open] / a channel `send` / `shutdown` when the stack
 * has torn down (transport closed, or the association aborted) — so the call fails fast with the typed
 * [reason] instead of suspending forever. [reason] is the association's [SctpFailureReason] when the
 * teardown was an abort, or null for a plain transport close.
 *
 * The typed [reason] is the discriminant, never the string. Re-parenting this onto socket's abstract
 * `SocketClosedException` (the QUIC-module extension point) — so a data-channel consumer catches it
 * uniformly with every other transport failure (ARCHITECTURE §3.1 "one thrown vocabulary") — is deferred with the
 * rest of the `SocketException` bridge: depending on `com.ditchoom:socket` collides socket's vendored
 * BoringSSL against buffer-crypto's on native (documented on the webrtc root's PeerConnectionFailureReason).
 */
public class SctpClosedException(
    public val reason: SctpFailureReason?,
) : Exception("SCTP data-channel stack closed${reason?.let { ": $it" } ?: ""}")

/**
 * One open data channel as a buffer-flow [Connection]<[ReadBuffer]> (RFC 8831). [send] posts one
 * user message to the association on this channel's stream with the channel's ordering + reliability;
 * [receive] is the inbound message flow. [id] is the SCTP stream identifier (RFC 8832 §6).
 *
 * **Backpressure is the suspension.** [send] returns as soon as the association accepts the message
 * while its send buffer is shallow, but once queued-but-unsent bytes pass
 * [SctpConfig.sendBufferHighWaterBytes] it suspends the caller until the peer has acknowledged enough
 * to drain back to [SctpConfig.sendBufferLowWaterBytes]. So the obvious producer loop —
 * `for (chunk in source) channel.send(chunk)` — is already flow-controlled, and a sender that outruns
 * the wire is throttled rather than buffered without bound.
 *
 * There is deliberately no `bufferedAmount` gauge and no low-water callback to subscribe to: the
 * suspension is the whole contract. If the association tears down while a caller is suspended, [send]
 * throws [SctpClosedException] — it never suspends forever.
 */
public class DataChannelConnection internal constructor(
    internal val streamId: StreamId,
    public val config: DataChannelConfig,
    private val stack: SctpDataChannelStack,
) : Connection<DataChannelPayload> {
    private val inbound = Channel<DataChannelPayload>(Channel.UNLIMITED)
    private var open = true

    override val id: Long = streamId.value.toLong()

    override suspend fun send(message: DataChannelPayload) {
        check(open) { "data channel ${streamId.value} is closed" }
        stack.sendMessage(streamId, config, message)
    }

    /**
     * The inbound message flow. **Each buffer is transferred to the collector**, which owes it a
     * `freeIfNeeded()` once it has finished reading — it is a reassembly copy allocated from
     * `SctpConfig.bufferFactory`, and on a pooled or native-memory factory a collector that only reads it
     * keeps that memory out of circulation for the life of the process.
     *
     * Deliberately not drained on close: a closed channel's flow still emits what is already buffered in
     * it, so releasing those here would be taking messages the application can still legitimately read.
     * The corollary is that abandoning a channel with unread messages abandons their buffers too.
     */
    override fun receive(): Flow<DataChannelPayload> = inbound.receiveAsFlow()

    /**
     * Close this data channel: stop delivering inbound messages, and reset the outgoing SCTP stream so
     * the peer's channel closes too (RFC 8831 §6.7 / RFC 6525). Returns as soon as the close is posted —
     * the reset itself is an exchange on the wire, and the stream id becomes reusable only once the peer
     * has reset its half in return. Idempotent: a second call posts nothing.
     */
    override suspend fun close() {
        closeLocal()
        stack.closeChannel(streamId)
    }

    internal fun deliver(payload: DataChannelPayload) {
        inbound.trySend(payload)
    }

    internal fun closeLocal() {
        open = false
        inbound.close()
    }
}
