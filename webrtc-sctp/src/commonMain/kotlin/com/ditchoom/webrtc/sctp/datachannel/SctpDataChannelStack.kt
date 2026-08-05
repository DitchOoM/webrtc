@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.Receiver
import com.ditchoom.buffer.flow.Sender
import com.ditchoom.buffer.flow.StreamMux
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.PayloadProtocolId
import com.ditchoom.webrtc.sctp.StreamId
import com.ditchoom.webrtc.sctp.association.SctpAssociation
import com.ditchoom.webrtc.sctp.association.SctpAssociationState
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.association.SctpEvent
import com.ditchoom.webrtc.sctp.association.SctpFailureReason
import com.ditchoom.webrtc.sctp.association.SctpOutput
import com.ditchoom.webrtc.sctp.association.SctpReliability
import com.ditchoom.webrtc.sctp.association.SctpSendOptions
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
) : StreamMux<ReadBuffer> {
    private val association = SctpAssociation(config, random)
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
    private var nextStreamId: Int = if (role == SctpRole.Client) 0 else 1
    private var closed = false

    // Stream ids mid-close: RFC 8831 §6.7 closes a data channel by resetting BOTH directions, and the two
    // resets are independent RFC 6525 exchanges that complete in either order. An id sits here holding
    // whichever half has landed; when the other one arrives the entry is dropped and the id recycled.
    private val resetHalves = HashMap<StreamId, ResetHalf>()

    // Stream ids whose channel is fully closed on both sides and which may back a new open. Reusing an id
    // is only safe after both resets: the SSN state the peer holds for it is gone, so a new channel's
    // first ordered message at SSN 0 is not read as a duplicate of the old channel's.
    private val reusableStreamIds = ArrayDeque<StreamId>()

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

    /** Queued-but-unsent user bytes, and how many senders are parked on backpressure — test-visible only. */
    internal val bufferedBytes: Int get() = association.bufferedBytes
    internal val parkedSenders: Int get() = awaitingDrain.size

    /**
     * Stream ids whose channel closed in both directions and that a future open will reuse — test-visible
     * only. It is the one direct read of "the close finished on the wire": a channel id lands here exactly
     * when its second RFC 6525 reset completes, which no consumer-facing signal reports (the flow closing
     * only means the *local* half is done).
     */
    internal val recycledStreamIds: List<StreamId> get() = reusableStreamIds.toList()

    /** Launch the driver: the transport reader, and the single serialized association drive loop. */
    public fun start() {
        scope.launch { readerLoop() }
        scope.launch { writerLoop() }
        scope.launch { driveLoop() }
    }

    // ── StreamMux<ReadBuffer> ──

    override suspend fun openBidirectional(): Connection<ReadBuffer> = open(DataChannelConfig())

    /** Open a data channel with explicit [config] (label / ordering / reliability) — RFC 8832 §5.1. */
    public suspend fun open(config: DataChannelConfig): Connection<ReadBuffer> {
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

    override suspend fun acceptBidirectional(): Connection<ReadBuffer> = accepted.receive()

    // WebRTC data channels are always bidirectional; a unidirectional view is a bidirectional channel
    // used in one direction (RFC 8831 has no half-open channel type).
    override suspend fun openUnidirectional(): Sender<ReadBuffer> = open(DataChannelConfig())

    override suspend fun acceptUnidirectional(): Receiver<ReadBuffer> = accepted.receive()

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
            is OpenCommand ->
                if (association.state == SctpAssociationState.Established) {
                    dispatchOpen(command)
                } else {
                    pendingOpens.addLast(command)
                }
            is SendCommand -> {
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
            ShutdownCommand -> apply(association.handle(SctpEvent.Shutdown, now()))
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
        pendingInbound.remove(streamId)?.forEach { it.payload.freeIfNeeded() }
    }

    private fun resetOutgoing(streams: Set<StreamId>) {
        apply(association.handle(SctpEvent.ResetStreams(StreamResetScope.Streams(streams)), now()))
    }

    private fun dispatchOpen(command: OpenCommand) {
        // Prefer an id whose channel closed cleanly on both sides over burning a fresh one (RFC 8832 §6
        // gives each side only half of a 16-bit space, and `nextStreamId` never comes back down).
        val streamId =
            if (reusableStreamIds.isEmpty()) {
                StreamId(nextStreamId).also { nextStreamId += 2 }
            } else {
                reusableStreamIds.removeFirst()
            }
        val connection = registerChannel(streamId, command.config, incoming = false)
        unconfirmedOutbound += streamId
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
                is SctpOutput.MessageReceived -> onMessage(output)
                is SctpOutput.Aborted -> tearDown(output.reason)
                // The association survived the peer's restart, but every channel on it did not: the peer
                // has forgotten each stream, so continuing would be a lie. Tear down with a typed reason
                // and let the session renegotiate (RFC 4960 §5.2.4 action A — see SctpOutput.PeerRestarted).
                SctpOutput.PeerRestarted -> tearDown(SctpFailureReason.PeerRestarted)
                is SctpOutput.IncomingStreamsReset -> onIncomingStreamsReset(output.scope)
                is SctpOutput.OutgoingStreamsReset -> onOutgoingStreamsReset(output.scope, output.outcome)
            }
        }
        flushReciprocalResets()
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
            noteResetHalf(streamId, ResetHalf.Peers)
        }
    }

    private fun onOutgoingStreamsReset(
        scope: StreamResetScope,
        outcome: StreamResetOutcome,
    ) {
        for (streamId in scope.resolve()) {
            when (outcome) {
                StreamResetOutcome.Performed -> noteResetHalf(streamId, ResetHalf.Ours)
                // The peer refused, or cannot reset at all. It still holds SSN state for the stream, so the
                // channel is closed locally (already done) but the id is spent for the rest of the session.
                is StreamResetOutcome.Refused, StreamResetOutcome.Unsupported -> resetHalves.remove(streamId)
            }
        }
    }

    // Record one direction of a channel's close; when both have landed the id is free to open again.
    private fun noteResetHalf(
        streamId: StreamId,
        half: ResetHalf,
    ) {
        val seen = resetHalves.put(streamId, half)
        if (seen != null && seen != half) {
            resetHalves.remove(streamId)
            // Only ids of OUR parity are ours to hand out again (RFC 8832 §6) — a peer-opened stream is
            // the peer's to reuse, and claiming it would collide with its next open.
            if (!streamIsPeerParity(streamId)) reusableStreamIds.addLast(streamId)
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
            StreamResetScope.AllStreams -> channels.keys + resetHalves.keys
            is StreamResetScope.Streams -> ids
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
        val empty = isEmptyPpid(message.payloadProtocolId)
        if (empty) message.payload.freeIfNeeded()
        val payload = if (empty) ReadBuffer.EMPTY_BUFFER else message.payload
        val connection = channels[message.streamId]
        if (connection != null) {
            connection.deliver(payload)
        } else {
            // User data (an unordered first message) beat its ordered DCEP OPEN — hold it, bounded, until
            // the OPEN registers the channel; drop beyond the cap (a peer sending data on a stream it
            // never OPENs). Dropping means releasing: past the cap this is the message's last reader.
            val queue = pendingInbound.getOrPut(message.streamId) { ArrayDeque() }
            if (queue.size < MAX_PENDING_INBOUND) {
                queue.addLast(PendingInbound(message.payloadProtocolId, payload))
            } else {
                payload.freeIfNeeded()
            }
        }
    }

    private fun onDcep(message: SctpOutput.MessageReceived) {
        when (val decoded = (DataChannelMessage.decode(message.payload) as? DataChannelDecodeResult.Success)?.message) {
            is DataChannelMessage.Open -> {
                // RFC 8832 §6: the peer owns the opposite stream-id parity. Reject an OPEN on our own
                // parity (a misbehaving/duplicate peer OPEN would otherwise overwrite a local channel),
                // and reject a duplicate OPEN on an already-registered stream.
                if (streamIsPeerParity(message.streamId) && message.streamId !in channels) {
                    val config = configOf(decoded)
                    registerChannel(message.streamId, config, incoming = true)
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

    // Whether [streamId] carries the PEER's parity (RFC 8832 §6): a Client peer uses even ids, a Server
    // peer odd — i.e. the opposite of our own role's parity.
    private fun streamIsPeerParity(streamId: StreamId): Boolean {
        val even = streamId.value % 2 == 0
        return if (role == SctpRole.Client) !even else even
    }

    private fun registerChannel(
        streamId: StreamId,
        config: DataChannelConfig,
        incoming: Boolean,
    ): DataChannelConnection {
        val connection = DataChannelConnection(streamId, config, this)
        channels[streamId] = connection
        // Flush any user data that arrived before this OPEN, in arrival order.
        pendingInbound.remove(streamId)?.forEach { held ->
            connection.deliver(if (isEmptyPpid(held.ppid)) ReadBuffer.EMPTY_BUFFER else held.payload)
        }
        if (incoming) accepted.trySend(connection)
        return connection
    }

    // Called by a DataChannelConnection.send — routes one user message through the association.
    internal suspend fun sendMessage(
        streamId: StreamId,
        config: DataChannelConfig,
        message: ReadBuffer,
    ) {
        val empty = message.remaining() == 0
        val ppid = if (empty) PayloadProtocolId.WebRtcBinaryEmpty else PayloadProtocolId.WebRtcBinary
        // SCTP DATA must carry ≥ 1 byte; an empty application message rides a single 0x00 with an
        // empty-marker PPID (RFC 8831 §6.6), stripped back to empty on delivery.
        val payload = if (empty) singleZeroByte() else message
        val deferred = CompletableDeferred<Unit>()
        val options = SctpSendOptions(streamId, ppid, delivery = config.delivery, reliability = config.reliability)
        try {
            post(SendCommand(options, payload, deferred))
            deferred.await()
        } finally {
            // The marker byte is ours; [message] is the application's and is never freed here. By the time
            // the deferred settles — completed or failed — the association has either encoded the payload
            // into its wire packets or never accepted it, and holds no view of it either way.
            if (empty) payload.freeIfNeeded()
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
            for (held in queue) held.payload.freeIfNeeded()
        }
        pendingInbound.clear()
        unconfirmedOutbound.clear()
        resetHalves.clear()
        reusableStreamIds.clear()
        reciprocalResets.clear()
        for (command in pendingOpens) command.deferred.completeExceptionally(cause)
        pendingOpens.clear()
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
            is CloseChannelCommand, ShutdownCommand -> Unit
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
    }
}

// The commands consumer coroutines hand to the drive loop (so association.handle is single-threaded).
internal sealed interface Command

internal class OpenCommand(
    val config: DataChannelConfig,
    val deferred: CompletableDeferred<DataChannelConnection>,
) : Command

internal class SendCommand(
    val options: SctpSendOptions,
    val payload: ReadBuffer,
    val deferred: CompletableDeferred<Unit>,
) : Command

internal class CloseChannelCommand(
    val streamId: StreamId,
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

// One inbound user message held until its channel's DCEP OPEN registers the stream (see pendingInbound).
internal class PendingInbound(
    val ppid: PayloadProtocolId,
    val payload: ReadBuffer,
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
) : Connection<ReadBuffer> {
    private val inbound = Channel<ReadBuffer>(Channel.UNLIMITED)
    private var open = true

    override val id: Long = streamId.value.toLong()

    override suspend fun send(message: ReadBuffer) {
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
    override fun receive(): Flow<ReadBuffer> = inbound.receiveAsFlow()

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

    internal fun deliver(payload: ReadBuffer) {
        inbound.trySend(payload)
    }

    internal fun closeLocal() {
        open = false
        inbound.close()
    }
}
