@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.buffer.flow.Receiver
import com.ditchoom.buffer.flow.Sender
import com.ditchoom.buffer.flow.StreamMux
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
import com.ditchoom.webrtc.sctp.dcep.ChannelType
import com.ditchoom.webrtc.sctp.dcep.DataChannelDecodeResult
import com.ditchoom.webrtc.sctp.dcep.DataChannelMessage
import com.ditchoom.webrtc.sctp.dcep.Reliability
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
 * runs under `runTest` virtual time (RFC §5.1). Every `association.handle(...)` call is serialized
 * through the single [driveLoop]; consumer `open`/`send`/`close` calls post commands into the same
 * inbox, so the non-thread-safe core is only ever touched from one coroutine.
 *
 * Stream ids follow RFC 8832 §6: a [SctpRole.Client] opener uses even ids and sends the INIT; a
 * [SctpRole.Server] uses odd ids. Channel close via SCTP stream reset (RFC 6525 RE-CONFIG) is not in
 * this subset — [Connection.close] tears down the local halves and is noted as a W7 follow-up.
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
    private val outbound = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val accepted = Channel<DataChannelConnection>(Channel.UNLIMITED)
    private val channels = HashMap<Int, DataChannelConnection>()
    private val pendingOpens = ArrayDeque<OpenCommand>()

    // Inbound user messages that arrived before their channel's DCEP OPEN registered the stream — held
    // briefly (bounded) and flushed when the OPEN lands, so an unordered first message that SCTP delivers
    // ahead of the still-in-order OPEN is not silently lost. Bounded to defeat a peer that never OPENs.
    private val pendingInbound = HashMap<Int, ArrayDeque<PendingInbound>>()
    private var nextStreamId: Int = if (role == SctpRole.Client) 0 else 1
    private var closed = false

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
    private val unconfirmedOutbound = HashSet<Int>()

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
        try {
            while (true) {
                val packet = transport.receive() ?: break
                inbox.send(DriveItem.Inbound(packet))
            }
            inbox.send(DriveItem.TransportClosed)
        } catch (_: kotlinx.coroutines.channels.ClosedSendChannelException) {
            // already torn down
        }
    }

    // Drain outgoing packets in strict emission order (SCTP tolerates reordering, but a single writer
    // keeps the wire deterministic and avoids a coroutine per datagram).
    private suspend fun writerLoop() {
        for (packet in outbound) transport.send(packet)
    }

    private suspend fun driveLoop() {
        if (role == SctpRole.Client) apply(association.handle(SctpEvent.Associate, now()))
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
                is DriveItem.Inbound -> apply(association.handle(SctpEvent.DatagramReceived(item.packet), now()))
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
                    if (command.options.streamId.value in unconfirmedOutbound) {
                        command.options.copy(unordered = false)
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
            is CloseChannelCommand -> {
                channels.remove(command.streamId.value)
                unconfirmedOutbound -= command.streamId.value
            }
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

    private fun dispatchOpen(command: OpenCommand) {
        val streamId = StreamId(nextStreamId)
        nextStreamId += 2
        val connection = registerChannel(streamId, command.config, incoming = false)
        unconfirmedOutbound += streamId.value
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
            ordered = true,
            reliability = SctpReliability.Reliable,
            payload = open.encode(bufferFactory),
        )
        command.deferred.complete(connection)
    }

    private fun apply(outputs: List<SctpOutput>) {
        for (output in outputs) {
            when (output) {
                is SctpOutput.Transmit -> {
                    output.packet.position(0)
                    outbound.trySend(output.packet.slice())
                }
                is SctpOutput.StateChanged -> onStateChanged(output.state)
                is SctpOutput.MessageReceived -> onMessage(output)
                is SctpOutput.Aborted -> tearDown(output.reason)
            }
        }
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
        unconfirmedOutbound -= message.streamId.value
        if (message.payloadProtocolId == PayloadProtocolId.WebRtcDcep) {
            onDcep(message)
            return
        }
        val payload = if (isEmptyPpid(message.payloadProtocolId)) ReadBuffer.EMPTY_BUFFER else message.payload
        val connection = channels[message.streamId.value]
        if (connection != null) {
            connection.deliver(payload)
        } else {
            // User data (an unordered first message) beat its ordered DCEP OPEN — hold it, bounded, until
            // the OPEN registers the channel; drop beyond the cap (a peer sending data on a stream it
            // never OPENs).
            val queue = pendingInbound.getOrPut(message.streamId.value) { ArrayDeque() }
            if (queue.size < MAX_PENDING_INBOUND) queue.addLast(PendingInbound(message.payloadProtocolId, payload))
        }
    }

    private fun onDcep(message: SctpOutput.MessageReceived) {
        when (val decoded = (DataChannelMessage.decode(message.payload) as? DataChannelDecodeResult.Success)?.message) {
            is DataChannelMessage.Open -> {
                // RFC 8832 §6: the peer owns the opposite stream-id parity. Reject an OPEN on our own
                // parity (a misbehaving/duplicate peer OPEN would otherwise overwrite a local channel),
                // and reject a duplicate OPEN on an already-registered stream.
                if (streamIsPeerParity(message.streamId) && message.streamId.value !in channels) {
                    val config = configOf(decoded)
                    registerChannel(message.streamId, config, incoming = true)
                }
                // Always ACK a (re-)OPEN so a peer whose ACK was lost converges.
                sendOnStream(
                    message.streamId,
                    PayloadProtocolId.WebRtcDcep,
                    ordered = true,
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
        channels[streamId.value] = connection
        // Flush any user data that arrived before this OPEN, in arrival order.
        pendingInbound.remove(streamId.value)?.forEach { held ->
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
        val options = SctpSendOptions(streamId, ppid, unordered = !config.ordered, reliability = config.reliability)
        post(SendCommand(options, payload, deferred))
        deferred.await()
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

    private fun sendOnStream(
        streamId: StreamId,
        ppid: PayloadProtocolId,
        ordered: Boolean,
        reliability: SctpReliability,
        payload: ReadBuffer,
    ) {
        val options = SctpSendOptions(streamId, ppid, unordered = !ordered, reliability = reliability)
        apply(association.handle(SctpEvent.SendMessage(options, payload), now()))
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
        pendingInbound.clear()
        unconfirmedOutbound.clear()
        for (command in pendingOpens) command.deferred.completeExceptionally(cause)
        pendingOpens.clear()
        accepted.close()
        outbound.close()
        transport.close()
        inbox.close()
        // Fail every command still queued (and thus every caller suspended on its deferred).
        while (true) {
            val item = inbox.tryReceive().getOrNull() ?: break
            if (item is DriveItem.Command) failCommand(item.command, cause)
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
            ordered = config.ordered,
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
            ordered = open.channelType.ordered,
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
 * uniformly with every other transport failure (RFC §3.1 "one thrown vocabulary") — is deferred with the
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

    override fun receive(): Flow<ReadBuffer> = inbound.receiveAsFlow()

    override suspend fun close() {
        closeLocal()
        stack.closeChannel(streamId) // drop from the routing map (no RFC 6525 stream reset in this subset — W7)
    }

    internal fun deliver(payload: ReadBuffer) {
        inbound.trySend(payload)
    }

    internal fun closeLocal() {
        open = false
        inbound.close()
    }
}
