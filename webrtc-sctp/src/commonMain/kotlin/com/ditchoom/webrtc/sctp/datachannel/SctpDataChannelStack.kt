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
    private var nextStreamId: Int = if (role == SctpRole.Client) 0 else 1

    private val _state = MutableStateFlow<SctpAssociationState>(SctpAssociationState.Closed)

    /** The association lifecycle, surfaced for the PeerConnection layer / tests to await. */
    public val state: StateFlow<SctpAssociationState> get() = _state

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
        inbox.send(DriveItem.Command(OpenCommand(config, deferred)))
        return deferred.await()
    }

    override suspend fun acceptBidirectional(): Connection<ReadBuffer> = accepted.receive()

    // WebRTC data channels are always bidirectional; a unidirectional view is a bidirectional channel
    // used in one direction (RFC 8831 has no half-open channel type).
    override suspend fun openUnidirectional(): Sender<ReadBuffer> = open(DataChannelConfig())

    override suspend fun acceptUnidirectional(): Receiver<ReadBuffer> = accepted.receive()

    /** Begin a graceful association shutdown (RFC 4960 §9.2). */
    public suspend fun shutdown() {
        inbox.send(DriveItem.Command(ShutdownCommand))
    }

    // ── the drive loop (the only place association.handle is called) ──

    private suspend fun readerLoop() {
        while (true) {
            val packet = transport.receive() ?: break
            inbox.send(DriveItem.Inbound(packet))
        }
        inbox.send(DriveItem.TransportClosed)
    }

    // Drain outgoing packets in strict emission order (SCTP tolerates reordering, but a single writer
    // keeps the wire deterministic and avoids a coroutine per datagram).
    private suspend fun writerLoop() {
        for (packet in outbound) transport.send(packet)
    }

    private suspend fun driveLoop() {
        if (role == SctpRole.Client) apply(association.handle(SctpEvent.Associate, now()))
        while (true) {
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
                DriveItem.TransportClosed -> {
                    tearDown()
                    break
                }
            }
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
                apply(association.handle(SctpEvent.SendMessage(command.options, command.payload), now()))
                command.deferred.complete(Unit)
            }
            ShutdownCommand -> apply(association.handle(SctpEvent.Shutdown, now()))
        }
    }

    private fun dispatchOpen(command: OpenCommand) {
        val streamId = StreamId(nextStreamId)
        nextStreamId += 2
        val connection = registerChannel(streamId, command.config, incoming = false)
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
                is SctpOutput.Aborted -> tearDown()
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
        if (message.payloadProtocolId == PayloadProtocolId.WebRtcDcep) {
            onDcep(message)
            return
        }
        val connection = channels[message.streamId.value] ?: return
        val payload = if (isEmptyPpid(message.payloadProtocolId)) ReadBuffer.EMPTY_BUFFER else message.payload
        connection.deliver(payload)
    }

    private fun onDcep(message: SctpOutput.MessageReceived) {
        when (val decoded = (DataChannelMessage.decode(message.payload) as? DataChannelDecodeResult.Success)?.message) {
            is DataChannelMessage.Open -> {
                val config = configOf(decoded)
                registerChannel(message.streamId, config, incoming = true)
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

    private fun registerChannel(
        streamId: StreamId,
        config: DataChannelConfig,
        incoming: Boolean,
    ): DataChannelConnection {
        val connection = DataChannelConnection(streamId, config, this)
        channels[streamId.value] = connection
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
        inbox.send(DriveItem.Command(SendCommand(options, payload, deferred)))
        deferred.await()
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

    private fun tearDown() {
        for (connection in channels.values) connection.closeLocal()
        channels.clear()
        accepted.close()
        outbound.close()
        transport.close()
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

internal data object ShutdownCommand : Command

/**
 * One open data channel as a buffer-flow [Connection]<[ReadBuffer]> (RFC 8831). [send] posts one
 * user message to the association on this channel's stream with the channel's ordering + reliability;
 * [receive] is the inbound message flow. [id] is the SCTP stream identifier (RFC 8832 §6).
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
    }

    internal fun deliver(payload: ReadBuffer) {
        inbound.trySend(payload)
    }

    internal fun closeLocal() {
        open = false
        inbound.close()
    }
}
