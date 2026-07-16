@file:Suppress("UNUSED_PARAMETER")

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.webrtc.sctp.association.SctpReliability
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.sdp.SignalingState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.await
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Uint8Array
import org.khronos.webgl.get
import org.khronos.webgl.set
import kotlin.js.Promise

/**
 * The browser [PeerConnectionSupport] (js): the one target where we **wrap, not reimplement** (RFC §1.1)
 * — [createDelegated] maps our [RtcPeerConnection] onto the browser's own `RTCPeerConnection`. Under Node
 * (no `RTCPeerConnection`) it reports [PeerConnectionKind.Native] so a caller isn't handed a delegator it
 * cannot back.
 */
public actual fun peerConnectionSupport(): PeerConnectionSupport =
    if (rtcPeerConnectionAvailable()) JsBrowserSupport else NativePeerConnectionSupport

private fun rtcPeerConnectionAvailable(): Boolean = js("typeof RTCPeerConnection !== 'undefined'").unsafeCast<Boolean>()

private object JsBrowserSupport : PeerConnectionSupport {
    override val kind: PeerConnectionKind get() = PeerConnectionKind.BrowserDelegated

    override fun createDelegated(
        scope: CoroutineScope,
        iceServers: List<String>,
    ): RtcPeerConnection = BrowserPeerConnection(iceServers)
}

// Build the RTCConfiguration { iceServers: [{ urls }] } from a flat URL list, then the RTCPeerConnection.
private fun newRtcPeerConnection(iceServers: List<String>): dynamic {
    val config: dynamic = js("({})")
    val servers = js("[]")
    for (url in iceServers) {
        val entry: dynamic = js("({})")
        entry.urls = url
        servers.push(entry)
    }
    config.iceServers = servers
    return js("new RTCPeerConnection(config)")
}

private fun sessionDescription(
    type: SdpType,
    sdp: String,
): dynamic {
    val d: dynamic = js("({})")
    d.type = type.token
    if (type != SdpType.Rollback) d.sdp = sdp
    return d
}

private fun iceCandidateInit(candidate: String): dynamic {
    val c: dynamic = js("({})")
    c.candidate = candidate
    // Match by m-line index only (a single m=application section): hardcoding sdpMid="0" would make the
    // browser reject a candidate when the remote description used a different mid.
    c.sdpMLineIndex = 0
    return c
}

// Forward the DataChannelConfig into an RTCDataChannelInit so ordered/reliability/protocol are honored,
// not silently dropped to the browser defaults (ordered + reliable).
private fun dataChannelInit(config: DataChannelConfig): dynamic {
    val init: dynamic = js("({})")
    init.ordered = config.ordered
    when (val r = config.reliability) {
        SctpReliability.Reliable -> Unit
        is SctpReliability.MaxRetransmits -> init.maxRetransmits = r.maxRetransmits
        is SctpReliability.MaxLifetime -> init.maxPacketLifeTime = r.maxLifetime.inWholeMilliseconds.toInt()
    }
    if (config.protocol.isNotEmpty()) init.protocol = config.protocol
    return init
}

private fun mapConnectionState(state: String): PeerConnectionState =
    when (state) {
        "new" -> PeerConnectionState.New
        // "disconnected" is a *transient* W3C ICE state that routinely recovers to "connected" — report a
        // non-terminal Connecting, never Closed, so a collector doesn't tear down a recoverable session.
        "connecting", "disconnected" -> PeerConnectionState.Connecting
        // The browser exposes no pair object here, and no portable failure discriminant — hence null / Unknown.
        "connected" -> PeerConnectionState.Connected(null)
        "failed" -> PeerConnectionState.Failed(PeerConnectionFailureReason.Unknown("RTCPeerConnection connectionState=failed"))
        "closed" -> PeerConnectionState.Closed
        else -> PeerConnectionState.Connecting
    }

// The typeof of a JS value (Kotlin/JS js() inlines and can reference the parameter by name).
private fun jsTypeof(o: dynamic): String = js("typeof o")

// UTF-8 encode a JS string via TextEncoder → Uint8Array (no Kotlin ByteArray at the browser edge).
private fun encodeUtf8(s: String): Uint8Array = js("new TextEncoder().encode(s)")

private fun mapSignalingState(state: String): SignalingState? =
    when (state) {
        "stable" -> SignalingState.Stable
        "have-local-offer" -> SignalingState.HaveLocalOffer
        "have-remote-offer" -> SignalingState.HaveRemoteOffer
        "have-local-pranswer" -> SignalingState.HaveLocalPrAnswer
        "have-remote-pranswer" -> SignalingState.HaveRemotePrAnswer
        "closed" -> SignalingState.Closed
        else -> null
    }

private class BrowserPeerConnection(
    iceServers: List<String>,
) : RtcPeerConnection {
    private val pc: dynamic = newRtcPeerConnection(iceServers)

    private val _connectionState = MutableStateFlow<PeerConnectionState>(PeerConnectionState.New)
    override val connectionState: StateFlow<PeerConnectionState> get() = _connectionState

    private val _signalingState = MutableStateFlow<SignalingState>(SignalingState.Stable)
    override val signalingState: StateFlow<SignalingState> get() = _signalingState

    private val candidateChannel = Channel<String>(Channel.UNLIMITED)
    override val localIceCandidates: Flow<String> get() = candidateChannel.receiveAsFlow()

    private val dataChannelChannel = Channel<Connection<ReadBuffer>>(Channel.UNLIMITED)
    override val incomingDataChannels: Flow<Connection<ReadBuffer>> get() = dataChannelChannel.receiveAsFlow()

    init {
        pc.onicecandidate = { event: dynamic ->
            val candidate = event.candidate
            if (candidate != null) candidateChannel.trySend(candidate.candidate.unsafeCast<String>())
        }
        pc.ondatachannel = { event: dynamic -> dataChannelChannel.trySend(BrowserDataChannel(event.channel)) }
        pc.onconnectionstatechange = { _: dynamic -> _connectionState.value = mapConnectionState(pc.connectionState.unsafeCast<String>()) }
        pc.onsignalingstatechange =
            { _: dynamic -> mapSignalingState(pc.signalingState.unsafeCast<String>())?.let { _signalingState.value = it } }
    }

    override suspend fun createDataChannel(config: DataChannelConfig): Connection<ReadBuffer> =
        BrowserDataChannel(pc.createDataChannel(config.label, dataChannelInit(config)))

    override suspend fun createOffer(): String =
        pc
            .createOffer()
            .unsafeCast<Promise<dynamic>>()
            .await()
            .sdp
            .unsafeCast<String>()

    override suspend fun createAnswer(): String =
        pc
            .createAnswer()
            .unsafeCast<Promise<dynamic>>()
            .await()
            .sdp
            .unsafeCast<String>()

    override suspend fun setLocalDescription(
        type: SdpType,
        sdp: String,
    ) {
        pc.setLocalDescription(sessionDescription(type, sdp)).unsafeCast<Promise<dynamic>>().await()
    }

    override suspend fun setRemoteDescription(
        type: SdpType,
        sdp: String,
    ) {
        pc.setRemoteDescription(sessionDescription(type, sdp)).unsafeCast<Promise<dynamic>>().await()
    }

    override suspend fun addIceCandidate(candidate: String) {
        pc.addIceCandidate(iceCandidateInit(candidate)).unsafeCast<Promise<dynamic>>().await()
    }

    override suspend fun close() {
        pc.close()
        candidateChannel.close()
        dataChannelChannel.close()
        _connectionState.value = PeerConnectionState.Closed
    }
}

private class BrowserDataChannel(
    private val dc: dynamic,
) : Connection<ReadBuffer> {
    private val inbound = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val opened = CompletableDeferred<Unit>()

    override val id: Long get() = (dc.id.unsafeCast<Int?>())?.toLong() ?: -1L

    init {
        dc.binaryType = "arraybuffer"
        if (dc.readyState.unsafeCast<String>() == "open") opened.complete(Unit)
        dc.onopen = { _: dynamic -> opened.complete(Unit) }
        dc.onmessage = { event: dynamic ->
            val data = event.data
            // A peer may send a text-mode message even with binaryType=arraybuffer — decode it rather than
            // reinterpret a JS string as an ArrayBuffer (which would corrupt the ReadBuffer).
            val buffer =
                if (jsTypeof(data) == "string") {
                    arrayBufferToReadBuffer(encodeUtf8(data.unsafeCast<String>()).buffer)
                } else {
                    arrayBufferToReadBuffer(data.unsafeCast<ArrayBuffer>())
                }
            inbound.trySend(buffer)
        }
        dc.onclose = { _: dynamic -> inbound.close() }
    }

    override suspend fun send(message: ReadBuffer) {
        opened.await()
        dc.send(readBufferToArrayBuffer(message))
    }

    override fun receive(): Flow<ReadBuffer> = inbound.receiveAsFlow()

    override suspend fun close() {
        dc.close()
        inbound.close()
    }
}

private fun readBufferToArrayBuffer(buf: ReadBuffer): ArrayBuffer {
    val start = buf.position()
    val len = buf.limit() - start
    val u8 = Uint8Array(len)
    for (i in 0 until len) u8[i] = buf.get(start + i)
    return u8.buffer
}

private fun arrayBufferToReadBuffer(ab: ArrayBuffer): ReadBuffer {
    val u8 = Uint8Array(ab)
    val len = u8.length
    val out = BufferFactory.Default.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
    for (i in 0 until len) out.writeByte(u8[i])
    out.resetForRead()
    out.setLimit(len)
    return out
}
