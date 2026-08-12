@file:Suppress("UNUSED_PARAMETER")

package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Connection
import com.ditchoom.webrtc.ice.CandidateGeneration
import com.ditchoom.webrtc.ice.IceServerCredentials
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.association.SctpReliability
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelPayload
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
 * The browser [PeerConnectionSupport] (js): the one target where we **wrap, not reimplement** (ARCHITECTURE §1.1)
 * — [PeerConnectionSupport.BrowserDelegated.create] maps our [RtcPeerConnection] onto the browser's own
 * `RTCPeerConnection`.
 *
 * Under **Node** (no `RTCPeerConnection`) this reports
 * [PeerConnectionUnavailableReason.NoBlockingKeyAgreement] rather than [PeerConnectionSupport.Native].
 * It used to say `Native`, and that was a lie with a delayed fuse: the app built a
 * [NativePeerConnection], ICE gathered and checked perfectly well — `socket-udp` does publish a js actual,
 * so UDP is not the obstacle — and the session then died at the **DTLS handshake**, because the key
 * schedule needs a *blocking* raw-ECDH premaster and buffer-crypto's shared js/wasmJs `KeyAgreement` is
 * WebCrypto, which is async-only. Everything up to the handshake looked healthy, which is the worst place
 * to find out (webrtc#126).
 */
public actual fun peerConnectionSupport(): PeerConnectionSupport =
    if (rtcPeerConnectionAvailable()) {
        JsBrowserSupport
    } else {
        PeerConnectionSupport.Unavailable(PeerConnectionUnavailableReason.NoBlockingKeyAgreement)
    }

private fun rtcPeerConnectionAvailable(): Boolean = js("typeof RTCPeerConnection !== 'undefined'").unsafeCast<Boolean>()

private object JsBrowserSupport : PeerConnectionSupport.BrowserDelegated {
    override fun create(
        scope: CoroutineScope,
        iceServers: List<IceServer>,
    ): RtcPeerConnection = BrowserPeerConnection(iceServers)
}

// Build the RTCConfiguration { iceServers: [{ urls, username?, credential? }] }, then the RTCPeerConnection.
private fun newRtcPeerConnection(iceServers: List<IceServer>): dynamic {
    val config: dynamic = js("({})")
    val servers = js("[]")
    for (server in iceServers) {
        val entry: dynamic = js("({})")
        val urls = js("[]")
        for (u in server.urls) urls.push(u)
        entry.urls = urls
        // Both halves together or neither — the sealed credential makes the half-filled entry the
        // browser used to accept unrepresentable. `IceServerCredentials` is imported from
        // `com.ditchoom.webrtc.ice`: Kotlin cannot reach a nested classifier through the typealias.
        when (val credentials = server.credentials) {
            IceServerCredentials.None -> Unit
            is IceServerCredentials.LongTerm -> {
                entry.username = credentials.username
                entry.credential = credentials.credential
            }
        }
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

private fun iceCandidateInit(
    candidate: String,
    generation: CandidateGeneration,
): dynamic {
    val c: dynamic = js("({})")
    c.candidate = candidate
    // Match by m-line index only (a single m=application section): hardcoding sdpMid="0" would make the
    // browser reject a candidate when the remote description used a different mid.
    c.sdpMLineIndex = 0
    // RFC 8838 §3.1's generation tag is `RTCIceCandidateInit.usernameFragment` in the W3C API, so it is
    // forwarded verbatim rather than re-encoded onto the line. Untagged leaves the field absent (`null`
    // means "this generation", per spec) — which is what every caller that never heard of the tag sends.
    when (generation) {
        CandidateGeneration.Untagged -> Unit
        is CandidateGeneration.Tagged -> c.usernameFragment = generation.ufrag.value
    }
    return c
}

// Forward the DataChannelConfig into an RTCDataChannelInit so ordered/reliability/protocol are honored,
// not silently dropped to the browser defaults (ordered + reliable).
private fun dataChannelInit(config: DataChannelConfig): dynamic {
    val init: dynamic = js("({})")
    init.ordered = config.delivery == DeliveryOrder.Ordered
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
        // The browser selects the pair internally and exposes no pair object here, and no portable failure
        // discriminant — hence Opaque / Unknown.
        "connected" -> PeerConnectionState.Connected(SelectedPath.Opaque)
        "failed" -> PeerConnectionState.Failed(PeerConnectionFailureReason.Unknown("RTCPeerConnection connectionState=failed"))
        "closed" -> PeerConnectionState.Closed
        else -> PeerConnectionState.Connecting
    }

// The typeof of a JS value (Kotlin/JS js() inlines and can reference the parameter by name).
private fun jsTypeof(o: dynamic): String = js("typeof o")

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

@OptIn(ExternalRtcPeerConnectionImplementation::class)
private class BrowserPeerConnection(
    iceServers: List<IceServer>,
) : RtcPeerConnection {
    private val pc: dynamic = newRtcPeerConnection(iceServers)

    private val _connectionState = MutableStateFlow<PeerConnectionState>(PeerConnectionState.New)
    override val connectionState: StateFlow<PeerConnectionState> get() = _connectionState

    private val _signalingState = MutableStateFlow<SignalingState>(SignalingState.Stable)
    override val signalingState: StateFlow<SignalingState> get() = _signalingState

    private val candidateChannel = Channel<String>(Channel.UNLIMITED)
    override val localIceCandidates: Flow<String> get() = candidateChannel.receiveAsFlow()

    private val dataChannelChannel = Channel<Connection<DataChannelPayload>>(Channel.UNLIMITED)
    override val incomingDataChannels: Flow<Connection<DataChannelPayload>> get() = dataChannelChannel.receiveAsFlow()

    private val renegotiationChannel = Channel<Unit>(Channel.CONFLATED)
    override val renegotiationNeeded: Flow<Unit> get() = renegotiationChannel.receiveAsFlow()

    init {
        pc.onnegotiationneeded = { _: dynamic -> renegotiationChannel.trySend(Unit) }
        pc.onicecandidate = { event: dynamic ->
            val candidate = event.candidate
            if (candidate != null) candidateChannel.trySend(candidate.candidate.unsafeCast<String>())
        }
        pc.ondatachannel = { event: dynamic -> dataChannelChannel.trySend(BrowserDataChannel(event.channel)) }
        pc.onconnectionstatechange = { _: dynamic -> _connectionState.value = mapConnectionState(pc.connectionState.unsafeCast<String>()) }
        pc.onsignalingstatechange =
            { _: dynamic -> mapSignalingState(pc.signalingState.unsafeCast<String>())?.let { _signalingState.value = it } }
    }

    override suspend fun createDataChannel(config: DataChannelConfig): Connection<DataChannelPayload> =
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

    override suspend fun addIceCandidate(
        candidate: String,
        generation: CandidateGeneration,
    ) {
        pc.addIceCandidate(iceCandidateInit(candidate, generation)).unsafeCast<Promise<dynamic>>().await()
    }

    // 1:1 with the native stack, which is why restartIce() was specified as deferred-intent rather than
    // immediate: `RTCPeerConnection.restartIce()` also just marks the next offer, and fires
    // negotiationneeded. Nothing to emulate.
    override suspend fun restartIce() {
        pc.restartIce()
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
) : Connection<DataChannelPayload> {
    private val inbound = Channel<DataChannelPayload>(Channel.UNLIMITED)
    private val opened = CompletableDeferred<Unit>()

    override val id: Long get() = (dc.id.unsafeCast<Int?>())?.toLong() ?: -1L

    init {
        dc.binaryType = "arraybuffer"
        if (dc.readyState.unsafeCast<String>() == "open") opened.complete(Unit)
        dc.onopen = { _: dynamic -> opened.complete(Unit) }
        dc.onmessage = { event: dynamic ->
            val data = event.data
            // The browser already tells us which kind of message this is, and now the type can carry it:
            // a text-mode message is delivered AS text instead of being re-encoded to bytes so it could
            // fit a buffer-only API. `binaryType = "arraybuffer"` still governs the binary half.
            val payload =
                if (jsTypeof(data) == "string") {
                    DataChannelPayload.Text(data.unsafeCast<String>())
                } else {
                    DataChannelPayload.Binary(arrayBufferToReadBuffer(data.unsafeCast<ArrayBuffer>()))
                }
            inbound.trySend(payload)
        }
        dc.onclose = { _: dynamic -> inbound.close() }
    }

    override suspend fun send(message: DataChannelPayload) {
        opened.await()
        when (message) {
            // A JS string, not an encoded buffer: this is what makes the peer's `event.data` a String.
            // The old path sent every message as an ArrayBuffer, so no browser peer ever saw text from us.
            is DataChannelPayload.Text -> dc.send(message.text.toString())
            is DataChannelPayload.Binary -> dc.send(readBufferToArrayBuffer(message.bytes))
        }
    }

    override fun receive(): Flow<DataChannelPayload> = inbound.receiveAsFlow()

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
    // BufferFactory.Default is correct HERE, and is not a missed seam: on the browser-delegated path the
    // whole stack is the browser's own RTCPeerConnection, `create(scope, iceServers)` takes no config, and
    // so there is no consumer-injected factory in play to honour. Every allocation the PURE-KOTLIN stack
    // makes routes through an injected factory (see webrtc-stun / SctpConfig / IceConfig).
    val out = BufferFactory.Default.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
    for (i in 0 until len) out.writeByte(u8[i])
    out.resetForRead()
    out.setLimit(len)
    return out
}
