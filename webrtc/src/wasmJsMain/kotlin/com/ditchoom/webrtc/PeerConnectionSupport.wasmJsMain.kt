@file:OptIn(ExperimentalWasmJsInterop::class)

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
import kotlin.js.ExperimentalWasmJsInterop
import kotlin.js.JsAny
import kotlin.js.JsString
import kotlin.js.Promise
import kotlin.js.toJsString

/**
 * The browser [PeerConnectionSupport] (wasmJs). wasmJs is a browser target where — like js — we **wrap,
 * not reimplement** (RFC §1.1): there is no real-UDP binder on wasm (socket-udp has no wasm target), so a
 * [NativePeerConnection] cannot run here and delegation to the browser `RTCPeerConnection` is the only
 * path.
 *
 * This is the same delegation the js actual provides (`PeerConnectionSupport.jsMain.kt`), expressed
 * through the **wasm JS-interop encoding** (`external interface : JsAny` handles + `@JsFun` bridges +
 * `JsString`) instead of js `dynamic` — the pattern buffer-crypto's WebCrypto bridges use. Data-channel
 * payloads cross the wasm↔JS boundary as **lowercase hex `JsString`** (byte-faithful, no `ByteArray` and
 * no webgl typed-array externals): the send side hex-encodes a [ReadBuffer]; the receive side decodes a
 * hex string — text or binary — back into one. Closing the W6 wasmJs follow-up: this actual now delegates
 * for real (Karma-tested via the loopback in `wasmJsTest`), not `NotImplementedError`.
 */
public actual fun peerConnectionSupport(): PeerConnectionSupport =
    if (jsRtcPeerConnectionAvailable()) WasmJsBrowserSupport else PeerConnectionSupport.Native

private object WasmJsBrowserSupport : PeerConnectionSupport.BrowserDelegated {
    override fun create(
        scope: CoroutineScope,
        iceServers: List<IceServer>,
    ): RtcPeerConnection = WasmBrowserPeerConnection(iceServers)
}

private class WasmBrowserPeerConnection(
    iceServers: List<IceServer>,
) : RtcPeerConnection {
    private val pc: JsRtcPeerConnection = jsNewRtcPeerConnection(iceServersJson(iceServers).toJsString())

    private val _connectionState = MutableStateFlow<PeerConnectionState>(PeerConnectionState.New)
    override val connectionState: StateFlow<PeerConnectionState> get() = _connectionState

    private val _signalingState = MutableStateFlow<SignalingState>(SignalingState.Stable)
    override val signalingState: StateFlow<SignalingState> get() = _signalingState

    private val candidateChannel = Channel<String>(Channel.UNLIMITED)
    override val localIceCandidates: Flow<String> get() = candidateChannel.receiveAsFlow()

    private val dataChannelChannel = Channel<Connection<ReadBuffer>>(Channel.UNLIMITED)
    override val incomingDataChannels: Flow<Connection<ReadBuffer>> get() = dataChannelChannel.receiveAsFlow()

    init {
        jsOnIceCandidate(pc) { line -> candidateChannel.trySend(line.toString()) }
        jsOnDataChannel(pc) { dc -> dataChannelChannel.trySend(WasmBrowserDataChannel(dc)) }
        jsOnConnectionStateChange(pc) { s -> _connectionState.value = mapConnectionState(s.toString()) }
        jsOnSignalingStateChange(pc) { s -> mapSignalingState(s.toString())?.let { _signalingState.value = it } }
    }

    override suspend fun createDataChannel(config: DataChannelConfig): Connection<ReadBuffer> =
        WasmBrowserDataChannel(jsCreateDataChannel(pc, config.label.toJsString(), dataChannelInitJson(config).toJsString()))

    override suspend fun createOffer(): String = jsCreateOffer(pc).await<JsString>().toString()

    override suspend fun createAnswer(): String = jsCreateAnswer(pc).await<JsString>().toString()

    override suspend fun setLocalDescription(
        type: SdpType,
        sdp: String,
    ) {
        // Rollback carries no SDP (mirrors the js actual); the bridge omits it when type == "rollback".
        jsSetLocalDescription(pc, type.token.toJsString(), sdp.toJsString()).await<JsAny?>()
    }

    override suspend fun setRemoteDescription(
        type: SdpType,
        sdp: String,
    ) {
        jsSetRemoteDescription(pc, type.token.toJsString(), sdp.toJsString()).await<JsAny?>()
    }

    override suspend fun addIceCandidate(candidate: String) {
        jsAddIceCandidate(pc, candidate.toJsString()).await<JsAny?>()
    }

    override suspend fun close() {
        jsCloseRtcPeerConnection(pc)
        candidateChannel.close()
        dataChannelChannel.close()
        _connectionState.value = PeerConnectionState.Closed
    }
}

private class WasmBrowserDataChannel(
    private val dc: JsRtcDataChannel,
) : Connection<ReadBuffer> {
    private val inbound = Channel<ReadBuffer>(Channel.UNLIMITED)
    private val opened = CompletableDeferred<Unit>()

    override val id: Long get() = jsDataChannelId(dc).let { if (it < 0) -1L else it.toLong() }

    init {
        jsDataChannelSetArrayBuffer(dc)
        if (jsDataChannelReadyState(dc).toString() == "open") opened.complete(Unit)
        jsDataChannelOnOpen(dc) { opened.complete(Unit) }
        // The bridge hands us the payload as hex (string messages TextEncoded, binary read straight),
        // so a text-mode message is never reinterpreted as an ArrayBuffer and corrupted.
        jsDataChannelOnMessageHex(dc) { hex -> inbound.trySend(hexToReadBuffer(hex.toString())) }
        jsDataChannelOnClose(dc) { inbound.close() }
    }

    override suspend fun send(message: ReadBuffer) {
        opened.await()
        jsDataChannelSend(dc, readBufferToHex(message).toJsString())
    }

    override fun receive(): Flow<ReadBuffer> = inbound.receiveAsFlow()

    override suspend fun close() {
        jsDataChannelClose(dc)
        inbound.close()
    }
}

// ── mapping helpers (shared shape with the js actual) ──

private fun mapConnectionState(state: String): PeerConnectionState =
    when (state) {
        "new" -> PeerConnectionState.New
        // "disconnected" is a *transient* W3C ICE state that routinely recovers — report a non-terminal
        // Connecting, never Closed, so a collector doesn't tear down a recoverable session.
        "connecting", "disconnected" -> PeerConnectionState.Connecting
        "connected" -> PeerConnectionState.Connected(null)
        "failed" -> PeerConnectionState.Failed(PeerConnectionFailureReason.Unknown("RTCPeerConnection connectionState=failed"))
        "closed" -> PeerConnectionState.Closed
        else -> PeerConnectionState.Connecting
    }

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

// RTCConfiguration { iceServers: [{ urls, username?, credential? }] } as JSON (parsed in the bridge).
private fun iceServersJson(iceServers: List<IceServer>): String =
    buildString {
        append("{\"iceServers\":[")
        iceServers.forEachIndexed { i, server ->
            if (i > 0) append(',')
            append("{\"urls\":[")
            server.urls.forEachIndexed { j, url ->
                if (j > 0) append(',')
                append('"').append(jsonEscape(url)).append('"')
            }
            append(']')
            server.username?.let { append(",\"username\":\"").append(jsonEscape(it)).append('"') }
            server.credential?.let { append(",\"credential\":\"").append(jsonEscape(it)).append('"') }
            append('}')
        }
        append("]}")
    }

// RTCDataChannelInit — ordered/reliability/protocol forwarded so they aren't dropped to browser defaults.
private fun dataChannelInitJson(config: DataChannelConfig): String =
    buildString {
        append("{\"ordered\":").append(config.ordered)
        when (val r = config.reliability) {
            SctpReliability.Reliable -> Unit
            is SctpReliability.MaxRetransmits -> append(",\"maxRetransmits\":").append(r.maxRetransmits)
            is SctpReliability.MaxLifetime -> append(",\"maxPacketLifeTime\":").append(r.maxLifetime.inWholeMilliseconds.toInt())
        }
        if (config.protocol.isNotEmpty()) append(",\"protocol\":\"").append(jsonEscape(config.protocol)).append("\"")
        append('}')
    }

private fun jsonEscape(s: String): String =
    buildString {
        for (c in s) {
            when (c) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                else -> append(c)
            }
        }
    }

private const val HEX = "0123456789abcdef"

private fun readBufferToHex(buf: ReadBuffer): String {
    val start = buf.position()
    val end = buf.limit()
    val sb = StringBuilder((end - start) * 2)
    for (i in start until end) {
        val b = buf.get(i).toInt() and 0xFF
        sb.append(HEX[b ushr 4]).append(HEX[b and 0x0F])
    }
    return sb.toString()
}

private fun hexDigit(c: Char): Int =
    when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> 0
    }

private fun hexToReadBuffer(hex: String): ReadBuffer {
    val len = hex.length / 2
    val out = BufferFactory.Default.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
    var i = 0
    while (i < len) {
        val hi = hexDigit(hex[i * 2])
        val lo = hexDigit(hex[i * 2 + 1])
        out.writeByte(((hi shl 4) or lo).toByte())
        i++
    }
    out.resetForRead()
    out.setLimit(len)
    return out
}

// ── the wasm↔JS bridge: opaque handles + @JsFun shims (RTCPeerConnection / RTCDataChannel) ──

private external interface JsRtcPeerConnection : JsAny

private external interface JsRtcDataChannel : JsAny

@JsFun("() => (typeof RTCPeerConnection !== 'undefined')")
private external fun jsRtcPeerConnectionAvailable(): Boolean

@JsFun("(cfgJson) => new RTCPeerConnection(JSON.parse(cfgJson))")
private external fun jsNewRtcPeerConnection(cfgJson: JsString): JsRtcPeerConnection

@JsFun("(pc, cb) => { pc.onicecandidate = (e) => { if (e.candidate) cb(e.candidate.candidate); }; }")
private external fun jsOnIceCandidate(
    pc: JsRtcPeerConnection,
    cb: (JsString) -> Unit,
)

@JsFun("(pc, cb) => { pc.ondatachannel = (e) => cb(e.channel); }")
private external fun jsOnDataChannel(
    pc: JsRtcPeerConnection,
    cb: (JsRtcDataChannel) -> Unit,
)

@JsFun("(pc, cb) => { pc.onconnectionstatechange = () => cb(pc.connectionState); }")
private external fun jsOnConnectionStateChange(
    pc: JsRtcPeerConnection,
    cb: (JsString) -> Unit,
)

@JsFun("(pc, cb) => { pc.onsignalingstatechange = () => cb(pc.signalingState); }")
private external fun jsOnSignalingStateChange(
    pc: JsRtcPeerConnection,
    cb: (JsString) -> Unit,
)

// Match by m-line index only (single m=application section): a hardcoded sdpMid would reject a candidate
// whose remote description used a different mid.
@JsFun("(pc, label, initJson) => pc.createDataChannel(label, JSON.parse(initJson))")
private external fun jsCreateDataChannel(
    pc: JsRtcPeerConnection,
    label: JsString,
    initJson: JsString,
): JsRtcDataChannel

@JsFun("(pc) => pc.createOffer().then((o) => o.sdp)")
private external fun jsCreateOffer(pc: JsRtcPeerConnection): Promise<JsString>

@JsFun("(pc) => pc.createAnswer().then((a) => a.sdp)")
private external fun jsCreateAnswer(pc: JsRtcPeerConnection): Promise<JsString>

@JsFun("(pc, type, sdp) => pc.setLocalDescription(type === 'rollback' ? { type } : { type, sdp })")
private external fun jsSetLocalDescription(
    pc: JsRtcPeerConnection,
    type: JsString,
    sdp: JsString,
): Promise<JsAny?>

@JsFun("(pc, type, sdp) => pc.setRemoteDescription({ type, sdp })")
private external fun jsSetRemoteDescription(
    pc: JsRtcPeerConnection,
    type: JsString,
    sdp: JsString,
): Promise<JsAny?>

@JsFun("(pc, cand) => pc.addIceCandidate({ candidate: cand, sdpMLineIndex: 0 })")
private external fun jsAddIceCandidate(
    pc: JsRtcPeerConnection,
    cand: JsString,
): Promise<JsAny?>

@JsFun("(pc) => { pc.close(); }")
private external fun jsCloseRtcPeerConnection(pc: JsRtcPeerConnection)

@JsFun("(dc) => { dc.binaryType = 'arraybuffer'; }")
private external fun jsDataChannelSetArrayBuffer(dc: JsRtcDataChannel)

@JsFun("(dc) => (dc.id == null ? -1 : dc.id)")
private external fun jsDataChannelId(dc: JsRtcDataChannel): Int

@JsFun("(dc) => dc.readyState")
private external fun jsDataChannelReadyState(dc: JsRtcDataChannel): JsString

@JsFun("(dc, cb) => { dc.onopen = () => cb(); }")
private external fun jsDataChannelOnOpen(
    dc: JsRtcDataChannel,
    cb: () -> Unit,
)

@JsFun("(dc, cb) => { dc.onclose = () => cb(); }")
private external fun jsDataChannelOnClose(
    dc: JsRtcDataChannel,
    cb: () -> Unit,
)

// Deliver every message as lowercase hex: a string message is UTF-8 encoded, an ArrayBuffer read straight.
@JsFun(
    """(dc, cb) => {
        dc.onmessage = (e) => {
            const d = e.data;
            const bytes = (typeof d === 'string') ? new TextEncoder().encode(d) : new Uint8Array(d);
            let s = '';
            for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
            cb(s);
        };
    }""",
)
private external fun jsDataChannelOnMessageHex(
    dc: JsRtcDataChannel,
    cb: (JsString) -> Unit,
)

@JsFun(
    """(dc, hex) => {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        dc.send(bytes);
    }""",
)
private external fun jsDataChannelSend(
    dc: JsRtcDataChannel,
    hex: JsString,
)

@JsFun("(dc) => { dc.close(); }")
private external fun jsDataChannelClose(dc: JsRtcDataChannel)
