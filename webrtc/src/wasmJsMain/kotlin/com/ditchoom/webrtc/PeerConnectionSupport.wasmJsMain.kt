package com.ditchoom.webrtc

import kotlinx.coroutines.CoroutineScope

/**
 * The browser [PeerConnectionSupport] (wasmJs). wasmJs is a browser target where — like js — we **wrap,
 * not reimplement** (RFC §1.1): there is no real-UDP binder on wasm (socket-udp has no wasm target), so a
 * [NativePeerConnection] cannot run here and delegation to the browser `RTCPeerConnection` is the only
 * path.
 *
 * The delegation itself is the js one (`PeerConnectionSupport.jsMain.kt`, Karma-tested against a real
 * in-browser `RTCPeerConnection` loopback). The wasmJs mapping is the same surface expressed through
 * `external interface` + `JsAny` instead of js `dynamic`; it is the **one remaining W6 follow-up**, so
 * this actual compiles and reports the intended [PeerConnectionKind.BrowserDelegated] while
 * [PeerConnectionSupport.createDelegated] fails fast with that pointer rather than pretending to work.
 */
public actual fun peerConnectionSupport(): PeerConnectionSupport = WasmJsBrowserSupport

private object WasmJsBrowserSupport : PeerConnectionSupport {
    override val kind: PeerConnectionKind get() = PeerConnectionKind.BrowserDelegated

    override fun createDelegated(
        scope: CoroutineScope,
        iceServers: List<String>,
    ): RtcPeerConnection =
        throw NotImplementedError(
            "wasmJs RTCPeerConnection delegation is the remaining W6 follow-up — the js browser delegation " +
                "(Karma-tested) is the reference; the wasmJs external-interface mapping is pending.",
        )
}
