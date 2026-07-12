package com.ditchoom.webrtc

import kotlin.jvm.JvmInline

/**
 * W6 placeholder — the consumer API root (`PeerConnection`, JSEP, `DataChannel`). Nothing here is
 * API-final; it exists so the umbrella module builds and publishes a 0.0.x across every target.
 */
public object WebRtc {
    public const val MODULE: String = "webrtc"
}

/** A data-channel identifier, wrapped so a channel id is never passed where some other `Int` is. */
@JvmInline
public value class DataChannelId(
    public val value: Int,
)

/**
 * Peer-connection lifecycle as a sealed hierarchy where each state carries exactly the data that is
 * valid in it — and nothing that isn't. There is no `connected: Boolean` + nullable
 * `failureReason` soup that could encode "connected AND failed"; the illegal states are simply
 * unrepresentable. (Standing directive: no impossible states in the type system.)
 */
public sealed interface PeerConnectionState {
    public object New : PeerConnectionState

    public object Connecting : PeerConnectionState

    public data class Connected(
        val selectedPairId: Long,
    ) : PeerConnectionState

    public data class Failed(
        val reason: String,
    ) : PeerConnectionState

    public object Closed : PeerConnectionState
}
