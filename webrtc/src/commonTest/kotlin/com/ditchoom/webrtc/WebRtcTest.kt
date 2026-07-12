package com.ditchoom.webrtc

import kotlin.test.Test
import kotlin.test.assertEquals

class WebRtcTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc", WebRtc.MODULE)
    }

    @Test
    fun stateTransitionsAreTyped() {
        val state: PeerConnectionState = PeerConnectionState.Connected(selectedPairId = 1L)
        val label =
            when (state) {
                is PeerConnectionState.New -> "new"
                is PeerConnectionState.Connecting -> "connecting"
                is PeerConnectionState.Connected -> "connected"
                is PeerConnectionState.Failed -> "failed"
                is PeerConnectionState.Closed -> "closed"
            }
        assertEquals("connected", label)
    }
}
