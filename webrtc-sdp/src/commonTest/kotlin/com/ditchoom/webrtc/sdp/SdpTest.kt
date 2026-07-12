package com.ditchoom.webrtc.sdp

import kotlin.test.Test
import kotlin.test.assertEquals

class SdpTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-sdp", Sdp.MODULE)
    }
}
