package com.ditchoom.webrtc.testsuite

import kotlin.test.Test
import kotlin.test.assertEquals

class WebRtcTestsuiteTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-testsuite", WebRtcTestsuite.MODULE)
    }
}
