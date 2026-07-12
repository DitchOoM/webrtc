package com.ditchoom.webrtc.stun

import kotlin.test.Test
import kotlin.test.assertEquals

class StunTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-stun", Stun.MODULE)
    }

    @Test
    fun stunClassOrdinalsAreTheWireClassValues() {
        // StunMessageType relies on these ordinals being the on-wire 2-bit class values.
        assertEquals(0, StunClass.Request.ordinal)
        assertEquals(1, StunClass.Indication.ordinal)
        assertEquals(2, StunClass.SuccessResponse.ordinal)
        assertEquals(3, StunClass.ErrorResponse.ordinal)
    }
}
