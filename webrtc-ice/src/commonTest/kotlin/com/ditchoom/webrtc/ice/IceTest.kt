package com.ditchoom.webrtc.ice

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IceTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-ice", Ice.MODULE)
    }

    @Test
    fun failureReasonIsTyped() {
        val reason: IceFailureReason = IceFailureReason.AllPairsFailed(pairsTried = 3)
        assertTrue(reason is IceFailureReason.AllPairsFailed)
    }
}
