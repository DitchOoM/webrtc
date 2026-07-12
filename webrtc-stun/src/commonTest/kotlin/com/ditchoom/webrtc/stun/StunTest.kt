package com.ditchoom.webrtc.stun

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class StunTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-stun", Stun.MODULE)
    }

    @Test
    fun transactionIdRejectsWrongWidth() {
        assertFailsWith<IllegalArgumentException> { TransactionId("abcd") }
    }

    @Test
    fun stunClassIsExhaustive() {
        assertEquals(4, StunClass.entries.size)
    }
}
