package com.ditchoom.webrtc.sctp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SctpTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-sctp", Sctp.MODULE)
    }

    @Test
    fun streamIdEnforcesU16Range() {
        assertFailsWith<IllegalArgumentException> { StreamId(70_000) }
    }
}
