package com.ditchoom.webrtc.dtls

import kotlin.test.Test
import kotlin.test.assertEquals

class DtlsTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-dtls", Dtls.MODULE)
    }

    @Test
    fun dtlsRoleIsExhaustive() {
        assertEquals(2, DtlsRole.entries.size)
    }
}
