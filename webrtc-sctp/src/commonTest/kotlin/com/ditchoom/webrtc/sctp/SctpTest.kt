package com.ditchoom.webrtc.sctp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SctpTest {
    @Test
    fun moduleMarkerIsWired() {
        assertEquals("webrtc-sctp", Sctp.MODULE)
    }

    @Test
    fun streamIdEnforcesU16Range() {
        assertFailsWith<IllegalArgumentException> { StreamId(70_000) }
    }

    @Test
    fun identifiersAreDistinctTypesOverTheSameScalar() {
        // Tsn and VerificationTag both wrap UInt but are not interchangeable — a compile-time guarantee;
        // here we just assert value semantics hold.
        assertEquals(Tsn(5u), Tsn(5u))
        assertEquals(VerificationTag(5u), VerificationTag(5u))
    }

    @Test
    fun tsnSerialArithmeticWrapsAtTheBoundary() {
        assertTrue(Tsn(0xFFFFFFFFu).sackPrecedes(Tsn(0u)), "0xFFFFFFFF precedes 0 across the wrap")
        assertTrue(!Tsn(0u).sackPrecedes(Tsn(0xFFFFFFFFu)))
        assertEquals(Tsn(0u), Tsn(0xFFFFFFFFu).next())
        assertTrue(Tsn(1u).sackPrecedes(Tsn(2u)))
    }

    @Test
    fun payloadProtocolIdConstantsMatchIana() {
        assertEquals(PayloadProtocolId(50u), PayloadProtocolId.WebRtcDcep)
        assertEquals(PayloadProtocolId(53u), PayloadProtocolId.WebRtcBinary)
    }
}
