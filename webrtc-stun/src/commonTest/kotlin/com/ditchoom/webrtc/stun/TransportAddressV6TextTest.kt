package com.ditchoom.webrtc.stun

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The IPv6 text boundary (RFC 5952 canonical [IpAddress.V6.toString] + the array-free
 * [IpAddress.V6.parse]) — the keystone every webrtc-ice v6 path renders and parses through. Proven
 * before any consumer relies on it (design note `docs/IPV6_DUAL_STACK_DESIGN.md`, step 1).
 */
class TransportAddressV6TextTest {
    @Test
    fun parsesLoopbackToZeroOne() {
        assertEquals(IpAddress.V6(0uL, 1uL), IpAddress.V6.parse("::1"))
    }

    @Test
    fun parsesAllZeroesToUnspecified() {
        assertEquals(IpAddress.V6(0uL, 0uL), IpAddress.V6.parse("::"))
    }

    @Test
    fun rendersRfc5769VectorAsPureHex() {
        // The RFC 5769 §2.2 IPv6 test-vector address, unbracketed, leading zeros suppressed.
        val addr = IpAddress.V6(0x20010db812345678uL, 0x0011223344556677uL)
        assertEquals("2001:db8:1234:5678:11:2233:4455:6677", addr.toString())
    }

    @Test
    fun compressesLeftmostLongestZeroRun() {
        assertEquals("2001:db8::1", IpAddress.V6.parse("2001:0db8:0000:0000:0000:0000:0000:0001")!!.toString())
    }

    @Test
    fun doesNotCompressALoneZeroHextet() {
        // RFC 5952 §4.2.2: a single zero group is written "0", never "::".
        assertEquals("2001:db8:0:1:1:1:1:1", IpAddress.V6.parse("2001:db8:0:1:1:1:1:1")!!.toString())
    }

    @Test
    fun compressesTheLongestZeroRun() {
        // Two zero runs (len 2 then len 3) → RFC 5952 §4.2.2 compresses the longer one.
        assertEquals("1:0:0:1::1", IpAddress.V6.parse("1:0:0:1:0:0:0:1")!!.toString())
    }

    @Test
    fun compressesLeftmostOfEqualLengthRuns() {
        // Two equal-length (len 2) zero runs → RFC 5952 §4.2.3 picks the leftmost.
        assertEquals("1::1:0:0:1:2", IpAddress.V6.parse("1:0:0:1:0:0:1:2")!!.toString())
    }

    @Test
    fun packsEmbeddedIpv4TailIntoLow() {
        assertEquals(IpAddress.V6(0uL, 0x0000ffff01020304uL), IpAddress.V6.parse("::ffff:1.2.3.4"))
    }

    @Test
    fun stripsZoneIdentifier() {
        assertEquals(IpAddress.V6.parse("fe80::1"), IpAddress.V6.parse("fe80::1%eth0"))
    }

    @Test
    fun packsHeadAndTailAroundCompression() {
        assertEquals(IpAddress.V6(0x20010db800000000uL, 1uL), IpAddress.V6.parse("2001:db8::1"))
    }

    @Test
    fun rendersFullFormWithNoCompression() {
        val addr = IpAddress.V6.parse("2001:db8:1:2:3:4:5:6")!!
        assertEquals("2001:db8:1:2:3:4:5:6", addr.toString())
    }

    @Test
    fun roundTripsCanonicalCorpus() {
        for (canonical in listOf("::", "::1", "2001:db8::1", "fe80::1", "2001:db8:1234:5678:11:2233:4455:6677", "1:0:0:1::1")) {
            assertEquals(canonical, IpAddress.V6.parse(canonical)!!.toString(), "round-trip of $canonical")
        }
    }

    @Test
    fun rejectsMalformedLiteralsAsTypedNull() {
        for (bad in listOf(
            "",
            "::1::2",
            "2001:db8:::1",
            "gggg::",
            "1:2:3:4:5:6:7:8:9",
            "[::1]",
            "2001:db8:0:0:0:0:0:0:0:1",
            ":1:2:3:4:5:6:7",
            "12345::",
        )) {
            assertNull(IpAddress.V6.parse(bad), "expected null for malformed literal: '$bad'")
        }
    }
}
