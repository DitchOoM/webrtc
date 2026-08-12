package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.sctp.Tsn
import com.ditchoom.webrtc.sctp.VerificationTag
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * [StateCookie.SIZE_BYTES] must equal what the codec actually writes.
 *
 * The number is now asked of the generated codec rather than written down beside the fields, which
 * removes the drift this fixture originally existed to catch. What it cannot remove is the possibility
 * that `sizeHint` and `encode` disagree — a generator bug, or a field whose declared width is not the
 * width it serialises. That is the agreement worth asserting: not the constant against a literal (which
 * would only check that KSP equals itself), but the constant against the **bytes that came out**.
 *
 * Why it is mandatory rather than nice to have: a cookie is opaque to the peer and simply echoed back, so
 * a size that is too small truncates the encode and every COOKIE ECHO then fails the magic check and is
 * discarded under RFC 4960 §5.1.5 — *silently*, by design. The visible symptom is a handshake that times
 * out with nothing in the log. There is no typed error to catch it and no interop lane that would
 * localise it, so this fixture is the only thing standing between that change and a day of debugging.
 */
class StateCookieSizeTest {
    /**
     * Every field distinct and non-zero, so the round trip catches two bugs a zeroed cookie cannot: a
     * field pair written in the wrong order, and a field silently aliasing another's offset.
     */
    private val cookie =
        StateCookie(
            magic = StateCookie.MAGIC,
            peerTag = VerificationTag(0x11111111u),
            peerInitialTsn = Tsn(0x22222222u),
            peerRwnd = 0x33333333u,
            peerForwardTsn = true,
            peerReConfig = false,
            ourTag = VerificationTag(0x44444444u),
            ourInitialTsn = Tsn(0x55555555u),
            localTieTag = VerificationTag(0x66666666u),
            peerTieTag = VerificationTag(0x77777777u),
        )

    @Test
    fun the_declared_size_is_the_number_of_bytes_encode_writes() {
        // Deliberately over-allocated: if `encode` writes MORE than SIZE_BYTES, the write must land in
        // spare room and be caught by the assertion below rather than by an out-of-bounds throw, which
        // would report a buffer problem instead of the size disagreement that caused it.
        val buffer = BufferFactory.managed().allocate(StateCookie.SIZE_BYTES * 2, ByteOrder.BIG_ENDIAN)
        StateCookieCodec.encode(buffer, cookie, EncodeContext.Empty)
        assertEquals(
            StateCookie.SIZE_BYTES,
            buffer.position(),
            "SIZE_BYTES disagrees with the bytes the codec wrote — encodeCookie would truncate or over-read",
        )
    }

    @Test
    fun a_cookie_round_trips_through_exactly_that_many_bytes() {
        val buffer = BufferFactory.managed().allocate(StateCookie.SIZE_BYTES, ByteOrder.BIG_ENDIAN)
        StateCookieCodec.encode(buffer, cookie, EncodeContext.Empty)
        buffer.resetForRead()
        buffer.setLimit(StateCookie.SIZE_BYTES)

        val decoded = StateCookieCodec.decode(buffer, DecodeContext.Empty)
        assertEquals(cookie, decoded, "a cookie must survive the exact-size buffer encodeCookie hands the peer")
        assertEquals(0, buffer.remaining(), "the decode must consume the whole cookie, leaving nothing unread")
    }

    /**
     * The derivation's own premise: `sizeHint` ignores the value because every field is FixedSize. If a
     * variable-width field were ever added, the probe in the companion would answer for the probe alone
     * and every other cookie would be mis-sized — so assert the invariance rather than assume it.
     */
    @Test
    fun the_size_does_not_depend_on_the_cookie_it_is_asked_about() {
        val zeroed =
            StateCookie(
                magic = 0u,
                peerTag = VerificationTag(0u),
                peerInitialTsn = Tsn(0u),
                peerRwnd = 0u,
                peerForwardTsn = false,
                peerReConfig = false,
                ourTag = VerificationTag(0u),
                ourInitialTsn = Tsn(0u),
                localTieTag = VerificationTag(0u),
                peerTieTag = VerificationTag(0u),
            )
        assertEquals(
            StateCookieCodec.sizeHint(zeroed, EncodeContext.Empty),
            StateCookieCodec.sizeHint(cookie, EncodeContext.Empty),
            "sizeHint varies with the value, so the companion's single probe cannot speak for every cookie",
        )
        assertTrue(StateCookie.SIZE_BYTES > 0, "a derived size of zero would make every cookie empty and unrejectable")
    }
}
