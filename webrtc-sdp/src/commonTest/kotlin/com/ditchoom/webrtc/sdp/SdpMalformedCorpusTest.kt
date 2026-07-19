package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * T0 floor (RFC §7): a hostile or malformed datagram must yield a **typed** [SdpParseResult.Reject],
 * never a throw-through or a crash. The committed cases pin specific reject reasons; the seeded
 * property loops assert the stronger invariant — parse is total (Success or Reject) over arbitrary
 * bytes and over mutations of valid vectors, on every platform. Semantic breakage of a single line
 * (a malformed `o=`/`m=`/`a=fingerprint`) is intentionally NOT a reject — it parses and the typed
 * reader is null — so those cases live in [totalityStillHoldsForSemanticGarbage].
 */
class SdpMalformedCorpusTest {
    private fun reject(text: String): SdpRejectReason {
        val r = SessionDescription.parse(sdpBufferOf(text))
        assertIs<SdpParseResult.Reject>(r, "expected Reject for <<<$text>>>, got $r")
        return r.reason
    }

    @Test
    fun emptyDatagramIsRejected() {
        // A zero-length datagram: allocate 1 byte but set the limit to 0 so remaining()==0.
        val buf = BufferFactory.Default.allocate(1, ByteOrder.BIG_ENDIAN)
        buf.resetForRead()
        buf.setLimit(0)
        assertIs<SdpRejectReason.Empty>((SessionDescription.parse(buf) as SdpParseResult.Reject).reason)
    }

    @Test
    fun emptyStringIsRejected() {
        assertIs<SdpRejectReason.Empty>((SessionDescription.parseText("") as SdpParseResult.Reject).reason)
    }

    @Test
    fun firstLineNotVersionIsMissingVersion() {
        assertIs<SdpRejectReason.MissingVersion>(reject(SdpTestVectors.crlf("o=- 1 1 IN IP4 0.0.0.0", "s=-")))
    }

    @Test
    fun unsupportedVersionIsRejected() {
        val r = reject(SdpTestVectors.crlf("v=1", "s=-"))
        assertIs<SdpRejectReason.UnsupportedVersion>(r)
        assertTrue(r.version == "1")
    }

    @Test
    fun lineWithoutEqualsIsMalformed() {
        val r = reject(SdpTestVectors.crlf("v=0", "this-is-not-a-line", "s=-"))
        assertIs<SdpRejectReason.MalformedLine>(r)
        assertTrue(r.lineIndex == 1)
    }

    @Test
    fun multiCharTypeIsMalformed() {
        // "ab=x" — the type must be a single character followed by '=' (RFC 8866 §5).
        assertIs<SdpRejectReason.MalformedLine>(reject(SdpTestVectors.crlf("v=0", "ab=x")))
    }

    @Test
    fun blankInteriorLineIsMalformed() {
        // A blank line has no '<type>=' — malformed, not silently skipped.
        assertIs<SdpRejectReason.MalformedLine>(reject("v=0\r\n\r\ns=-\r\n"))
    }

    @Test
    fun emptyValueLineIsAccepted() {
        // "a=" is valid: a property attribute may be present with an empty value region.
        val r = SessionDescription.parse(sdpBufferOf(SdpTestVectors.crlf("v=0", "s=-", "a=")))
        assertIs<SdpParseResult.Success>(r)
    }

    @Test
    fun parseIsTotalOverArbitraryBytes() {
        // The core T0 invariant: no input makes parse throw. Seeded, so a failure reproduces. Fast
        // cross-platform smoke (kept small so it stays well under the JS-node 2s Mocha budget — 20k
        // flaked there at ~1.9s). Deep coverage-guided fuzzing is :webrtc-sdp:sdpCodecFuzz.
        val random = Random(0x5DDF00D)
        repeat(2_000) {
            val n = random.nextInt(0, 256)
            val buf = BufferFactory.Default.allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
            repeat(n) { buf.writeByte(random.nextInt().toByte()) }
            buf.resetForRead()
            buf.setLimit(n)
            val result = SessionDescription.parse(buf)
            assertTrue(result is SdpParseResult.Success || result is SdpParseResult.Reject)
        }
    }

    @Test
    fun parseIsTotalOverAsciiLineNoise() {
        // Bias toward text so we exercise the line walk, not just the header reject. Fast smoke count
        // (see parseIsTotalOverArbitraryBytes — 20k flaked JS-node at the 2s Mocha budget).
        val random = Random(0xBAD5EED)
        val alphabet = "v=o0s-t a:mIPNc/.\r\n1234;".toCharArray()
        repeat(2_000) {
            val len = random.nextInt(0, 200)
            val sb = StringBuilder(len)
            repeat(len) { sb.append(alphabet[random.nextInt(alphabet.size)]) }
            val text = sb.toString()
            val result = SessionDescription.parseText(text)
            assertTrue(result is SdpParseResult.Success || result is SdpParseResult.Reject)
            // Any Success must re-encode without throwing.
            if (result is SdpParseResult.Success) result.description.encode()
        }
    }

    @Test
    fun everySingleLineDropOfAValidVectorStaysTotal() {
        for (vector in SdpTestVectors.all) {
            val lines = vector.removeSuffix(Sdp.CRLF).split(Sdp.CRLF)
            for (drop in lines.indices) {
                val mutated = lines.filterIndexed { i, _ -> i != drop }.joinToString(Sdp.CRLF, postfix = Sdp.CRLF)
                when (val r = SessionDescription.parseText(mutated)) {
                    is SdpParseResult.Success -> r.description.encode() // must not throw
                    is SdpParseResult.Reject -> {} // typed reject is fine
                }
            }
        }
    }

    @Test
    fun totalityStillHoldsForSemanticGarbage() {
        // A structurally valid document whose typed fields are broken still parses; readers are null,
        // never throwing (the RawAttribute discipline for text).
        val garbage =
            SdpTestVectors.crlf(
                "v=0",
                "o=only three fields",
                "s=-",
                "t=0 0",
                "m=application",
                "a=setup:bogus",
                "a=sctp-port:not-a-number",
                "a=fingerprint:incomplete",
                "a=mid:0",
            )
        val r = SessionDescription.parse(sdpBufferOf(garbage))
        assertIs<SdpParseResult.Success>(r)
        val sdp = r.description
        assertTrue(sdp.origin() == null, "3-field o= is a typed miss")
        val m = sdp.mediaDescriptions.single()
        assertTrue(m.mediaLine() == null, "1-field m= is a typed miss")
        assertTrue(m.setup() == null, "unknown setup token is a typed miss")
        assertTrue(m.sctpPort() == null, "non-numeric sctp-port is a typed miss")
        assertTrue(m.fingerprints().isEmpty(), "single-field fingerprint is a typed miss")
        assertTrue(m.mid() == Mid("0"))
    }

    @Test
    fun rejectReasonEqualityIsTyped() {
        assertTrue(SdpRejectReason.Empty == SdpRejectReason.Empty)
        assertTrue(SdpRejectReason.MissingVersion == SdpRejectReason.MissingVersion)
    }
}
