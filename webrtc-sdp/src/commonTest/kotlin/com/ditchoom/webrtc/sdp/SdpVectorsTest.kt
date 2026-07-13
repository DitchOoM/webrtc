package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.Charset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * T0 interop-grade vectors (RFC §7 / TESTING.md §3): the real-world data-channel offers/answers must
 * parse to the expected typed fields and round-trip byte-for-byte through parse→encode. SDP has no RFC
 * sample-vector suite, so these captured browser/Pion descriptions are the corpus (TESTING.md §3).
 */
class SdpVectorsTest {
    private fun parse(text: String): SessionDescription {
        val r = SessionDescription.parse(sdpBufferOf(text))
        assertIs<SdpParseResult.Success>(r, "vector must parse: got $r")
        return r.description
    }

    @Test
    fun everyVectorRoundTripsByteForByte() {
        for (text in SdpTestVectors.all) {
            val decoded = parse(text)
            // toText round-trip
            assertEquals(text, decoded.toText(), "toText must reproduce the canonical CRLF document")
            // encode() to a buffer round-trip (the datagram path)
            val encoded = decoded.encode()
            val out: CharSequence = encoded.readString(encoded.remaining(), Charset.UTF8)
            assertEquals(text, out.toString(), "encode() must reproduce the datagram")
        }
    }

    @Test
    fun everyVectorReparsesIdentically() {
        // parse(encode(parse(x))) == parse(x): the model is a fixed point.
        for (text in SdpTestVectors.all) {
            val once = parse(text)
            val twice = parse(once.toText())
            assertEquals(once.toText(), twice.toText())
            assertEquals(once.mediaDescriptions.size, twice.mediaDescriptions.size)
        }
    }

    @Test
    fun chromeOfferTypedFields() {
        val sdp = parse(SdpTestVectors.chromeDataChannelOffer)
        assertEquals("4611731400430051336", sdp.origin()?.sessionId)
        assertEquals("2", sdp.origin()?.sessionVersion)
        assertEquals(listOf(listOf(Mid("0"))), sdp.bundleGroups())
        assertEquals(1, sdp.mediaDescriptions.size)

        val m = sdp.mediaDescriptions[0]
        val mediaLine = assertNotNull(m.mediaLine())
        assertTrue(mediaLine.isDataChannel)
        assertEquals(MediaLine.APPLICATION_MEDIA, mediaLine.media)
        assertEquals("4ZcD", m.iceUfrag())
        assertEquals("2/1muCWoOi3uLifh0NuRHlB5", m.icePwd())
        assertEquals(SetupRole.ActPass, m.setup())
        assertEquals(Mid("0"), m.mid())
        assertEquals(5000, m.sctpPort())
        assertEquals(262144L, m.maxMessageSize())
        val fp = m.fingerprints().single()
        assertEquals("sha-256", fp.hashFunction)
        assertTrue(fp.value.startsWith("4A:AD:B9"))
    }

    @Test
    fun firefoxOfferMixesSessionAndMediaLevelParameters() {
        val sdp = parse(SdpTestVectors.firefoxDataChannelOffer)
        // Fingerprint + ice-options are session-level here; ice-ufrag/pwd/setup are media-level.
        assertEquals(1, sdp.fingerprints().size, "session-level fingerprint")
        val m = sdp.mediaDescriptions.single()
        assertEquals("6f2a1b3c", m.iceUfrag())
        assertEquals(SetupRole.ActPass, m.setup())
        assertEquals(1073741823L, m.maxMessageSize())
        assertEquals(1, m.candidates().size)
        assertTrue(m.hasEndOfCandidates())
        // A media section with no fingerprint of its own falls back to the session's (JSEP §5.2.1).
        assertTrue(m.fingerprints().isEmpty())
    }

    @Test
    fun pionAnswerResolvedActiveRole() {
        val sdp = parse(SdpTestVectors.pionDataChannelAnswer)
        val m = sdp.mediaDescriptions.single()
        assertEquals(SetupRole.Active, m.setup(), "answerer resolves actpass to active")
        assertEquals(Mid("0"), m.mid())
        assertEquals("aQwErTyU", m.iceUfrag())
        assertEquals(1, m.candidates().size)
        assertTrue(m.hasEndOfCandidates())
        assertEquals(1, sdp.fingerprints().size)
    }
}
