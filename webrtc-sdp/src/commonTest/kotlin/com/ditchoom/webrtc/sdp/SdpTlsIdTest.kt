package com.ditchoom.webrtc.sdp

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `a=tls-id` (RFC 8842 §5.3/§5.5) at the codec layer: the value class, the typed three-way read, and the
 * emit side.
 *
 * The property that matters most here is the **negative** one. The attribute is optional, and no peer in
 * this stack's interop matrix (Chrome, Firefox, WebKit, Pion, werift) emits one — so a description without
 * it must read as [TlsIdAttribute.Absent], a distinct answer from "present but unreadable", and a
 * [DataChannelParameters] without one must emit byte-identical SDP to what it emitted before the attribute
 * existed. Those two are what keep the foreign interop lanes on the pre-#72 behaviour.
 */
class SdpTlsIdTest {
    private val wellFormed = "abcdefghij0123456789"

    private fun params(tlsId: TlsId?) =
        DataChannelParameters(
            iceUfrag = "ufrag",
            icePwd = "0123456789abcdef0123456789abcdef",
            fingerprint =
                Fingerprint(
                    "sha-256",
                    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                ),
            setup = SetupRole.ActPass,
            tlsId = tlsId,
        )

    // ---- the value class -----------------------------------------------------------------------------

    @Test
    fun theGrammarIsTheConstructionInvariant() {
        // RFC 8842 §5.3: tls-id-value = 20*(token-char). Exactly 20 is legal; 19 is not.
        assertEquals(20, TlsId.MIN_LENGTH)
        assertEquals(wellFormed, TlsId(wellFormed).value)
        assertFailsWith<IllegalArgumentException> { TlsId(wellFormed.substring(1)) }
        assertFailsWith<IllegalArgumentException> { TlsId("has a space in it 12345") }
    }

    @Test
    fun fromValueIsTheTotalParseAndRejectsWhatTheConstructorRefuses() {
        // The untrusted-input door: never a throw, null on anything the grammar refuses (T0 discipline).
        assertEquals(TlsId(wellFormed), TlsId.fromValue(wellFormed))
        assertNull(TlsId.fromValue(""), "empty")
        assertNull(TlsId.fromValue("tooshort"), "shorter than 20")
        assertNull(TlsId.fromValue("has a space in it 12345"), "space is not a token-char")
        assertNull(TlsId.fromValue("colons:are:not:token:chars"), "':' is not a token-char")
        assertNull(TlsId.fromValue("slashes/are/not/token/chars"), "'/' is not a token-char")
        // …and the whole of RFC 4566's token-char set really is accepted, not just the alphanumerics.
        val everyShapeOfTokenChar = "!#\$%&'*+-.^_`{|}~ABCyz09"
        assertEquals(everyShapeOfTokenChar, TlsId.fromValue(everyShapeOfTokenChar)?.value)
    }

    @Test
    fun generatedIdsAreWellFormedDistinctAndReplayableFromASeed() {
        val id = TlsId.random(Random(7))
        assertTrue(id.value.length >= TlsId.MIN_LENGTH)
        assertEquals(id, TlsId.fromValue(id.value), "a generated id survives its own parser")
        // Directive #2: entropy is a seam, so the same seed replays the same id — and a different draw
        // from the same generator does not repeat it (144 bits over a 64-symbol alphabet).
        assertEquals(id, TlsId.random(Random(7)))
        val stream = Random(7)
        assertNotEquals(TlsId.random(stream), TlsId.random(stream))
    }

    // ---- the typed read ------------------------------------------------------------------------------

    @Test
    fun everyInteropVectorReadsAsAbsentRatherThanAsAFailure() {
        // The backward-compatibility floor for #72: nobody out there emits a=tls-id, and "nobody said
        // anything" must be its own answer — not a malformed reject, and not a value we could compare.
        for (vector in SdpTestVectors.all) {
            val parsed = assertIs<SdpParseResult.Success>(SessionDescription.parseText(vector)).description
            assertEquals(TlsIdAttribute.Absent, parsed.tlsId(), "session level")
            assertEquals(TlsIdAttribute.Absent, parsed.mediaDescriptions.single().tlsId(), "media level")
        }
    }

    @Test
    fun aWellFormedAttributeReadsAtEitherLevel() {
        // RFC 8842 §5.3 allows session or media level; the reader interprets whichever section it is asked.
        val text =
            SdpTestVectors.crlf(
                "v=0",
                "o=- 42 0 IN IP4 127.0.0.1",
                "s=-",
                "t=0 0",
                "a=tls-id:sessionLevel12345678",
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                "a=tls-id:$wellFormed",
            )
        val parsed = assertIs<SdpParseResult.Success>(SessionDescription.parseText(text)).description
        assertEquals(TlsIdAttribute.Present(TlsId("sessionLevel12345678")), parsed.tlsId())
        assertEquals(TlsIdAttribute.Present(TlsId(wellFormed)), parsed.mediaDescriptions.single().tlsId())
    }

    @Test
    fun aMalformedAttributeIsATypedRejectNotAThrowAndNotAnAbsence() {
        // Three shapes of broken, one answer — and critically NOT `Absent`, which would silently promote a
        // peer that said something unreadable into a peer that said nothing.
        for (bad in listOf("tooshort", "has spaces in the value", "colon:separated:value:here")) {
            val text =
                SdpTestVectors.crlf(
                    "v=0",
                    "o=- 42 0 IN IP4 127.0.0.1",
                    "s=-",
                    "t=0 0",
                    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                    "a=tls-id:$bad",
                )
            val parsed = assertIs<SdpParseResult.Success>(SessionDescription.parseText(text)).description
            val read = parsed.mediaDescriptions.single().tlsId()
            // The value carried is a diagnostic; the discriminant is the type (directive #3). A ':' in the
            // text is consumed by the attribute grammar itself, so only the tail survives to be rejected.
            assertIs<TlsIdAttribute.Malformed>(read, "'$bad' must be a typed reject")
            assertTrue(bad.endsWith(read.value), "the raw text rides along for diagnosis: $read")
        }
    }

    @Test
    fun aValuelessFlagLineIsMalformedNotAbsent() {
        // `a=tls-id` with no value at all: the peer declared the attribute and said nothing in it.
        val text =
            SdpTestVectors.crlf(
                "v=0",
                "o=- 42 0 IN IP4 127.0.0.1",
                "s=-",
                "t=0 0",
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                "a=tls-id",
            )
        val parsed = assertIs<SdpParseResult.Success>(SessionDescription.parseText(text)).description
        assertEquals(TlsIdAttribute.Malformed(""), parsed.mediaDescriptions.single().tlsId())
    }

    // ---- the emit side -------------------------------------------------------------------------------

    @Test
    fun anOfferCarriesTheTlsIdBesideTheOtherDtlsParametersAndRoundTrips() {
        val id = TlsId.random(Random(3))
        val offer = dataChannelDescription(params(id), sessionId = "42", sessionVersion = 0)
        val text = offer.toText()
        assertTrue(text.contains("${Sdp.CRLF}a=tls-id:${id.value}${Sdp.CRLF}"), "emitted as its own line: $text")
        assertTrue(
            text.indexOf("a=setup:") < text.indexOf("a=tls-id:"),
            "beside the DTLS parameters it qualifies, at media level",
        )
        val reparsed = assertIs<SdpParseResult.Success>(SessionDescription.parseText(text)).description
        assertEquals(TlsIdAttribute.Present(id), reparsed.mediaDescriptions.single().tlsId())
        assertEquals(text, reparsed.toText(), "and the document still round-trips byte-for-byte")
    }

    @Test
    fun omittingTheTlsIdEmitsExactlyTheBytesItAlwaysDid() {
        // The other half of the compatibility floor: an existing caller that never heard of tls-id gets
        // the pre-#72 document, line for line — the attribute is not "empty", it is not there.
        val without = dataChannelDescription(params(null), sessionId = "42", sessionVersion = 0).toText()
        assertTrue(!without.contains("tls-id"), "no attribute at all: $without")
        val with = dataChannelDescription(params(TlsId(wellFormed)), sessionId = "42", sessionVersion = 0).toText()
        assertEquals(
            without,
            with.replace("a=tls-id:$wellFormed${Sdp.CRLF}", ""),
            "the tls-id line is the ONLY difference between the two documents",
        )
    }
}
