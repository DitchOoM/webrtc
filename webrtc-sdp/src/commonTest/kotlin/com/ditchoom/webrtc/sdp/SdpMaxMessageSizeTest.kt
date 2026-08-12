package com.ditchoom.webrtc.sdp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * `a=max-message-size` (RFC 8841 §6 / RFC 8831 §6.6) at the codec layer: the typed four-way read, the
 * value class's construction invariant, and the emit side it must round-trip with.
 *
 * The point of the type is that the `Long?` it supersedes answers four questions with two values, and
 * **inverts the most dangerous one**: `0` on the wire is RFC 8841 §6's *no limit*, the largest thing the
 * attribute can say, spelled with the smallest number a ceiling comparison can hold. So the fixtures
 * that matter most here are the negative ones — zero is not a ceiling, absent is not malformed, and a
 * value read out of the wrong media section is a plausible number rather than an obvious failure.
 */
class SdpMaxMessageSizeTest {
    private fun sectionsOf(text: String): List<MediaDescription> =
        assertIs<SdpParseResult.Success>(SessionDescription.parseText(text)).description.mediaDescriptions

    /** A one-data-channel-section document carrying [attributeLines] verbatim after `a=sctp-port`. */
    private fun dataChannelSdp(vararg attributeLines: String): MediaDescription =
        sectionsOf(
            SdpTestVectors.crlf(
                "v=0",
                "o=- 42 0 IN IP4 127.0.0.1",
                "s=-",
                "t=0 0",
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                "a=mid:0",
                "a=sctp-port:5000",
                *attributeLines,
            ),
        ).single()

    // ---- the four cases ------------------------------------------------------------------------------

    @Test
    fun aStatedCeilingReadsAsBytesAndRoundTripsThroughTheWriter() {
        // The writer (MediaSectionBuilder.maxMessageSize) and this reader are the two halves of one
        // attribute; a fixture that only parsed hand-written text would not hold them together.
        for (bytes in listOf(1L, 1024L, 262_144L, 1_073_741_823L, Long.MAX_VALUE)) {
            val built =
                SessionDescriptionBuilder()
                    .version()
                    .origin(Origin("-", "42", "0", "IN", "IP4", "127.0.0.1"))
                    .sessionName()
                    .timing()
                    .media("${MediaLine.APPLICATION_MEDIA} 9 ${Sdp.PROTO_UDP_DTLS_SCTP} ${Sdp.DATA_CHANNEL_FMT}") {
                        maxMessageSize(bytes)
                    }.build()
            assertEquals(MaxMessageSizeAttribute.Bytes(bytes), built.mediaDescriptions.single().maxMessageSizeAttribute())
            // …and again after a full text round trip, which is what a peer actually hands us.
            val reparsed = sectionsOf(built.toText()).single()
            assertEquals(MaxMessageSizeAttribute.Bytes(bytes), reparsed.maxMessageSizeAttribute())
        }
    }

    @Test
    fun theInteropVectorsReadAsTheCeilingsTheyState() {
        // Chrome states 256 KiB, Firefox states 2^30-1, Pion states nothing at all — and "nothing at all"
        // is a case, not a failure. This is the corpus the L2/L3 lanes actually meet.
        val chrome = sectionsOf(SdpTestVectors.chromeDataChannelOffer).single()
        assertEquals(MaxMessageSizeAttribute.Bytes(262_144), chrome.maxMessageSizeAttribute())
        val firefox = sectionsOf(SdpTestVectors.firefoxDataChannelOffer).single()
        assertEquals(MaxMessageSizeAttribute.Bytes(1_073_741_823), firefox.maxMessageSizeAttribute())
        val pion = sectionsOf(SdpTestVectors.pionDataChannelAnswer).single()
        assertEquals(MaxMessageSizeAttribute.Absent, pion.maxMessageSizeAttribute())
    }

    @Test
    fun aSectionThatSaysNothingIsAbsentRatherThanZeroOrMalformed() {
        // RFC 8831 §6.6 gives silence a defined reading (assume 64 KiB) — but the codec reports the
        // silence and lets the transport apply the default, so the two peers stay distinguishable.
        val silent = dataChannelSdp()
        assertEquals(MaxMessageSizeAttribute.Absent, silent.maxMessageSizeAttribute())
        assertNotEquals<MaxMessageSizeAttribute>(MaxMessageSizeAttribute.Unlimited, silent.maxMessageSizeAttribute())
        assertNotEquals<MaxMessageSizeAttribute>(MaxMessageSizeAttribute.Malformed(""), silent.maxMessageSizeAttribute())
    }

    @Test
    fun zeroIsUnlimitedRatherThanACeilingOfZero() {
        // RFC 8841 §6: "a value of zero indicates the endpoint can handle messages of any size". Reading
        // it as a number makes it the tightest ceiling expressible, which would refuse every message
        // including the empty one — the inversion this type exists to make unrepresentable.
        assertEquals(MaxMessageSizeAttribute.Unlimited, dataChannelSdp("a=max-message-size:0").maxMessageSizeAttribute())
        // Leading zeros are still DIGITs, so they are still the same wire value.
        assertEquals(MaxMessageSizeAttribute.Unlimited, dataChannelSdp("a=max-message-size:000").maxMessageSizeAttribute())
    }

    @Test
    fun aCeilingOfZeroIsUnconstructible() {
        // The other half of the above: no code path anywhere can build the value that would mean
        // "accepts nothing", so the reader cannot produce it by accident and neither can a consumer.
        assertFailsWith<IllegalArgumentException> { MaxMessageSizeAttribute.Bytes(0) }
        assertFailsWith<IllegalArgumentException> { MaxMessageSizeAttribute.Bytes(-1) }
        assertEquals(1L, MaxMessageSizeAttribute.Bytes(1).value, "one byte is a legal, if useless, ceiling")
    }

    @Test
    fun everyShapeOfBrokenValueIsATypedRejectCarryingItsText() {
        // Not a throw (T0), and critically not Absent — a peer that said something unreadable must not be
        // promoted into a peer that said nothing, because those get different treatment upstream.
        val broken =
            listOf(
                "not-a-number",
                "-1", // the grammar is a digit string; a sign is not one, and a negative ceiling is nonsense
                "+1024",
                "1024.5",
                " 1024",
                "1024 ",
                "0x400",
                "1_024",
                "٤٢", // non-ASCII digits: Char.isDigit() would accept these, the RFC's DIGIT does not
                "18446744073709551616", // 2^64: well-formed per the grammar, past what a Long can state
            )
        for (value in broken) {
            val read = dataChannelSdp("a=max-message-size:$value").maxMessageSizeAttribute()
            assertEquals(MaxMessageSizeAttribute.Malformed(value), read, "'$value' must be a typed reject")
        }
    }

    @Test
    fun aValuelessFlagLineIsMalformedNotAbsent() {
        // `a=max-message-size` with no `:` at all — the attribute is declared and says nothing.
        assertEquals(
            MaxMessageSizeAttribute.Malformed(""),
            dataChannelSdp("a=max-message-size").maxMessageSizeAttribute(),
        )
        // …and with a colon and an empty value region, which is a different line and the same answer.
        assertEquals(
            MaxMessageSizeAttribute.Malformed(""),
            dataChannelSdp("a=max-message-size:").maxMessageSizeAttribute(),
        )
    }

    @Test
    fun theFirstOfSeveralLinesWins() {
        // Consistent with every other reader here (firstAttributeValue), and stated so that a peer
        // repeating the attribute has one defined reading rather than a positional accident.
        val repeated = dataChannelSdp("a=max-message-size:1024", "a=max-message-size:2048")
        assertEquals(MaxMessageSizeAttribute.Bytes(1024), repeated.maxMessageSizeAttribute())
    }

    // ---- the wrong-section hazard --------------------------------------------------------------------

    @Test
    fun theCeilingBelongsToTheDataChannelSectionNotToTheFirstOne() {
        // A Phase-2 description whose FIRST m= section is audio. `mediaDescriptions.firstOrNull()` — the
        // shape the existing remote-description ingest uses — reads a real, plausible number out of the
        // wrong section, so the failure is a wrong ceiling rather than a visible miss. Unlike ice-ufrag
        // or setup there is no session-level fallback to rescue it: RFC 8841 §6 is media-level only, and
        // this attribute describes one SCTP association.
        val text =
            SdpTestVectors.crlf(
                "v=0",
                "o=- 42 0 IN IP4 127.0.0.1",
                "s=-",
                "t=0 0",
                "a=group:BUNDLE 0 1",
                "m=audio 9 UDP/TLS/RTP/SAVPF 111",
                "c=IN IP4 0.0.0.0",
                "a=mid:0",
                "a=max-message-size:1024",
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                "c=IN IP4 0.0.0.0",
                "a=mid:1",
                "a=sctp-port:5000",
                "a=max-message-size:262144",
            )
        val sections = sectionsOf(text)
        assertEquals(2, sections.size)

        val firstSection = sections.first()
        assertTrue(firstSection.mediaLine()?.isDataChannel == false, "the first section is not the data channel")
        assertEquals(
            MaxMessageSizeAttribute.Bytes(1024),
            firstSection.maxMessageSizeAttribute(),
            "taking the first section yields a plausible WRONG ceiling, which is why the caller must select",
        )

        val dataChannel = sections.single { it.mediaLine()?.isDataChannel == true }
        assertEquals(MaxMessageSizeAttribute.Bytes(262_144), dataChannel.maxMessageSizeAttribute())
        assertNotEquals(firstSection.maxMessageSizeAttribute(), dataChannel.maxMessageSizeAttribute())
    }

    @Test
    fun anAudioFirstDescriptionWhoseDataChannelSaysNothingStillReadsAbsent() {
        // The same hazard in its quieter form: the audio section carries the only such line in the
        // document, so a first-section reader invents a ceiling for an association that stated none.
        val text =
            SdpTestVectors.crlf(
                "v=0",
                "o=- 42 0 IN IP4 127.0.0.1",
                "s=-",
                "t=0 0",
                "m=audio 9 UDP/TLS/RTP/SAVPF 111",
                "a=mid:0",
                "a=max-message-size:1024",
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                "a=mid:1",
                "a=sctp-port:5000",
            )
        val sections = sectionsOf(text)
        assertEquals(MaxMessageSizeAttribute.Bytes(1024), sections.first().maxMessageSizeAttribute())
        val dataChannel = sections.single { it.mediaLine()?.isDataChannel == true }
        assertEquals(MaxMessageSizeAttribute.Absent, dataChannel.maxMessageSizeAttribute())
    }

    // ---- the superseded reader -----------------------------------------------------------------------

    @Test
    @Suppress("DEPRECATION")
    fun theSupersededReaderStillAnswersExactlyAsItAlwaysDid() {
        // It has a production caller (the interop endpoint) that a later step migrates, so "deprecated"
        // must not mean "changed". This pins the old behaviour AND shows the collapse that motivates the
        // new type: three genuinely different descriptions, two indistinguishable answers.
        assertEquals(262_144L, dataChannelSdp("a=max-message-size:262144").maxMessageSize())
        assertEquals(0L, dataChannelSdp("a=max-message-size:0").maxMessageSize(), "no-limit, spelled as a ceiling")
        assertEquals(null, dataChannelSdp().maxMessageSize(), "absent")
        assertEquals(null, dataChannelSdp("a=max-message-size:nonsense").maxMessageSize(), "…and malformed, identically")
        // The same four descriptions, told apart by the new reader.
        assertEquals(MaxMessageSizeAttribute.Bytes(262_144), dataChannelSdp("a=max-message-size:262144").maxMessageSizeAttribute())
        assertEquals(MaxMessageSizeAttribute.Unlimited, dataChannelSdp("a=max-message-size:0").maxMessageSizeAttribute())
        assertEquals(MaxMessageSizeAttribute.Absent, dataChannelSdp().maxMessageSizeAttribute())
        assertEquals(
            MaxMessageSizeAttribute.Malformed("nonsense"),
            dataChannelSdp("a=max-message-size:nonsense").maxMessageSizeAttribute(),
        )
    }

    @Test
    fun theReaderIsTotalOverTheMalformedCorpusAndOverArbitraryValues() {
        // T0: every reachable operation on a parsed description is crash-free on hostile content. The
        // reader is reached from the same place `sctpPort()` is, so it joins the same floor.
        val hostile =
            listOf(
                "",
                ":",
                "::",
                "9".repeat(400),
                " ",
                "-",
                "0 0",
                "NaN",
                "Infinity",
            )
        for (value in hostile) {
            val read = dataChannelSdp("a=max-message-size:$value").maxMessageSizeAttribute()
            assertIs<MaxMessageSizeAttribute.Malformed>(read, "'$value'")
        }
    }
}
