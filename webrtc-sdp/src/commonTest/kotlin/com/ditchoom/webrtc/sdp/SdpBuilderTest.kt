package com.ditchoom.webrtc.sdp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The write side of the codec: [SessionDescriptionBuilder] emits exactly the lines added, in order,
 * and a built document parses back to the same typed fields (parse and build are inverses).
 */
class SdpBuilderTest {
    @Test
    fun buildsExpectedCanonicalText() {
        val text =
            SessionDescriptionBuilder()
                .version()
                .origin(Origin("-", "42", "0", "IN", "IP4", "127.0.0.1"))
                .sessionName()
                .timing()
                .bundle(listOf(Mid("0")))
                .media("application 9 UDP/DTLS/SCTP webrtc-datachannel") {
                    connection()
                    iceUfrag("uFrAg")
                    icePwd("pwd0123456789")
                    setup(SetupRole.ActPass)
                    mid(Mid("0"))
                    sctpPort(5000)
                    maxMessageSize(262144)
                }.build()
                .toText()

        val expected =
            SdpTestVectors.crlf(
                "v=0",
                "o=- 42 0 IN IP4 127.0.0.1",
                "s=-",
                "t=0 0",
                "a=group:BUNDLE 0",
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
                "c=IN IP4 0.0.0.0",
                "a=ice-ufrag:uFrAg",
                "a=ice-pwd:pwd0123456789",
                "a=setup:actpass",
                "a=mid:0",
                "a=sctp-port:5000",
                "a=max-message-size:262144",
            )
        assertEquals(expected, text)
    }

    @Test
    fun builtDocumentParsesToTheSameFields() {
        val built =
            SessionDescriptionBuilder()
                .version()
                .origin(Origin("-", "42", "7", "IN", "IP4", "127.0.0.1"))
                .sessionName()
                .timing()
                .media("application 9 UDP/DTLS/SCTP webrtc-datachannel") {
                    setup(SetupRole.Passive)
                    mid(Mid("data"))
                    fingerprint(Fingerprint("sha-256", "AA:BB"))
                }.build()

        val r = SessionDescription.parse(sdpBufferOf(built.toText()))
        assertIs<SdpParseResult.Success>(r)
        val sdp = r.description
        assertEquals("7", sdp.origin()?.sessionVersion)
        val m = sdp.mediaDescriptions.single()
        assertEquals(SetupRole.Passive, m.setup())
        assertEquals(Mid("data"), m.mid())
        assertEquals(Fingerprint("sha-256", "AA:BB"), m.fingerprints().single())
    }

    @Test
    fun propertyAttributeHasNoValue() {
        val line = SdpLine('a', "end-of-candidates")
        val attr = assertIs<Attribute>(line.attribute())
        assertEquals("end-of-candidates", attr.name)
        assertEquals(null, attr.value)
    }
}
