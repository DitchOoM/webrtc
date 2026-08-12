package com.ditchoom.webrtc.sdp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * [dataChannelSection] exists for one hazard, and the first fixture here is it: a description whose first
 * `m=` is **not** the data channel hands `mediaDescriptions.first()` a real, plausible section, and every
 * SCTP attribute read off it comes back with a wrong *number* rather than a visible miss.
 *
 * That is why the pair below is discriminating. "The helper finds the application section" would pass on
 * an implementation that simply returned the first one; asserting in the same breath that the first
 * section answers `a=max-message-size` **differently** is what proves the selection did any work. The
 * audio section here carries its own `a=max-message-size:1024`, which is legal SDP (RFC 8866 puts no
 * media-type constraint on an unknown attribute) and is the shape that makes the wrong answer survive
 * every sanity check a caller could think to apply.
 */
class DataChannelSectionTest {
    private fun parse(sdp: String): SessionDescription =
        when (val result = SessionDescription.parseText(sdp)) {
            is SdpParseResult.Success -> result.description
            is SdpParseResult.Reject -> throw AssertionError("fixture SDP did not parse: ${result.reason}")
        }

    private val sessionBlock =
        "v=0\r\n" +
            "o=- 1 1 IN IP4 127.0.0.1\r\n" +
            "s=-\r\n" +
            "t=0 0\r\n"

    @Test
    fun the_data_channel_section_is_found_behind_an_audio_section() {
        val description =
            parse(
                sessionBlock +
                    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" +
                    "a=mid:0\r\n" +
                    "a=max-message-size:1024\r\n" +
                    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
                    "a=mid:1\r\n" +
                    "a=sctp-port:5000\r\n" +
                    "a=max-message-size:262144\r\n",
            )

        val section = assertIs<DataChannelSection.Present>(description.dataChannelSection())
        assertEquals(Mid("1"), section.media.mid(), "the application section, not the first one")
        assertEquals(MaxMessageSizeAttribute.Bytes(262144), section.media.maxMessageSizeAttribute())

        // The anti-vacuity half: the section a positional read would have picked answers a DIFFERENT,
        // entirely plausible number. Without this the fixture passes on `firstOrNull()`.
        assertEquals(
            MaxMessageSizeAttribute.Bytes(1024),
            description.mediaDescriptions
                .first()
                .maxMessageSizeAttribute(),
            "the first section carries a plausible wrong answer — that is the hazard",
        )
    }

    @Test
    fun a_single_data_channel_description_is_found_where_it_already_was() {
        val description =
            parse(
                sessionBlock +
                    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
                    "a=mid:0\r\n",
            )
        val section = assertIs<DataChannelSection.Present>(description.dataChannelSection())
        assertEquals(Mid("0"), section.media.mid())
    }

    // Some peers still emit the pre-RFC-8841 proto. Selecting on `MediaLine.isDataChannel` rather than on
    // the media type alone is what keeps them found — and what keeps a hypothetical
    // `m=application … UDP/DTLS/SCTP` carrying something other than a data channel out.
    @Test
    fun the_legacy_dtls_sctp_proto_is_still_a_data_channel() {
        val description =
            parse(
                sessionBlock +
                    "m=application 9 DTLS/SCTP 5000\r\n" +
                    "a=max-message-size:65536\r\n",
            )
        val section = assertIs<DataChannelSection.Present>(description.dataChannelSection())
        assertEquals(MaxMessageSizeAttribute.Bytes(65536), section.media.maxMessageSizeAttribute())
    }

    @Test
    fun a_description_with_no_application_section_is_absent() {
        val description =
            parse(
                sessionBlock +
                    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" +
                    "a=mid:0\r\n" +
                    "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n" +
                    "a=mid:1\r\n",
            )
        assertEquals(DataChannelSection.Absent, description.dataChannelSection())
    }

    @Test
    fun a_session_with_no_media_at_all_is_absent() {
        assertEquals(DataChannelSection.Absent, parse(sessionBlock).dataChannelSection())
    }

    // `MediaLine.parse` is null-on-malformed and the selection must stay total on it: an `m=` line with
    // too few fields is skipped, not thrown on, and the real section behind it is still found.
    @Test
    fun a_malformed_media_line_is_skipped_rather_than_thrown_on() {
        val description =
            parse(
                sessionBlock +
                    "m=application 9\r\n" +
                    "a=mid:0\r\n" +
                    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
                    "a=mid:1\r\n",
            )
        val section = assertIs<DataChannelSection.Present>(description.dataChannelSection())
        assertEquals(Mid("1"), section.media.mid(), "the well-formed section, past the unparseable one")
    }

    // The builder's own output must be findable by the reader — otherwise every peer would have to know
    // that our `m=` line and our selector agree by coincidence rather than by construction.
    @Test
    fun a_description_this_module_builds_is_found_by_this_module_s_reader() {
        val built =
            dataChannelDescription(
                DataChannelParameters(
                    iceUfrag = "ufrag",
                    icePwd = "password-at-least-22-chars",
                    fingerprint = Fingerprint("sha-256", "AA:BB"),
                    setup = SetupRole.ActPass,
                    maxMessageSize = 131072,
                ),
                sessionId = "1",
                sessionVersion = 1,
            )
        val section = assertIs<DataChannelSection.Present>(built.dataChannelSection())
        assertEquals(MaxMessageSizeAttribute.Bytes(131072), section.media.maxMessageSizeAttribute())
    }
}
