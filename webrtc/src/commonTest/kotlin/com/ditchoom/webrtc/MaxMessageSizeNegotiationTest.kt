@file:OptIn(ExperimentalTime::class, ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.DatagramBinder
import com.ditchoom.webrtc.sctp.association.ReceiveMessageLimit
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.PeerMessageLimit
import com.ditchoom.webrtc.sdp.DataChannelParameters
import com.ditchoom.webrtc.sdp.DataChannelSection
import com.ditchoom.webrtc.sdp.MaxMessageSizeAttribute
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SdpType
import com.ditchoom.webrtc.sdp.SessionDescription
import com.ditchoom.webrtc.sdp.dataChannelSection
import com.ditchoom.webrtc.sdp.maxMessageSizeAttribute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * `a=max-message-size` (RFC 8841 §6) at the session seam, in both directions.
 *
 * The **outbound** half is the one that had no fixture and no wiring: `localParams` took
 * `DataChannelParameters`' own default, so the number we advertised was a constant rather than the
 * ceiling the association is configured to enforce. A caller could lower `receiveMessageLimit` and keep
 * promising 256 KiB — a promise the reassembly queue is configured to break, and one no assertion here
 * or on the wire would have noticed. Every fixture below therefore reads the emitted SDP, not the config
 * it came from.
 *
 * The **inbound** half is the read, and its sharp case is a description whose first `m=` is not the data
 * channel: the attribute is media-level only (no session-level fallback), so a positional read returns a
 * plausible number belonging to something else rather than nothing at all.
 *
 * `webrtc` is the only module that sees both `ReceiveMessageLimit.Default` and
 * `DataChannelParameters.DEFAULT_MAX_MESSAGE_SIZE`, so it is the only place their agreement can be
 * asserted rather than maintained by hand.
 */
class MaxMessageSizeNegotiationTest {
    private val epoch = Instant.fromEpochSeconds(0)

    private fun peer(
        scope: CoroutineScope,
        sctpConfig: SctpConfig = SctpConfig(),
    ) = NativePeerConnection(
        scope = scope,
        clock = { epoch },
        random = Random(11),
        binder = DatagramBinder { TestNet().bind(it) },
        gathering = { it.gatherHost("10.0.0.1", 4000) },
        dtls = PlaintextDtls,
        config = PeerConnectionConfig(sctpConfig = sctpConfig),
    )

    private fun advertisedIn(sdp: String): MaxMessageSizeAttribute {
        val description =
            when (val parsed = SessionDescription.parseText(sdp)) {
                is SdpParseResult.Success -> parsed.description
                is SdpParseResult.Reject -> throw AssertionError("our own offer did not parse: ${parsed.reason}")
            }
        val section = assertIs<DataChannelSection.Present>(description.dataChannelSection())
        return section.media.maxMessageSizeAttribute()
    }

    @Test
    fun the_two_defaults_in_this_area_agree() {
        assertEquals(
            ReceiveMessageLimit.Bytes(DataChannelParameters.DEFAULT_MAX_MESSAGE_SIZE),
            ReceiveMessageLimit.Default,
            "the SCTP receive default and the SDP advertise default are the same number, in two modules",
        )
    }

    @Test
    fun an_unconfigured_offer_advertises_the_default_ceiling() =
        runTest {
            val pc = peer(backgroundScope)
            assertEquals(MaxMessageSizeAttribute.Bytes(262_144), advertisedIn(pc.createOffer()))
            pc.close()
        }

    @Test
    fun a_configured_receive_ceiling_is_what_the_offer_advertises() =
        runTest {
            val pc = peer(backgroundScope, SctpConfig(receiveMessageLimit = ReceiveMessageLimit.Bytes(16_384)))
            assertEquals(
                MaxMessageSizeAttribute.Bytes(16_384),
                advertisedIn(pc.createOffer()),
                "what we advertise is what the association will accept",
            )
            pc.close()
        }

    // The inversion, at the one place it reaches the wire: RFC 8841 §6 spells "no limit" as `0`. An
    // implementation that emitted `Unbounded` as its numeric value would advertise nothing at all, and
    // one that emitted a ceiling of 0 would tell every peer to send nothing.
    @Test
    fun an_unbounded_receive_ceiling_advertises_the_wire_s_zero() =
        runTest {
            val pc = peer(backgroundScope, SctpConfig(receiveMessageLimit = ReceiveMessageLimit.Unbounded))
            assertEquals(MaxMessageSizeAttribute.Unlimited, advertisedIn(pc.createOffer()))
            pc.close()
        }

    @Test
    fun the_peer_limit_is_not_yet_negotiated_before_any_remote_description() =
        runTest {
            val pc = peer(backgroundScope)
            assertEquals(PeerMessageLimit.NotYetNegotiated, pc.peerMessageLimit.value)
            pc.close()
        }

    @Test
    fun a_peer_that_states_a_ceiling_is_read_as_advertised() =
        runTest {
            val pc = peer(backgroundScope)
            pc.setLocalDescription(SdpType.Offer, pc.createOffer())
            pc.setRemoteDescription(SdpType.Answer, remoteAnswer(maxMessageSize = "131072"))
            assertEquals(PeerMessageLimit.Advertised(131_072), pc.peerMessageLimit.value)
            pc.close()
        }

    @Test
    fun a_peer_that_states_nothing_is_read_as_the_rfc_8831_assumed_default() =
        runTest {
            val pc = peer(backgroundScope)
            pc.setLocalDescription(SdpType.Offer, pc.createOffer())
            pc.setRemoteDescription(SdpType.Answer, remoteAnswer(maxMessageSize = null))
            assertEquals(PeerMessageLimit.AssumedDefault, pc.peerMessageLimit.value)
            pc.close()
        }

    @Test
    fun a_peer_that_states_zero_is_read_as_unlimited() =
        runTest {
            val pc = peer(backgroundScope)
            pc.setLocalDescription(SdpType.Offer, pc.createOffer())
            pc.setRemoteDescription(SdpType.Answer, remoteAnswer(maxMessageSize = "0"))
            assertEquals(PeerMessageLimit.Unlimited, pc.peerMessageLimit.value)
            pc.close()
        }

    /**
     * The conservative direction, and the reason it is not merely tidy: a digit string past
     * `Long.MAX_VALUE` is grammatically legal and cannot be a `Long`, so it arrives as `Malformed`. Read
     * as "we could not parse a limit, so there is none" it becomes the most permissive value in the type;
     * read as silence it becomes the tightest defensible one. RFC 8831 §6.6 makes exceeding a peer's
     * limit a MUST NOT, so only one of those readings is available.
     */
    @Test
    fun a_peer_whose_ceiling_is_unreadable_is_treated_as_silence_not_as_no_limit() =
        runTest {
            val pc = peer(backgroundScope)
            pc.setLocalDescription(SdpType.Offer, pc.createOffer())
            pc.setRemoteDescription(SdpType.Answer, remoteAnswer(maxMessageSize = "99999999999999999999"))
            assertEquals(PeerMessageLimit.AssumedDefault, pc.peerMessageLimit.value)
            pc.close()
        }

    /**
     * The hazard the shared helper exists to close. The audio section carries a real ceiling of its own,
     * so a positional read produces `Advertised(1024)` — a number that is plausible, wrong, and belongs
     * to a different section entirely.
     */
    @Test
    fun the_peer_limit_comes_from_the_data_channel_section_not_the_first_one() =
        runTest {
            val pc = peer(backgroundScope)
            pc.setLocalDescription(SdpType.Offer, pc.createOffer())
            pc.setRemoteDescription(SdpType.Answer, audioFirstAnswer())
            assertEquals(
                PeerMessageLimit.Advertised(262_144),
                pc.peerMessageLimit.value,
                "the application section's ceiling, not the audio section's 1024",
            )
            pc.close()
        }

    // A remote answer built by hand rather than by `dataChannelDescription`, because half of what is
    // under test here is which SECTION is read — which a single-section builder cannot express.
    private fun remoteAnswer(maxMessageSize: String?): String =
        buildString {
            append("v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n")
            append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
            append("c=IN IP4 0.0.0.0\r\n")
            append("a=ice-ufrag:remoteufrag\r\n")
            append("a=ice-pwd:remotepasswordremotepassword\r\n")
            append("a=fingerprint:sha-256 $REMOTE_FINGERPRINT\r\n")
            append("a=setup:active\r\n")
            append("a=mid:0\r\n")
            append("a=sctp-port:5000\r\n")
            if (maxMessageSize != null) append("a=max-message-size:$maxMessageSize\r\n")
        }

    private fun audioFirstAnswer(): String =
        buildString {
            append("v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n")
            append("m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n")
            append("a=ice-ufrag:remoteufrag\r\n")
            append("a=ice-pwd:remotepasswordremotepassword\r\n")
            append("a=fingerprint:sha-256 $REMOTE_FINGERPRINT\r\n")
            append("a=setup:active\r\n")
            append("a=mid:0\r\n")
            append("a=max-message-size:1024\r\n")
            append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
            append("a=mid:1\r\n")
            append("a=sctp-port:5000\r\n")
            append("a=max-message-size:262144\r\n")
        }

    private companion object {
        // Any well-formed SHA-256 digest: this fixture never completes a DTLS handshake, so the value is
        // only ever parsed, never verified against a certificate.
        private const val REMOTE_FINGERPRINT =
            "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:" +
                "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
    }
}
