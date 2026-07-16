package com.ditchoom.webrtc

import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.sctp.association.SctpFailureReason
import com.ditchoom.webrtc.sctp.datachannel.SctpClosedException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The W6 error sweep (HANDOFF step 4): every WebRTC failure surfaces as one exception type carrying a
 * **typed** cause that composes the sub-layer sealed reason unchanged — so a caller catches one type and
 * still recovers the exact ICE/DTLS/SCTP condition, and `when` is exhaustive at every level (directive #3).
 * (Re-parenting these onto socket's `SocketException` — RFC §3.1 — is deferred on the upstream BoringSSL
 * constraint documented on [PeerConnectionFailureReason].)
 */
class WebRtcFailureTest {
    @Test
    fun webrtc_exception_preserves_the_typed_ice_cause() {
        val e = WebRtcException(PeerConnectionFailureReason.Ice(IceFailureReason.AllPairsFailed(3)))
        val ice = assertIs<PeerConnectionFailureReason.Ice>(e.failure) // rich cause preserved, not flattened
        assertIs<IceFailureReason.AllPairsFailed>(ice.reason)
        assertTrue(e.message!!.contains("ICE failed"))
    }

    @Test
    fun failure_reasons_are_exhaustive_and_describe_themselves() {
        val reasons: List<PeerConnectionFailureReason> =
            listOf(
                PeerConnectionFailureReason.Ice(IceFailureReason.NoCandidatePairs),
                PeerConnectionFailureReason.Ice(IceFailureReason.ConsentExpired),
                PeerConnectionFailureReason.Dtls(DtlsFailureReason.FingerprintMismatch),
                PeerConnectionFailureReason.Dtls(DtlsFailureReason.HandshakeFailed),
                PeerConnectionFailureReason.Sctp(SctpFailureReason.HandshakeTimeout),
                PeerConnectionFailureReason.Sctp(SctpFailureReason.AbortReceived),
            )
        for (r in reasons) {
            // Exhaustive `when` with no else — adding a variant is a compile error until handled.
            val label =
                when (r) {
                    is PeerConnectionFailureReason.Ice -> "ice"
                    is PeerConnectionFailureReason.Dtls -> "dtls"
                    is PeerConnectionFailureReason.Sctp -> "sctp"
                }
            assertTrue(label.isNotEmpty())
            assertTrue(r.description.isNotEmpty())
        }
    }

    @Test
    fun sctp_closed_exception_carries_its_typed_reason() {
        val closed = SctpClosedException(SctpFailureReason.AbortReceived)
        assertEquals(SctpFailureReason.AbortReceived, closed.reason)
    }
}
