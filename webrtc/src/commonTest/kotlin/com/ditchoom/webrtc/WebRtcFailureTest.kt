package com.ditchoom.webrtc

import com.ditchoom.socket.ConnectionFailure
import com.ditchoom.socket.ConnectionFailureReason
import com.ditchoom.socket.SocketClosedException
import com.ditchoom.socket.SocketException
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.sctp.association.SctpFailureReason
import com.ditchoom.webrtc.sctp.datachannel.SctpClosedException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The W6 error sweep (HANDOFF step 4): every WebRTC failure maps into socket's `SocketException`
 * hierarchy with its typed sub-layer reason preserved, so a caller catches one vocabulary and still
 * recovers the exact ICE/DTLS/SCTP cause (RFC §3.1 "one thrown vocabulary", directive #3).
 */
class WebRtcFailureTest {
    @Test
    fun webrtc_exception_is_a_socket_exception_and_exposes_a_portable_reason() {
        val e = WebRtcException(PeerConnectionFailureReason.Ice(IceFailureReason.AllPairsFailed(3)))
        assertIs<SocketException>(e) // caught uniformly with every other transport failure
        assertIs<SocketClosedException>(e) // the QUIC-module extension point
        assertIs<ConnectionFailure>(e)
        assertEquals(ConnectionFailureReason.HostUnreachable, (e as ConnectionFailure).reason)
        // The rich typed cause is preserved, not flattened.
        val ice = assertIs<PeerConnectionFailureReason.Ice>(e.failure)
        assertIs<IceFailureReason.AllPairsFailed>(ice.reason)
    }

    @Test
    fun each_ice_reason_maps_to_a_portable_reason() {
        assertEquals(
            ConnectionFailureReason.NetworkUnreachable,
            PeerConnectionFailureReason.Ice(IceFailureReason.NoCandidatePairs).toConnectionFailureReason(),
        )
        assertEquals(
            ConnectionFailureReason.Timeout,
            PeerConnectionFailureReason.Ice(IceFailureReason.ConsentExpired).toConnectionFailureReason(),
        )
    }

    @Test
    fun dtls_and_sctp_reasons_map_into_the_hierarchy() {
        assertEquals(
            ConnectionFailureReason.TlsBadCertificate,
            PeerConnectionFailureReason.Dtls(DtlsFailureReason.FingerprintMismatch).toConnectionFailureReason(),
        )
        assertEquals(
            ConnectionFailureReason.TlsHandshake,
            PeerConnectionFailureReason.Dtls(DtlsFailureReason.HandshakeFailed).toConnectionFailureReason(),
        )
        assertEquals(
            ConnectionFailureReason.Timeout,
            PeerConnectionFailureReason.Sctp(SctpFailureReason.HandshakeTimeout).toConnectionFailureReason(),
        )
        val abort = PeerConnectionFailureReason.Sctp(SctpFailureReason.AbortReceived).toConnectionFailureReason()
        assertIs<ConnectionFailureReason.Unknown>(abort)
    }

    @Test
    fun sctp_closed_exception_is_now_a_socket_exception() {
        // W5's data-channel close vocabulary joined the hierarchy in this wave (the SocketException sweep).
        val closed = SctpClosedException(SctpFailureReason.AbortReceived)
        assertIs<SocketException>(closed)
        assertIs<SocketClosedException>(closed)
        assertTrue(closed.reason == SctpFailureReason.AbortReceived)
    }
}
