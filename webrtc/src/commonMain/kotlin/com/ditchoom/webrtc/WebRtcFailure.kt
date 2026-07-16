package com.ditchoom.webrtc

import com.ditchoom.socket.ConnectionFailure
import com.ditchoom.socket.ConnectionFailureReason
import com.ditchoom.socket.SocketClosedException
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.sctp.association.SctpFailureReason

/**
 * Why a DTLS handshake failed — a sealed, exhaustive vocabulary defined here (W6) so the session-layer
 * error sweep is complete before the real backend (W4) lands (HANDOFF W6 step 4: map ICE + SCTP + "the
 * coming DTLS reasons" into the `SocketException` hierarchy). The BoringSSL driver produces these; until
 * then the plaintext DTLS stand-in never fails, so no value is constructed at runtime yet.
 */
public sealed interface DtlsFailureReason {
    /** Human-readable summary — the sealed value is the discriminant, never the string (directive #3). */
    public val description: String

    /** The DTLS handshake did not complete (alert, record error, or version/cipher mismatch). */
    public data object HandshakeFailed : DtlsFailureReason {
        override val description: String get() = "DTLS handshake failed"
    }

    /** The peer's certificate fingerprint did not match the `a=fingerprint` in its SDP (RFC 8122). */
    public data object FingerprintMismatch : DtlsFailureReason {
        override val description: String get() = "DTLS certificate fingerprint did not match the SDP a=fingerprint"
    }

    /** The handshake did not complete within its retransmission budget. */
    public data object Timeout : DtlsFailureReason {
        override val description: String get() = "DTLS handshake timed out"
    }
}

/**
 * The exhaustive, typed cause of a WebRTC session failure — the WebRTC-level companion to socket's
 * [ConnectionFailureReason]. It composes the sub-layer sealed reasons unchanged ([IceFailureReason],
 * [DtlsFailureReason], [SctpFailureReason]) rather than flattening them, so a caller can recover the
 * exact ICE/DTLS/SCTP condition, and `when` is exhaustive at every level (DESIGN §3/§6). This realizes
 * the "typed errors, never stringly" directive at the session boundary — the ICE and SCTP handoffs
 * explicitly deferred mapping their reasons into the shared hierarchy to this wave.
 */
public sealed interface PeerConnectionFailureReason {
    /** One-line summary for the exception message; the sealed value is the API surface. */
    public val description: String

    /** The portable socket-level cause, for `catch (e: SocketException)` recovery via [ConnectionFailure]. */
    public fun toConnectionFailureReason(): ConnectionFailureReason

    /** ICE never produced (or lost) a usable candidate pair (RFC 8445 / RFC 7675). */
    public data class Ice(
        public val reason: IceFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "ICE failed: $reason"

        override fun toConnectionFailureReason(): ConnectionFailureReason =
            when (reason) {
                is IceFailureReason.NoCandidatePairs -> ConnectionFailureReason.NetworkUnreachable
                is IceFailureReason.AllPairsFailed -> ConnectionFailureReason.HostUnreachable
                is IceFailureReason.ConsentExpired -> ConnectionFailureReason.Timeout
            }
    }

    /** The DTLS handshake over the selected pair failed (W4). */
    public data class Dtls(
        public val reason: DtlsFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = reason.description

        override fun toConnectionFailureReason(): ConnectionFailureReason =
            when (reason) {
                DtlsFailureReason.HandshakeFailed -> ConnectionFailureReason.TlsHandshake
                DtlsFailureReason.FingerprintMismatch -> ConnectionFailureReason.TlsBadCertificate
                DtlsFailureReason.Timeout -> ConnectionFailureReason.Timeout
            }
    }

    /** The SCTP association aborted or never established (RFC 4960 / RFC 3758). */
    public data class Sctp(
        public val reason: SctpFailureReason,
    ) : PeerConnectionFailureReason {
        override val description: String get() = "SCTP failed: $reason"

        override fun toConnectionFailureReason(): ConnectionFailureReason =
            when (reason) {
                SctpFailureReason.HandshakeTimeout -> ConnectionFailureReason.Timeout
                SctpFailureReason.RetransmissionLimitReached -> ConnectionFailureReason.Timeout
                SctpFailureReason.AbortReceived -> ConnectionFailureReason.Unknown("SCTP association aborted by peer")
                is SctpFailureReason.ProtocolViolation -> ConnectionFailureReason.Unknown("SCTP protocol violation")
            }
    }
}

/**
 * The single thrown vocabulary for a WebRTC session failure (RFC §3.1). It extends socket's abstract
 * [SocketClosedException] — the extension point protocol layers built on socket use (the QUIC module's
 * `QuicCloseException` is the precedent) — so a WebRTC failure is caught uniformly with every other
 * transport failure via `catch (e: SocketClosedException)` / `catch (e: SocketException)` / on JVM
 * `catch (e: IOException)`. It also implements [ConnectionFailure], so a caller can read the portable
 * [reason] off the catch-all without knowing this concrete type; the rich WebRTC cause stays available
 * as the typed [failure].
 */
public class WebRtcException(
    public val failure: PeerConnectionFailureReason,
    cause: Throwable? = null,
) : SocketClosedException(failure.description, cause),
    ConnectionFailure {
    override val reason: ConnectionFailureReason get() = failure.toConnectionFailureReason()
}
