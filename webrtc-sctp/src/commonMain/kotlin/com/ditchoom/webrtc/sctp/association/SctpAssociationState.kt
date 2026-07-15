package com.ditchoom.webrtc.sctp.association

/**
 * The lifecycle phase of an [SctpAssociation] (RFC 4960 §4). A **sealed** set so a consumer's `when` is
 * exhaustive with no `else`; the cross-cutting protocol data (TSN counters, send/retransmit queues,
 * congestion state) lives on the association itself — this discriminant is the phase only. The illegal
 * "established AND closed" style combinations a boolean bag would allow are unrepresentable
 * (DESIGN_PRINCIPLES §4).
 */
public sealed interface SctpAssociationState {
    /** No association — before [SctpEvent.Associate], or after a completed shutdown / abort. */
    public data object Closed : SctpAssociationState

    /** Sent INIT, awaiting INIT-ACK (RFC 4960 §4). The active-open side's first wait. */
    public data object CookieWait : SctpAssociationState

    /** Sent COOKIE-ECHO, awaiting COOKIE-ACK (RFC 4960 §4). */
    public data object CookieEchoed : SctpAssociationState

    /** The four-way handshake completed — user data may flow (RFC 4960 §4). */
    public data object Established : SctpAssociationState

    /** A local shutdown was requested; draining outstanding data before SHUTDOWN (RFC 4960 §9.2). */
    public data object ShutdownPending : SctpAssociationState

    /** Sent SHUTDOWN, awaiting SHUTDOWN-ACK (RFC 4960 §9.2). */
    public data object ShutdownSent : SctpAssociationState

    /** Received the peer's SHUTDOWN; draining our outstanding data before SHUTDOWN-ACK (RFC 4960 §9.2). */
    public data object ShutdownReceived : SctpAssociationState

    /** Sent SHUTDOWN-ACK, awaiting SHUTDOWN-COMPLETE (RFC 4960 §9.2). */
    public data object ShutdownAckSent : SctpAssociationState
}

/**
 * Why an [SctpAssociation] failed — a sealed, exhaustive vocabulary; the discriminant is the type,
 * never a string (directive #3). These map into the `SocketException` hierarchy at the PeerConnection
 * layer (W6). Diagnostic detail rides as data on the variant.
 */
public sealed interface SctpFailureReason {
    /** The peer sent an ABORT (RFC 4960 §3.3.7). Carries whether the T-bit reflected our tag. */
    public data object AbortReceived : SctpFailureReason

    /** The retransmission error counter crossed Association.Max.Retrans (RFC 4960 §8.1). */
    public data object RetransmissionLimitReached : SctpFailureReason

    /** INIT / COOKIE-ECHO exceeded Max.Init.Retransmits without a response (RFC 4960 §4). */
    public data object HandshakeTimeout : SctpFailureReason

    /**
     * A handshake chunk was malformed or arrived out of the protocol's expected order in a way that
     * cannot be recovered (e.g. an INIT-ACK with no State Cookie, or a cookie we did not mint).
     */
    public data class ProtocolViolation(
        public val detail: ProtocolViolationKind,
    ) : SctpFailureReason
}

/** The specific handshake/protocol fault behind an [SctpFailureReason.ProtocolViolation]. */
public enum class ProtocolViolationKind {
    /** An INIT-ACK carried no State Cookie parameter (RFC 4960 §3.3.3.1). */
    MissingStateCookie,

    /** A COOKIE-ECHO carried a cookie this endpoint did not mint (bad magic / stale). */
    InvalidCookie,

    /** An INIT advertised zero inbound or outbound streams (RFC 4960 §3.3.2 requires ≥ 1). */
    ZeroStreams,
}
