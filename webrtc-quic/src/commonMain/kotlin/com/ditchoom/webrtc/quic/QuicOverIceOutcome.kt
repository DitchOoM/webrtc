package com.ditchoom.webrtc.quic

import com.ditchoom.webrtc.ice.CandidatePair
import com.ditchoom.webrtc.ice.IceFailureReason
import com.ditchoom.webrtc.ice.IceRole

/**
 * Which QUIC role the ICE role decided (`draft-seemann-quic-nat-traversal`, ICE mode): the controlling
 * agent dials, the controlled one listens. Derived from [IceRole] after nomination, so a role conflict
 * resolved during the checks (RFC 8445 §7.3.1.1) can never leave both peers dialling.
 */
public enum class QuicOverIceRole {
    Client,
    Server,
    ;

    public companion object {
        public fun of(role: IceRole): QuicOverIceRole =
            when (role) {
                IceRole.Controlling -> Client
                IceRole.Controlled -> Server
            }
    }
}

/**
 * The pair a QUIC connection rides and the role this endpoint took on it. ICE is the only thing that
 * can move the pair: the connection's own `migrate()` answers `BackendCannotMigrate`, because its local
 * endpoint is the socket ICE owns (`QuicClientBinding.Shared`).
 */
public data class QuicOverIcePath(
    public val pair: CandidatePair,
    public val role: QuicOverIceRole,
)

/**
 * How a session opened by `quicOverIce` ended — the composition's two lifetime limits as values a `when`
 * must handle, beside the ordinary completion. The connection's own failures (a handshake or idle
 * timeout, a peer's close) are not here; they keep their typed `QuicCloseException`.
 */
public sealed interface QuicOverIceOutcome<out R> {
    /** The block returned [value] over the pair it started on. */
    public data class Completed<R>(
        public val value: R,
    ) : QuicOverIceOutcome<R>

    /**
     * ICE nominated [to] while the session rode [from] — an ICE restart completed. The connection is
     * over rather than moved, for two reasons that no callback lifts: a shared-port client cannot
     * migrate (RFC 9000 §9 moves the *local* endpoint, and that is ICE's socket), and QUIC v1 cannot
     * follow a *peer's* address change at all. Reaching [to] is a reconnect — a full handshake today,
     * 0-RTT once socket#610 binds quiche's session API.
     */
    public data class PairMoved(
        public val from: CandidatePair,
        public val to: CandidatePair,
    ) : QuicOverIceOutcome<Nothing>

    /** ICE failed under the session, or before it ever nominated a pair; the connection went with it. */
    public data class IceFailed(
        public val reason: IceFailureReason,
    ) : QuicOverIceOutcome<Nothing>
}
