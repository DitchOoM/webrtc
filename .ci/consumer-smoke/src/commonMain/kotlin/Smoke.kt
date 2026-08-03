package consumer.smoke

import com.ditchoom.webrtc.IceServer
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.ice.IceServerCredentials
import com.ditchoom.webrtc.sctp.DeliveryOrder
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.testsuite.harness.NatType
import com.ditchoom.webrtc.testsuite.harness.NetworkImpairment
import com.ditchoom.webrtc.testsuite.harness.WebRtcHarnessScope
import kotlin.time.Duration.Companion.milliseconds

/**
 * Touches the published surface a real consumer configures — both `com.ditchoom:webrtc` (the consumer
 * API) and `com.ditchoom:webrtc-testsuite` (the `withWebRtcHarness` DSL) — on EVERY declared target.
 * Compiling this in commonMain is already stronger than dependency resolution: it catches an API that
 * resolves but does not compile (a wrong signature, a moved package, a type that didn't publish, a klib
 * variant missing for one target). It is deliberately not executed here; the behavioural establishment
 * runs in `jvmTest`.
 */
object Smoke {
    /** The typed NAT taxonomy the DSL exposes — referencing every variant pins the published sealed shape. */
    fun natTypes(): List<NatType> =
        listOf(
            NatType.None,
            NatType.FullCone,
            NatType.AddressRestrictedCone,
            NatType.PortRestrictedCone,
            NatType.Symmetric,
        )

    /** A netem-style impairment built through the published factory. */
    fun impairment(): NetworkImpairment =
        NetworkImpairment.of(delay = 20.milliseconds, jitter = 5.milliseconds, loss = 0.05)

    /** Configure a scenario through the DSL scope (compile-only — never invoked without a harness). */
    fun configure(scope: WebRtcHarnessScope) {
        scope.natType(NatType.Symmetric)
        scope.relayOnly()
        scope.impaired(impairment())
    }

    // ── `com.ditchoom:webrtc` — the consumer API, reached through its OWN published coordinate ─────────
    // Everything below compiles against the artifact a downstream project declares to write application
    // code, not test code. It is what proves that coordinate is independently usable.

    /**
     * A TURN server with long-term credentials, exactly as a consumer configures one.
     *
     * The two imports above are deliberately asymmetric, and that asymmetry is the assertion. `IceServer`
     * and `IceServerCredentials` now live in `com.ditchoom.webrtc.ice`, where `webrtc-ice` can reach them
     * to implement gathering; `com.ditchoom.webrtc` keeps `typealias`es so existing code that names the
     * *type* still compiles — which the `IceServer` import here pins. A typealias cannot carry a nested
     * classifier, though, so `IceServerCredentials.LongTerm` must be reached through the real package.
     * That is the one source break in the move, and this file is where it is proven rather than assumed:
     * flipping this import back to `com.ditchoom.webrtc` is expected to fail the build.
     */
    fun iceServers(): List<IceServer> =
        listOf(
            IceServer("stun:stun.example.org:3478"),
            IceServer("turn:turn.example.org:3478", IceServerCredentials.LongTerm("user", "pass")),
        )

    /** The peer-connection config a consumer hands to a factory — defaults must be usable as published. */
    fun peerConnectionConfig(): PeerConnectionConfig = PeerConnectionConfig()

    /** The data-channel shapes a consumer opens: reliable/ordered by default, and an unordered one. */
    fun dataChannelConfigs(): List<DataChannelConfig> =
        listOf(
            DataChannelConfig(label = "control"),
            DataChannelConfig(label = "telemetry", delivery = DeliveryOrder.Unordered),
        )

    /**
     * The sealed connection-state hierarchy a consumer must be able to `when` over exhaustively — no
     * `else` branch. If a variant is added or renamed in a published release, this stops compiling,
     * which is the whole point: it is a source-compatibility assertion the .api files cannot make.
     */
    fun describe(state: PeerConnectionState): String =
        when (state) {
            is PeerConnectionState.New -> "new"
            is PeerConnectionState.Connecting -> "connecting"
            is PeerConnectionState.Connected -> "connected"
            // Added in the ICE-restart release (RFC 8445 §9): the session is live and usable — data still
            // rides the old pair — but the pair underneath is about to change. A consumer that lumped this
            // in with `connected` would be told nothing; that it had to come here and choose is the reason
            // it is a variant rather than a flag.
            is PeerConnectionState.Restarting -> "restarting"
            is PeerConnectionState.Failed -> "failed: ${state.reason}"
            is PeerConnectionState.Closed -> "closed"
        }
}
