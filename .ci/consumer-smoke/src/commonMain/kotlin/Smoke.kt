package consumer.smoke

import com.ditchoom.webrtc.testsuite.harness.NatType
import com.ditchoom.webrtc.testsuite.harness.NetworkImpairment
import com.ditchoom.webrtc.testsuite.harness.WebRtcHarnessScope
import kotlin.time.Duration.Companion.milliseconds

/**
 * Touches the published `withWebRtcHarness` DSL surface a real consumer configures, on EVERY declared
 * target. Compiling this in commonMain is already stronger than dependency resolution — it catches an
 * API that resolves but does not compile (a wrong signature, a moved package, a type that didn't
 * publish). It is deliberately not executed here; the behavioural establishment runs in `jvmTest`.
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
}
