package com.ditchoom.webrtc.testsuite.harness

import com.ditchoom.webrtc.testsuite.vnet.ImpairmentConfig
import kotlin.time.Duration

/**
 * A `netem`-style link impairment applied end-to-end to every datagram of a [withWebRtcHarness]
 * scenario. [loss] and [duplicate] are per-datagram probabilities; wire delay is drawn uniformly in
 * `[minDelay, maxDelay]` (so **reordering is emergent** — two datagrams that draw different delays
 * arrive out of order — and there is no separate reorder knob). Realized against `runTest` virtual
 * time, so a 200 ms jittered link costs zero wall-clock and replays identically from the harness seed.
 *
 * Prefer the [WebRtcHarnessScope.impaired] DSL setter, which expresses delay as a base ± jitter.
 */
public data class NetworkImpairment(
    public val loss: Double = 0.0,
    public val duplicate: Double = 0.0,
    public val minDelay: Duration = Duration.ZERO,
    public val maxDelay: Duration = Duration.ZERO,
) {
    init {
        require(loss in 0.0..1.0) { "loss must be a probability in 0.0..1.0, was $loss" }
        require(duplicate in 0.0..1.0) { "duplicate must be a probability in 0.0..1.0, was $duplicate" }
        require(minDelay <= maxDelay) { "minDelay ($minDelay) must not exceed maxDelay ($maxDelay)" }
    }

    internal fun toConfig(): ImpairmentConfig =
        ImpairmentConfig(loss = loss, duplicate = duplicate, minDelay = minDelay, maxDelay = maxDelay)

    public companion object {
        /**
         * A link with base [delay] ± [jitter] (netem `delay <delay> <jitter>`), [loss], and [duplicate].
         * The delay window is `[(delay - jitter).coerceAtLeast(0), delay + jitter]`.
         */
        public fun of(
            delay: Duration = Duration.ZERO,
            jitter: Duration = Duration.ZERO,
            loss: Double = 0.0,
            duplicate: Double = 0.0,
        ): NetworkImpairment =
            NetworkImpairment(
                loss = loss,
                duplicate = duplicate,
                minDelay = (delay - jitter).coerceAtLeast(Duration.ZERO),
                maxDelay = delay + jitter,
            )
    }
}
