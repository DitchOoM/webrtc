@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package consumer.smoke

import com.ditchoom.webrtc.ice.CandidateType
import com.ditchoom.webrtc.testsuite.harness.NatType
import com.ditchoom.webrtc.testsuite.harness.withWebRtcHarness
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * W7 Phase 3: drive the deterministic in-memory harness through the PUBLISHED
 * `com.ditchoom:webrtc-testsuite` artifact exactly as a downstream consumer would — an `implementation`
 * dependency resolved from `mavenLocal()` (or the merged repo under validation in CI), plain
 * `runTest` test code, no docker, no knowledge of the vnet internals.
 *
 * This RUNS a full two-peer establishment (ICE + plaintext-DTLS + SCTP + a DataChannel) over the
 * published DSL and asserts the echoed payload + the selected candidate types — proving the published
 * API is usable, and links + runs, from outside the repo. It is the artifact-shape safety net the
 * source-built lanes cannot see (the socket #188 lesson: every published artifact, `webrtc-testsuite`
 * included, must be a real consumer's dependency at least once).
 */
class HarnessConsumerSmokeTest {
    private val epoch = Instant.fromEpochSeconds(0)

    @Test
    fun flatHarnessEstablishesThroughPublishedApi() =
        runTest(timeout = kotlin.time.Duration.parse("60s")) {
            withWebRtcHarness(
                scope = backgroundScope,
                clock = { epoch + testScheduler.currentTime.milliseconds },
            ) {
                natType(NatType.None)
                val echoed = roundTrip("consumer-smoke")
                assertEquals("consumer-smoke", echoed, "published harness must echo the data-channel payload")
                assertEquals(CandidateType.Host, establish().selectedPair?.local?.type)
                println("[consumer-smoke] withWebRtcHarness establish + echo OK via published webrtc-testsuite")
            }
        }

    @Test
    fun symmetricNatRelaysThroughPublishedApi() =
        runTest(timeout = kotlin.time.Duration.parse("60s")) {
            withWebRtcHarness(
                scope = backgroundScope,
                clock = { epoch + testScheduler.currentTime.milliseconds },
            ) {
                natType(NatType.Symmetric)
                val conn = establish()
                assertNotNull(conn.selectedPair, "symmetric scenario must select a pair")
                assertEquals(CandidateType.Relayed, conn.selectedPair?.local?.type, "symmetric↔symmetric meets on the relay")
            }
        }
}
