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
import kotlin.test.assertTrue
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

    /**
     * `relayOnly()` on its own: no host/srflx candidate is even gathered, so a FLAT topology — one that
     * would trivially connect host-to-host — must still come up over TURN. Asserting `Relayed` on a flat
     * topology is what makes this a real test of the knob rather than of the NAT: under [NatType.None] a
     * relayed pair can only be the result of `relayOnly()` having taken effect.
     */
    @Test
    fun relayOnlyForcesTheRelayPathThroughPublishedApi() =
        runTest(timeout = kotlin.time.Duration.parse("60s")) {
            withWebRtcHarness(
                scope = backgroundScope,
                clock = { epoch + testScheduler.currentTime.milliseconds },
            ) {
                natType(NatType.None)
                relayOnly()
                val echoed = roundTrip("relay-only")
                assertEquals("relay-only", echoed, "the relayed path must carry data-channel payload end to end")
                assertEquals(
                    CandidateType.Relayed,
                    establish().selectedPair?.local?.type,
                    "relayOnly() must suppress host/srflx so only a relayed pair can be selected",
                )
            }
        }

    /**
     * The W7 exit-criterion scenario, verbatim: `natType()` + `relayOnly()` + `impaired()` composed in
     * one harness. Loss + delay + jitter + duplication on the link, both peers behind a symmetric NAT,
     * ICE constrained to TURN — the hardest topology the DSL can express — and the data channel still
     * echoes. Runs in virtual time, so the impairment costs no wall-clock.
     */
    @Test
    fun impairedRelayOnlySymmetricScenarioThroughPublishedApi() =
        runTest(timeout = kotlin.time.Duration.parse("120s")) {
            withWebRtcHarness(
                scope = backgroundScope,
                clock = { epoch + testScheduler.currentTime.milliseconds },
            ) {
                natType(NatType.Symmetric)
                relayOnly()
                impaired(loss = 0.05, delay = 20.milliseconds, jitter = 5.milliseconds, duplicate = 0.01)

                val echoed = roundTrip("impaired-relay")
                assertEquals("impaired-relay", echoed, "the stack must ride out loss/jitter/duplication and echo intact")

                val conn = establish()
                assertEquals(CandidateType.Relayed, conn.selectedPair?.local?.type)
                assertEquals(NatType.Symmetric, conn.manifest.natType, "the manifest must report the scenario it ran")
                assertTrue(conn.manifest.relayOnly, "the manifest must report relayOnly")
                assertNotNull(conn.manifest.impairment, "the manifest must report the impairment")
                assertTrue(allocationCount > 0, "the counting buffer factory must have observed allocations")
                println("[consumer-smoke] impaired relay-only symmetric scenario OK (allocations=$allocationCount)")
            }
        }
}
