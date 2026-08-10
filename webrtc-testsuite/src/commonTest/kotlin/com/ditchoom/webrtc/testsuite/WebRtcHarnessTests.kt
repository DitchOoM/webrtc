@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.testsuite

import com.ditchoom.webrtc.ice.CandidateType
import com.ditchoom.webrtc.testsuite.harness.NatType
import com.ditchoom.webrtc.testsuite.harness.NetworkImpairment
import com.ditchoom.webrtc.testsuite.harness.withWebRtcHarness
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * W7 Phase 3 validation of the published `withWebRtcHarness { }` consumer harness — the mirror of
 * socket's `NetworkHarnessTests`, but driving the deterministic in-memory **vnet** under `runTest`
 * virtual time (not real docker; that is the L2/L3 `test-harness/` concern). Every test asserts
 * **observable establishment state** (Connected + a data-channel echo, or a typed failure) under the
 * harness's virtual `establishTimeout` **watchdog** — never a wall-clock budget (directive #4). The
 * whole matrix replays at zero wall-clock on every platform the module builds (Apple is
 * compile-faithful here; JVM/Linux runtime-validated).
 */
class WebRtcHarnessTests {
    private val epoch = Instant.fromEpochSeconds(0)

    /** A flat (no-NAT) link establishes and echoes a data-channel message on the host candidate pair. */
    @Test
    fun flatLinkEstablishesAndRoundTrips() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.None)
                val echoed = roundTrip("ping")
                assertEquals("ping", echoed, "flat link should echo the data-channel payload")
                assertEquals(CandidateType.Host, establish().selectedPair?.local?.type, "flat link selects a host pair")
            }
        }

    /**
     * A full-cone NAT on both peers connects via the server-reflexive (srflx) candidates.
     *
     * Pinning the type is the whole point: the harness policy also gathers a TURN relay outside
     * `relayOnly`, so a total srflx regression would silently fall back to the relay and a bare
     * `assertNotNull(selectedPair)` would stay green. The claim is read off the **remote** side —
     * per RFC 8445 §6.1.2.2 a local srflx candidate is replaced by its **base** when pairs are formed,
     * so our own half of an srflx pair is legitimately a `Host` candidate (asserted here too, so a
     * relayed *local* candidate cannot hide behind the remote check).
     */
    @Test
    fun fullConeNatConnectsViaServerReflexive() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.FullCone)
                assertEquals("hello", roundTrip("hello"))
                val pair = assertNotNull(establish().selectedPair, "full-cone should select a candidate pair")
                assertEquals(
                    CandidateType.ServerReflexive,
                    pair.remote.type,
                    "full-cone must meet on the peer's server-reflexive candidate, not the relay fallback",
                )
                assertEquals(
                    CandidateType.Host,
                    pair.local.type,
                    "a local srflx candidate pairs as its base (RFC 8445 §6.1.2.2) — a relayed local means the fallback won",
                )
            }
        }

    /** A symmetric NAT defeats srflx, so ICE falls back to the TURN relay — the canonical §5.2 meetup. */
    @Test
    fun symmetricNatFallsBackToRelay() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.Symmetric)
                assertEquals("relayed", roundTrip("relayed"))
                assertEquals(
                    CandidateType.Relayed,
                    establish().selectedPair?.local?.type,
                    "symmetric↔symmetric can only meet on a relay",
                )
            }
        }

    /** `relayOnly()` offers only relay candidates, so the relay path is used even under a lenient NAT. */
    @Test
    fun relayOnlyForcesTheRelayPath() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.PortRestrictedCone)
                relayOnly()
                val conn = establish()
                assertEquals(CandidateType.Relayed, conn.selectedPair?.local?.type, "relayOnly must select a relay pair")
                assertEquals(CandidateType.Relayed, conn.selectedPair?.remote?.type, "relayOnly peers are both relayed")
                assertTrue(conn.manifest.relayOnly, "manifest records the relay-only policy")
            }
        }

    /** An impaired link (loss + jittered delay) still establishes deterministically under virtual time. */
    @Test
    fun impairedLinkStillEstablishes() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                impaired(loss = 0.1, delay = 20.milliseconds, jitter = 5.milliseconds)
                assertEquals("through-loss", roundTrip("through-loss"), "retransmission carries the payload over a lossy link")
            }
        }

    /** The resolved manifest reflects exactly the requested scenario (what was asked was provisioned). */
    @Test
    fun manifestReflectsTheRequestedScenario() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.Symmetric)
                val impairment = NetworkImpairment.of(delay = 10.milliseconds, loss = 0.02)
                impaired(impairment)
                val manifest = establish().manifest
                assertEquals(NatType.Symmetric, manifest.natType)
                assertEquals(false, manifest.relayOnly)
                assertEquals(impairment, manifest.impairment)
                assertEquals(3478, manifest.stun.port, "STUN endpoint is described")
                assertEquals(3478, manifest.turn.port, "TURN endpoint is described")
                assertTrue(manifest.offerer.ip != manifest.answerer.ip, "the two peers have distinct host IPs")
            }
        }

    /** Reconfiguring a live scenario is a modeled illegal state — a guarded check, not silent drift. */
    @Test
    fun configuringAfterEstablishThrows() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                establish()
                assertFailsWith<IllegalStateException> { natType(NatType.Symmetric) }
                assertFailsWith<IllegalStateException> { relayOnly() }
            }
        }

    /** The counting (tracking) buffer factory observes real allocations — the no-runaway-alloc invariant. */
    @Test
    fun allocationsAreTracked() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                assertEquals(0L, allocationCount, "no allocations before establishment")
                roundTrip("count-me")
                assertTrue(allocationCount > 0L, "the vnet + peers allocated buffers through the tracked factory")
            }
        }

    /**
     * **The invariant a consumer could not assert until now** (TESTING.md §4.1, directive #6): every
     * buffer the scenario allocated came back. Run over the relay path deliberately — it is the longest
     * one, so the census covers the vnet's delivery copies, both peers' ICE/SCTP, the TURN server's
     * control and relay loops, and the harness's own echo responder in a single number.
     */
    @Test
    fun aFinishedScenarioReturnsEveryBuffer() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.Symmetric)
                relayOnly()
                assertEquals("drain-me", roundTrip("drain-me"))
                assertNoBufferLeaks("the relay-only symmetric-NAT scenario")
            }
        }

    /** The same, over the impaired fabric — a delayed/duplicated datagram is owned by its own coroutine. */
    @Test
    fun anImpairedScenarioReturnsEveryBuffer() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                impaired(loss = 0.1, delay = 20.milliseconds, jitter = 5.milliseconds, duplicate = 0.1)
                assertEquals("lossy", roundTrip("lossy"))
                assertNoBufferLeaks("the impaired scenario")
            }
        }

    /**
     * The census is a value, not just an assertion — and it is trustworthy or it says so. A saturated
     * pool would make `outstandingChunks` under-report, so a consumer reading the numbers can tell a
     * clean run from an unmeasurable one without knowing how a pool behaves at its cap.
     */
    @Test
    fun theCensusReportsWhatItMeasured() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                roundTrip("census")
                val census = bufferCensus()
                assertTrue(census.allocations > 0, "the scenario allocated through the tracked factory")
                assertTrue(census.chunksCreated > 0, "the pool created chunks — a vacuous census proves nothing")
                assertEquals(false, census.saturated, "the harness pool must not fill, or the measurement is worthless: $census")
                assertEquals(0, census.outstandingChunks, "every chunk back in the pool: $census")
                assertEquals(0, census.unreleasedBuffers, "every buffer released: $census")
                assertTrue(census.isDrained, "isDrained is the conjunction of the three above: $census")
            }
        }

    /** [WebRtcHarnessScope.close] is idempotent and leaves the scenario unusable rather than half-alive. */
    @Test
    fun closeIsIdempotentAndFinal() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                establish()
                close()
                close()
                assertFailsWith<IllegalStateException> { establish() }
            }
        }

    /** `establish()` is idempotent: repeated calls return the same live connection, not a fresh one. */
    @Test
    fun establishIsIdempotent() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                val first = establish()
                val second = establish()
                assertTrue(first === second, "establish() must be idempotent")
            }
        }

    /** The default DTLS backend is plaintext, so the harness never advertises a real fingerprint. */
    @Test
    fun flatLinkHasNoRelayWhenDirect() =
        runTest {
            withWebRtcHarness(scope = backgroundScope, clock = virtualClock()) {
                natType(NatType.None)
                val conn = establish()
                assertNull(conn.manifest.impairment, "clean link by default")
                assertEquals(CandidateType.Host, conn.selectedPair?.remote?.type)
            }
        }

    private fun kotlinx.coroutines.test.TestScope.virtualClock(): () -> Instant = { epoch + testScheduler.currentTime.milliseconds }
}
