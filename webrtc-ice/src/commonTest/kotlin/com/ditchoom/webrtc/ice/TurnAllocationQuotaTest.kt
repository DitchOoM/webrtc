@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.Meetup
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.ip
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **486 Allocation Quota Reached** (RFC 8656 §7.2, §18) — the refusal a TURN server gives when a
 * username has spent its concurrent-allocation budget.
 *
 * It had no fixture anywhere, and the reason is worth naming because it is not "nobody got to it":
 * coturn's quota is **unlimited by default**, so no lane of the container harness could ever provoke
 * one, and the code path lived in `TurnAllocation`'s KDoc as a parenthetical. That is now closed from
 * both ends — `test-harness`'s `turn-quota` lane sets `user-quota=1` on real coturn, and this is its
 * deterministic L1 mirror (TESTING.md's L1↔L2 parity rule: interop finds bugs, the vnet owns the
 * regression).
 *
 * What matters about 486 is not that it is an error — it is *which* error, and that it stays one:
 *
 * - It arrives as [TurnAllocationResult.Unavailable.Rejected] carrying the server's own
 *   [com.ditchoom.webrtc.stun.StunErrorCode], **not** as [TurnAllocationResult.Unavailable.NoResponse].
 *   A quota refusal and an unreachable relay send an operator in opposite directions, and a nullable
 *   "no relay candidate" made them identical.
 * - It is **non-fatal to gathering**: `gatherRelay` answers a sealed
 *   [RelayGatheringResult.Unavailable] and the driver carries on, so a peer whose relay is refused
 *   still offers its host and server-reflexive candidates.
 */
class TurnAllocationQuotaTest {
    /**
     * A server holding its one permitted allocation refuses the next client 486, and the client reports
     * the code rather than silence.
     *
     * Anti-vacuity in three parts, because "the second allocation failed" is cheap to satisfy by
     * accident: the FIRST allocation must succeed (so the refusal is the quota and not a broken server),
     * the server must record exactly one quota refusal (so the second client was refused for *this*
     * reason and not, say, a bad credential), and the code carried up to the caller must be 486.
     */
    @Test
    fun a_second_allocation_is_refused_486_and_the_code_reaches_the_caller() =
        runTest {
            val meetup =
                Vnets.meetup(
                    backgroundScope,
                    profileA = NatProfile.Symmetric,
                    profileB = NatProfile.Symmetric,
                    turnAllocationQuota = 1,
                )

            val first = allocationOn(meetup.aliceHost.ip, port = 5100, meetup)
            assertIs<TurnAllocationResult.Allocated>(
                withTimeoutOrNull(TIMEOUT) { first.allocate() },
                "the first allocation must succeed, or the refusal below is not a quota refusal",
            )

            val second = allocationOn(meetup.bobHost.ip, port = 5200, meetup)
            val refused =
                assertIs<TurnAllocationResult.Unavailable.Rejected>(
                    withTimeoutOrNull(TIMEOUT) { second.allocate() },
                    "the second allocation must be REJECTED — a quota refusal is an answer, not silence",
                )

            assertEquals(QUOTA_REACHED, refused.error.code, "the server's own code reaches the caller")
            assertEquals(1, meetup.turn.quotaRefusals, "the server refused exactly one Allocate for quota")

            first.close()
            second.close()
            advanceUntilIdle()
        }

    /**
     * Gathering **continues** past a refused relay: the driver answers a typed
     * [RelayGatheringResult.Unavailable] and the host candidate it already gathered stands. This is the
     * property the `turn-quota` harness lane asserts end-to-end (both peers establish anyway, over
     * host/srflx); here it is asserted at the seam that decides it.
     *
     * The buffer census rides along because a refusal is the *shortest* path through the exchange
     * machinery — one 401 challenge, one refused retry, no relayed address — and therefore the easiest
     * one to leave a response unreleased on.
     */
    @Test
    fun a_quota_refusal_leaves_gathering_alive_and_gives_every_buffer_back() =
        runTest {
            val received = LeakTrackingFactory()
            val meetup =
                Vnets.meetup(
                    backgroundScope,
                    profileA = NatProfile.Symmetric,
                    profileB = NatProfile.Symmetric,
                    turnAllocationQuota = 1,
                )
            // Spend the server's only allocation before the driver ever asks for one.
            val incumbent = allocationOn(meetup.aliceHost.ip, port = 5100, meetup)
            assertIs<TurnAllocationResult.Allocated>(withTimeoutOrNull(TIMEOUT) { incumbent.allocate() })

            val driver =
                IceAgentDriver(
                    role = IceRole.Controlling,
                    random = Random(0x486),
                    binder = DatagramBinder { meetup.vnet.bind(it, bufferFactory = received) },
                    scope = backgroundScope,
                    clock = { EPOCH + testScheduler.currentTime.milliseconds },
                    config = IceConfig(bufferFactory = LeakTrackingFactory()),
                )
            driver.start()
            driver.gatherHost(meetup.bobHost.ip, meetup.bobHost.port)

            val relay =
                assertIs<RelayGatheringResult.Unavailable>(
                    withTimeoutOrNull(TIMEOUT) {
                        driver.gatherRelay(meetup.turnAddress, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, meetup.bobHost.ip, 5200)
                    },
                    "a quota-refused relay is Unavailable, never a thrown exception",
                )
            val rejected = assertIs<TurnAllocationResult.Unavailable.Rejected>(relay.cause, "and the cause is the server's refusal")
            assertEquals(QUOTA_REACHED, rejected.error.code)

            assertTrue(
                driver.localCandidates.any { it is IceCandidate.Host },
                "the host candidate gathered before the refusal must survive it — a refused relay is not a failed gather",
            )
            assertTrue(
                driver.localCandidates.none { it is IceCandidate.Relayed },
                "and no relay candidate may be offered for an allocation the server refused",
            )

            incumbent.close()
            driver.close()
            advanceUntilIdle()
            received.assertNoLeaks("the datagrams a quota-refused gather received")
            received.assertPoolDrained("the datagrams a quota-refused gather received")
        }

    private fun kotlinx.coroutines.test.TestScope.allocationOn(
        ip: String,
        port: Int,
        meetup: Meetup,
    ): TurnAllocation =
        TurnAllocation(
            underlying = meetup.vnet.bind(vnetAddress(ip, port)),
            server = meetup.turnAddress,
            username = Vnets.TURN_USERNAME,
            password = Vnets.TURN_PASSWORD,
            random = Random(port.toLong()),
            scope = backgroundScope,
        )

    private companion object {
        val EPOCH: Instant = Instant.fromEpochSeconds(0)
        val TIMEOUT = 30.seconds
        const val QUOTA_REACHED = 486
    }
}
