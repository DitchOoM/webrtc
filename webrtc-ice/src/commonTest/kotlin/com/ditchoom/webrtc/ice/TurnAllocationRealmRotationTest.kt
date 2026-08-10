@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.Meetup
import com.ditchoom.webrtc.ice.vnet.NatProfile
import com.ditchoom.webrtc.ice.vnet.RealmPolicy
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.ip
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * **A realm that changes underneath a live allocation** — the last TURN behaviour in `TurnAllocation`
 * with no fixture anywhere, and the one whose absence was least visible.
 *
 * `requestWithChallengeRetry` already adopts the challenge's REALM and re-derives the long-term key
 * through `asChallenge()`. Every existing TURN fixture, though, runs a server whose realm is a `val`
 * fixed for its whole life, so the re-derivation has only ever been exercised with the realm it already
 * had. Under that setup a client that cached its key — deriving once at the first 401 and reusing it
 * forever — passes every test in the corpus. The re-derivation was implemented, asserted nowhere, and
 * one refactor away from silently becoming a no-op.
 *
 * ## Why a rotated realm is a different event from a rotated nonce
 *
 * They look alike on the wire and are not alike at all. The NONCE is opaque: surviving a 438 means
 * copying a string back, and [TurnAllocationRefreshTest] already proves the client does. The REALM is an
 * **input to the key** (RFC 8489 §9.2.2 — `HMAC(MD5(username:realm:password), …)`), so a server that
 * answers with a new realm has invalidated every key the client holds. The failure mode this catches is
 * specific and nasty: a client that copies the new realm into its attributes but keeps signing with the
 * old key presents *correct-looking* credentials that authenticate against nothing, failing in the shape
 * of a wrong password rather than a stale challenge.
 *
 * ## What the server does here
 *
 * [RealmPolicy.RotateAfter] replaces the realm once, after a given number of granted requests, and the
 * vnet server's `keyProvider` is keyed on `(username, realm)` — so after the rotation the server verifies
 * against `MD5(user:vnet-rotated:pass)` while the client is still holding `MD5(user:vnet:pass)`. That is
 * what makes this non-vacuous rather than a rename: a provider closing over one fixed realm would agree
 * with a cached-key client and the fixture would pass no matter what the client did.
 *
 * The client's next request is therefore refused **401 Unauthorized** carrying the new realm — not 438,
 * because the credentials genuinely are invalid now — and a correct client answers it by re-deriving,
 * which is exactly the branch `isStaleChallenge()` admits 401 for.
 *
 * L1↔L2 parity note (TESTING.md §4): this has no container lane and is not expected to grow one. coturn
 * reads `realm` at startup, so rotating it against real coturn means restarting the process, which drops
 * every allocation and destroys the property under test — the rotation must outlive the allocation to
 * mean anything. This is the deterministic side of a behaviour whose real-server side needs a provider
 * that rotates realms on a live server; the client half is fully owned here regardless.
 */
class TurnAllocationRealmRotationTest {
    /**
     * The allocation survives a realm rotation, and survives it by **re-deriving the key**.
     *
     * Anti-vacuity is carried by three independent assertions, because "the refresh succeeded" is cheap
     * to satisfy by accident: the server must actually have rotated (`realmRotations == 1` — a server
     * that never rotated would pass every other assertion here), the client must actually have been
     * refused under the dead realm (`staleRealmChallenges >= 1` — proving the rotation landed *on* the
     * client rather than between its requests), and Refreshes must have been granted **after** the
     * rotation, which is only possible with a key derived from the new realm.
     */
    @Test
    fun a_refresh_survives_a_realm_rotation_by_re_deriving_the_long_term_key() =
        runTest {
            val meetup =
                Vnets.meetup(
                    backgroundScope,
                    profileA = NatProfile.Symmetric,
                    profileB = NatProfile.Symmetric,
                    // Compressed from coturn's 600 s purely so several Refreshes land inside the fixture;
                    // the client refreshes at a fraction of the GRANTED lifetime, so every ratio it
                    // reasons about is unchanged.
                    turnLifetimeSeconds = ALLOCATION_LIFETIME_SECONDS,
                    // After the Allocate exchange has been granted, so the rotation lands on a live
                    // allocation's keep-alive rather than on its creation — a realm that changed before
                    // the allocation existed would only re-test the initial 401 handshake.
                    turnRealmPolicy = RealmPolicy.RotateAfter(afterRequests = ROTATE_AFTER),
                )

            val allocation = allocationOn(meetup.aliceHost.ip, port = 5100, meetup)
            assertIs<TurnAllocationResult.Allocated>(
                withTimeoutOrNull(TIMEOUT) { allocation.allocate() },
                "the allocation must be granted under the ORIGINAL realm, or there is no rotation to survive",
            )
            assertEquals(0, meetup.turn.realmRotations, "the realm must still be the original one at this point")

            // Long enough for several refresh cycles to cross the rotation. The client refreshes at a
            // fraction of the granted lifetime, so this spans multiple keep-alives either side of it.
            advanceTimeBy(SESSION)
            advanceUntilIdle()

            assertEquals(1, meetup.turn.realmRotations, "the server must have rotated its realm exactly once")
            assertTrue(
                meetup.turn.staleRealmChallenges >= 1,
                "the client must have been refused at least once while signing under the dead realm — " +
                    "otherwise the rotation never landed on it and nothing was re-derived, got " +
                    "${meetup.turn.staleRealmChallenges}",
            )

            val refreshesAcrossRotation = meetup.turn.refreshes
            assertTrue(
                refreshesAcrossRotation >= MIN_REFRESHES,
                "Refreshes must have been GRANTED after the rotation, which is only possible with a key " +
                    "derived from the new realm, got $refreshesAcrossRotation",
            )

            // And the allocation is still usable rather than merely un-erroring: one more granted Refresh
            // after everything above, under the rotated realm.
            advanceTimeBy(SESSION)
            advanceUntilIdle()
            assertTrue(
                meetup.turn.refreshes > refreshesAcrossRotation,
                "the allocation must keep refreshing indefinitely under the new realm, not merely recover once",
            )

            allocation.close()
            advanceUntilIdle()
        }

    /**
     * The rotation exchange gives every buffer back.
     *
     * It earns its own assertion because it is a shape the corpus has been bitten by before: the refused
     * response is decoded, read for its REALM/NONCE, and then **discarded** in favour of a retry, so it
     * is a decode whose result nobody returns — the documented signature of a missing release. The
     * `first.release()` on that branch of `requestWithChallengeRetry` is exactly what this pins.
     */
    @Test
    fun a_realm_rotation_gives_every_buffer_back() =
        runTest {
            val received = LeakTrackingFactory()
            val meetup =
                Vnets.meetup(
                    backgroundScope,
                    profileA = NatProfile.Symmetric,
                    profileB = NatProfile.Symmetric,
                    turnLifetimeSeconds = ALLOCATION_LIFETIME_SECONDS,
                    turnRealmPolicy = RealmPolicy.RotateAfter(afterRequests = ROTATE_AFTER),
                )

            val allocation =
                TurnAllocation(
                    underlying = meetup.vnet.bind(vnetAddress(meetup.aliceHost.ip, 5100), bufferFactory = received),
                    server = meetup.turnAddress,
                    username = Vnets.TURN_USERNAME,
                    password = Vnets.TURN_PASSWORD,
                    random = Random(0x5EA1),
                    scope = backgroundScope,
                )
            assertIs<TurnAllocationResult.Allocated>(withTimeoutOrNull(TIMEOUT) { allocation.allocate() })

            advanceTimeBy(SESSION)
            advanceUntilIdle()
            assertEquals(1, meetup.turn.realmRotations, "the census is meaningless if the rotation never happened")
            assertTrue(meetup.turn.staleRealmChallenges >= 1, "and meaningless if the client was never refused under it")

            allocation.close()
            advanceUntilIdle()
            received.assertNoLeaks("the datagrams a realm-rotating session received")
            received.assertPoolDrained("the datagrams a realm-rotating session received")
        }

    private fun TestScope.allocationOn(
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
        val TIMEOUT = 30.seconds

        /** Compressed from coturn's 600 s so several keep-alives fit inside the fixture. */
        const val ALLOCATION_LIFETIME_SECONDS: UInt = 60u

        /**
         * The Allocate exchange costs two granted requests (the challenged retry, then the Allocate
         * itself), so rotating after three lands the change on the first Refresh rather than on the
         * allocation's creation.
         */
        const val ROTATE_AFTER = 3

        /** Several allocation lifetimes, so refreshes fall on both sides of the rotation. */
        val SESSION = 300.seconds

        /** Refresh fires at a fraction of a 60 s lifetime, so a 300 s session grants several. */
        const val MIN_REFRESHES = 3
    }
}
