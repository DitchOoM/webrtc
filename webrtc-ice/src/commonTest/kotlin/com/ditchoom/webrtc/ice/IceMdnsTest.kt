@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * mDNS **resolve-only** (RFC 8838 privacy candidates; EXECUTION_PLAN §11.4 W3 decision): a peer hides
 * its private IP behind an `<uuid>.local` name, and we must resolve it — via the injected
 * [MdnsResolver] seam, never a hardwired multicast socket — before a check can be sent. Here the
 * resolver is a deterministic stub; the resolved address becomes an ordinary remote host candidate and
 * the session establishes. Advertising *our own* `.local` (the responder) is deferred (RFC §11.4).
 */
@OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class, ExperimentalDatagramApi::class)
class IceMdnsTest {
    @Test
    fun a_dot_local_remote_candidate_is_resolved_and_used() =
        runTest {
            val vnet = Vnets.flat()
            val clock = IceDriver.clockOf { testScheduler.currentTime }
            val alice = IceDriver(IceRole.Controlling, seed = 1, vnet = vnet, scope = backgroundScope, clock = clock)
            val bob = IceDriver(IceRole.Controlled, seed = 2, vnet = vnet, scope = backgroundScope, clock = clock)
            alice.start()
            bob.start()

            val bobHost = bob.bindHost("10.0.0.2", 5000)
            alice.bindHost("10.0.0.1", 4000)

            // Bob advertises `bob.local` instead of its address; the resolver maps it back (resolve-only).
            val resolver = MdnsResolver { name -> if (name == "bob.local") vnetAddress("10.0.0.2", 5000) else null }
            val resolved = resolver.resolve("bob.local")
            assertNotNull(resolved, "the injected resolver resolves the .local name")

            alice.post(IceEvent.SetRemoteCredentials(bob.agent.localCredentials))
            alice.post(IceEvent.AddRemoteCandidate(IceCandidate.host(resolved.toTransportAddress())))
            bob.connectTo(alice)

            assertNotNull(withTimeoutOrNull(TIMEOUT) { alice.awaitConnected() }, "Alice connects to the resolved candidate")
            assertEquals(bobHost.address, alice.selectedPair!!.remote.address, "the selected remote is Bob's resolved host address")
        }

    private companion object {
        val TIMEOUT = 30.seconds
    }
}
