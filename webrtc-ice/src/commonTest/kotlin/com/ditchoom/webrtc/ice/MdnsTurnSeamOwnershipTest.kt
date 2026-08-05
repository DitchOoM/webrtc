@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.LeakTrackingFactory
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.utf8Buffer
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.IpAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * **The two `webrtc-ice` control-plane loops that were still holding memory**, each gated at zero
 * outstanding chunks rather than at zero missed frees.
 *
 * These are the last two seams below the ICE data path. The data path itself was closed by #155/#157 and
 * is covered by [ReceivedDatagramOwnershipTest]; what is left here is the *control* plane, where a buffer
 * is allocated per query, per answer or per relayed datagram — so a leak is proportional to session
 * length, not to session count, which is the shape that actually exhausts a `deterministic()` heap on
 * Kotlin/Native Linux.
 *
 * Both cases are about a buffer whose reader **never runs**, which is why neither showed up in an
 * ordinary round-trip fixture:
 *
 * - `MdnsResponder.serve` hands its answer back for observation (`serveOne` deliberately does not
 *   release, so a caller can look at what it just sent) and then dropped it. The two-way [MdnsEndpoint]
 *   already released it; the standalone driver did not, and a responder answers for as long as it is up.
 * - `TurnAllocation` decapsulates every Data indication into a buffer of its own and queues it on an
 *   UNLIMITED channel. Closing a channel does not release what is sitting in it, and a relay is torn
 *   down mid-flight all the time — a superseded ICE generation retires its relay socket while the peer
 *   is still sending. Every queued payload was a buffer whose reader would now never run.
 *
 * `assertPoolDrained` in both, not just `assertNoLeaks`: the weaker probe is blind to a refcount that
 * never reached zero, and it is the one that names *which* buffer, so both are asserted, weaker first.
 */
class MdnsTurnSeamOwnershipTest {
    @Test
    fun the_standalone_mdns_responder_returns_every_answer_it_sends() =
        runTest {
            val answers = LeakTrackingFactory()
            val vnet = Vnets.flat()
            val responder = MdnsResponder(answers)
            responder.advertise(OUR_NAME, OUR_IP)
            val socket = vnet.bind(RESPONDER)
            backgroundScope.launch { responder.serve(socket, GROUP) }

            // Several, because one answer released by luck and one released by rule look identical: a
            // per-answer leak is only distinguishable from a fixture artefact once the count can grow.
            // The querier allocates from the DEFAULT factory, not from `answers`: pointing one tracker at
            // both sides attributes the harness's own questions to the code under test, which is how this
            // harness first reported "5 of 10 leaked" while the responder was already correct.
            val querier = vnet.bind(vnetAddress(QUERIER_IP, QUERIER_PORT))
            repeat(ANSWERS) {
                val question = MdnsMessage.encodeQuery(OUR_NAME.value, MdnsMessage.TYPE_A, BufferFactory.Default)
                querier.send(question, to = RESPONDER)
                question.releaseAfterSend()
                val reply = withTimeoutOrNull(WATCHDOG) { querier.receive() }
                assertIs<DatagramReadResult.Received>(reply, "the responder answered query #$it")
                reply.datagram.payload.releaseReceived()
            }
            socket.close()
            // The loop is parked in `receive`; closing it lets the iteration finish and its `finally` run.
            // Measuring before that reports a confident wrong number — a cancelled coroutine's `finally`
            // needs a dispatch, and `advanceUntilIdle()` alone has not been enough here before.
            delay(SETTLE)
            testScheduler.advanceUntilIdle()

            answers.assertNoLeaks("the standalone mDNS responder's answers")
            answers.assertPoolDrained("the standalone mDNS responder's answers")
        }

    @Test
    fun a_relay_torn_down_with_data_still_queued_returns_every_decapsulated_payload() =
        runTest {
            val relayed = LeakTrackingFactory()
            val meetup = Vnets.meetup(backgroundScope)
            val alice =
                TurnAllocation(
                    underlying = meetup.vnet.bind(meetup.aliceHost),
                    server = meetup.turnAddress,
                    username = Vnets.TURN_USERNAME,
                    password = Vnets.TURN_PASSWORD,
                    random = Random(0x159),
                    scope = backgroundScope,
                    bufferFactory = relayed,
                )
            val bobAddress = vnetAddress(BOB_IP, BOB_PORT)
            val bob = meetup.vnet.bind(bobAddress)
            assertIs<TurnAllocationResult.Allocated>(withTimeoutOrNull(WATCHDOG) { alice.allocate() }, "the relay allocated")

            // One round trip first, so the permission exists and Bob knows the relayed address to answer.
            alice.send(utf8Buffer("hello"), to = bobAddress)
            val atBob = withTimeoutOrNull(WATCHDOG) { bob.receive() }
            assertIs<DatagramReadResult.Received>(atBob, "the relay carried the outbound leg")
            val relayAddress = atBob.datagram.peer
            atBob.datagram.payload.releaseReceived()

            // Now Bob keeps sending and **nobody calls `alice.receive()`**, so every decapsulated payload
            // piles up in the UNLIMITED inbound channel. That queue is the thing under test: it is exactly
            // what a relay retired mid-flight is holding.
            repeat(QUEUED) { bob.send(utf8Buffer("queued-$it"), to = relayAddress) }
            delay(SETTLE)
            testScheduler.advanceUntilIdle()
            assertTrue(relayed.allocations > QUEUED, "the fixture must have queued payloads to strand, got ${relayed.allocations}")

            alice.close()
            delay(SETTLE) // the deallocating Refresh rides a coroutine; `releaseTransport` runs in its finally
            testScheduler.advanceUntilIdle()

            relayed.assertNoLeaks("a relay torn down with data queued")
            relayed.assertPoolDrained("a relay torn down with data queued")
        }

    private companion object {
        val RESPONDER: SocketAddress = vnetAddress("192.168.7.2", MDNS_UDP_PORT)
        val GROUP: SocketAddress = vnetAddress("224.0.0.251", MDNS_UDP_PORT)
        const val QUERIER_IP = "192.168.7.3"
        const val QUERIER_PORT = 51000
        const val BOB_IP = "203.0.113.50" // an ordinary endpoint on the PUBLIC segment, as the refresh fixture uses
        const val BOB_PORT = 6000
        val OUR_NAME = MdnsHostName("3f1a9c22-0000-4000-8000-000000000001.local")
        val OUR_IP: IpAddress = IpAddress.V4(0xC0A80702u) // 192.168.7.2
        const val ANSWERS = 5
        const val QUEUED = 8
        val WATCHDOG = 5.seconds
        val SETTLE = 250.milliseconds
    }
}
