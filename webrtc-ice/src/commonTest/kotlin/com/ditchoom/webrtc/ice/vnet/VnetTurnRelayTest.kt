@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.Datagram
import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.toSocketAddress
import com.ditchoom.webrtc.ice.toTransportAddress
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.asXorMappedAddress
import com.ditchoom.webrtc.stun.ofRequestedTransport
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The canonical **dual-symmetric-NAT → relay** path (RFC §5.2), proven at the vnet layer before ICE
 * rides it: two peers each behind a symmetric NAT cannot reach one another directly (their srflx
 * mappings are per-destination and mutually filtered), so they meet on the [TurnServer]. This drives a
 * faithful TURN client inline — authed Allocate, CreatePermission, and Send/Data relaying — so the
 * whole relay machine (and the short-term-credential MESSAGE-INTEGRITY) is exercised end to end under
 * `runTest` virtual time. The ICE agent's real TURN client (step 4) automates exactly this exchange.
 */
@OptIn(ExperimentalDatagramApi::class)
class VnetTurnRelayTest {
    private fun key() = utf8Buffer(Vnets.TURN_PASSWORD)

    @Test
    fun symmetric_peers_relay_a_round_trip_through_turn() =
        runTest {
            val meetup = Vnets.meetup(backgroundScope, profileA = NatProfile.Symmetric, profileB = NatProfile.Symmetric)
            val alice = meetup.vnet.bind(meetup.aliceHost)
            val bob = meetup.vnet.bind(meetup.bobHost)

            // Direct control: a symmetric peer cannot even reach the other's host address (different LAN).
            alice.send(text("direct?"), to = meetup.bobHost)
            assertNull(bob.receiveWithin(TIMEOUT), "symmetric peers have no direct path — the relay is mandatory")

            val aliceRelayed = allocate(alice, meetup.turnAddress)
            val bobRelayed = allocate(bob, meetup.turnAddress)
            assertNotNull(aliceRelayed, "Alice obtains a relayed transport address")
            assertNotNull(bobRelayed, "Bob obtains a relayed transport address")

            createPermission(alice, meetup.turnAddress, bobRelayed)
            createPermission(bob, meetup.turnAddress, aliceRelayed)

            // Alice → Bob over the relay.
            sendIndication(alice, meetup.turnAddress, peer = bobRelayed, data = "hello over the relay")
            val atBob = bob.receiveData(TIMEOUT)
            assertNotNull(atBob, "Bob receives the relayed datagram as a Data indication")
            assertEquals("hello over the relay", atBob.second, "relayed payload intact")
            assertEquals(aliceRelayed, atBob.first, "Bob sees Alice's relayed address as the peer")

            // Bob → Alice back over the relay.
            sendIndication(bob, meetup.turnAddress, peer = aliceRelayed, data = "and back again")
            val atAlice = alice.receiveData(TIMEOUT)
            assertNotNull(atAlice, "Alice receives Bob's reply over the relay")
            assertEquals("and back again", atAlice.second, "return payload intact")
        }

    @Test
    fun allocate_without_auth_is_challenged_401() =
        runTest {
            val meetup = Vnets.meetup(backgroundScope)
            val alice = meetup.vnet.bind(meetup.aliceHost)

            val txid = TransactionId.random(Random(1))
            val unauthenticated =
                StunMessageBuilder
                    .of(StunClass.Request, StunMethod.Allocate, txid)
                    .add(RawAttribute.ofRequestedTransport())
                    .encode()
            alice.send(unauthenticated, to = meetup.turnAddress)

            val response = alice.receiveStun(TIMEOUT)
            assertNotNull(response, "the server answers an unauthenticated Allocate")
            assertEquals(StunClass.ErrorResponse, response.messageType.stunClass, "with an error response")
            assertNotNull(response.firstOrNull(StunAttributeType.Realm), "carrying a REALM for the long-term challenge")
            assertNotNull(response.firstOrNull(StunAttributeType.Nonce), "and a NONCE")
        }

    // ---- an inline TURN client, the pattern the ICE relay driver automates in step 4 --------------

    private suspend fun allocate(
        client: DatagramChannel,
        turn: SocketAddress,
    ): SocketAddress? {
        val txid = TransactionId.random(Random(client.hashCode().toLong()))
        val request =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.Allocate, txid)
                .add(RawAttribute.ofText(StunAttributeType.Username, Vnets.TURN_USERNAME))
                .add(RawAttribute.ofRequestedTransport())
                .addMessageIntegrity(key())
                .encode()
        client.send(request, to = turn)
        val response = client.receiveStun(TIMEOUT) ?: return null
        return response
            .firstOrNull(StunAttributeType.XorRelayedAddress)
            ?.asXorMappedAddress(response.transactionId)
            ?.toSocketAddress()
    }

    private suspend fun createPermission(
        client: DatagramChannel,
        turn: SocketAddress,
        peer: SocketAddress,
    ) {
        val txid = TransactionId.random(Random(peer.hashCode().toLong()))
        val request =
            StunMessageBuilder
                .of(StunClass.Request, StunMethod.CreatePermission, txid)
                .add(RawAttribute.ofText(StunAttributeType.Username, Vnets.TURN_USERNAME))
                .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), txid))
                .addMessageIntegrity(key())
                .encode()
        client.send(request, to = turn)
        client.receiveStun(TIMEOUT) // drain the success response
    }

    private suspend fun sendIndication(
        client: DatagramChannel,
        turn: SocketAddress,
        peer: SocketAddress,
        data: String,
    ) {
        val txid = TransactionId.random(Random(data.hashCode().toLong()))
        val indication =
            StunMessageBuilder
                .of(StunClass.Indication, StunMethod.Send, txid)
                .add(RawAttribute.ofXorAddress(StunAttributeType.XorPeerAddress, peer.toTransportAddress(), txid))
                .add(RawAttribute.ofRaw(StunAttributeType.Data, text(data)))
                .encode()
        client.send(indication, to = turn)
    }

    // Receive a Data indication and return (peer, payloadText).
    private suspend fun DatagramChannel.receiveData(within: Duration): Pair<SocketAddress, String>? {
        val message = receiveStun(within) ?: return null
        if (message.messageType.method != StunMethod.Data) return null
        val peer =
            message.firstOrNull(StunAttributeType.XorPeerAddress)?.asXorMappedAddress(message.transactionId)?.toSocketAddress()
                ?: return null
        val data = message.firstOrNull(StunAttributeType.Data)?.value ?: return null
        return peer to data.readString(data.remaining(), Charset.UTF8)
    }

    private suspend fun DatagramChannel.receiveStun(within: Duration): StunMessage? {
        val datagram = receiveWithin(within) ?: return null
        return when (val decoded = StunMessage.decode(datagram.payload)) {
            is StunDecodeResult.Success -> decoded.message
            is StunDecodeResult.Reject -> null
        }
    }

    private suspend fun DatagramChannel.receiveWithin(within: Duration): Datagram? =
        withTimeoutOrNull(within) {
            when (val result = receive()) {
                is DatagramReadResult.Received -> result.datagram
                is DatagramReadResult.Closed -> null
            }
        }

    private fun text(value: String): ReadBuffer = utf8Buffer(value)

    private companion object {
        val TIMEOUT = 2.seconds
    }
}
