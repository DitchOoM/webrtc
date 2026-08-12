@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramSendOptions
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.TurnServer
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * [TurnAllocation.maxWritableSize] must reserve what a Send indication actually costs on the wire, and
 * that cost **depends on the address family**: XOR-PEER-ADDRESS carries the peer's transport address, 4
 * bytes of it for IPv4 and 16 for IPv6 (RFC 8656 §12.1, RFC 8489 §14).
 *
 * It used to be one fixed `TURN_OVERHEAD_BYTES = 40`, which is the IPv4 figure. On an IPv6 allocation
 * that under-reserved by 12 bytes, so a caller writing exactly `maxWritableSize` — which is precisely
 * what a caller sizing to the ceiling does — built a datagram 12 bytes past the underlying channel's
 * own limit. Nothing caught it because nothing tested it: no fixture in either repo asserted
 * `TURN_OVERHEAD_BYTES` or `TurnAllocation.maxWritableSize`, so the constant was free to be wrong.
 *
 * These assert against the **encoded indication**, not against a restated constant. The underlying
 * channel is wrapped in a [CeilingRecorder] that both declares a small [maxWritableSize] (so the
 * reserve is proven relative to the channel's ceiling rather than to a hardcoded MTU) and records how
 * large the datagram `TurnAllocation` actually handed down. A test that recomputed 36 + padding would
 * pass against the bug it is here to prevent.
 */
class TurnRelayOverheadTest {
    @Test
    fun a_v4_relay_reserves_what_a_send_indication_costs() =
        runTest {
            val relay =
                relayOverV4(
                    client = vnetAddress("192.0.2.10", 40000),
                    peer = vnetAddress("198.51.100.7", 50000),
                )

            val onWire = relay.sendAtCeiling()
            assertTrue(
                onWire <= CHANNEL_CEILING,
                "a payload of exactly maxWritableSize must encode within the channel's own ceiling, " +
                    "but the Send indication came to $onWire bytes against a $CHANNEL_CEILING ceiling",
            )
            assertTrue(
                onWire >= CHANNEL_CEILING - STUN_ATTRIBUTE_PADDING,
                "the reserve must be tight, not merely safe: it left ${CHANNEL_CEILING - onWire} bytes " +
                    "unused, more than the $STUN_ATTRIBUTE_PADDING bytes STUN attribute padding can explain",
            )
        }

    /**
     * The v6 case, in two legs. The first is the fix; the second **restores the bug** — a payload sized
     * by the old 40-byte reserve, sent over the same allocation, must overrun the ceiling. Without that
     * leg the first assertion passes just as happily against the old constant on a v4 allocation, and
     * the regression this file exists for goes unpinned.
     */
    @Test
    fun a_v6_relay_reserves_the_twelve_extra_bytes_its_peer_address_costs() =
        runTest {
            val relay =
                relayOverV6(
                    client = vnetAddress("fd00:31::100", 40000),
                    peer = vnetAddress("fd00:32::100", 50000),
                )

            val onWire = relay.sendAtCeiling()
            assertTrue(
                onWire <= CHANNEL_CEILING,
                "a v6 peer address costs 12 bytes more in XOR-PEER-ADDRESS, and maxWritableSize must " +
                    "hold that back too — the indication came to $onWire bytes against a $CHANNEL_CEILING ceiling",
            )

            val underOldReserve = relay.sendReserving(OLD_FIXED_RESERVE_BYTES)
            assertTrue(
                underOldReserve > CHANNEL_CEILING,
                "restore-the-bug leg is vacuous: sizing by the old fixed $OLD_FIXED_RESERVE_BYTES-byte " +
                    "reserve produced $underOldReserve bytes, which did NOT overrun the $CHANNEL_CEILING " +
                    "ceiling — so this test would have passed against the defect it guards",
            )
        }

    // ── fixtures ──

    private suspend fun TestScope.relayOverV4(
        client: SocketAddress,
        peer: SocketAddress,
    ) = relay(Vnets.TURN_SERVER_ADDRESS, client, peer)

    private suspend fun TestScope.relayOverV6(
        client: SocketAddress,
        peer: SocketAddress,
    ) = relay(Vnets.TURN_SERVER_ADDRESS_V6, client, peer)

    /**
     * A live allocation on a flat vnet, its underlying channel wrapped so the encoded indication can be
     * measured. Flat (no NAT) on purpose: the question here is the size of a datagram, not whether it
     * traverses.
     */
    private suspend fun TestScope.relay(
        server: SocketAddress,
        client: SocketAddress,
        peer: SocketAddress,
    ): Relay {
        val vnet = Vnets.flat()
        TurnServer(
            address = server,
            vnet = vnet,
            scope = backgroundScope,
            keyProvider = Vnets.turnKeyProvider(),
        ).start()

        val recorder = CeilingRecorder(vnet.bind(client), CHANNEL_CEILING)
        val allocation =
            TurnAllocation(recorder, server, Vnets.TURN_USERNAME, Vnets.TURN_PASSWORD, Random(0x0BAD), backgroundScope)
        assertIs<TurnAllocationResult.Allocated>(
            allocation.allocate(),
            "the fixture needs a live allocation before maxWritableSize means anything",
        )
        return Relay(allocation, recorder, peer)
    }

    private class Relay(
        private val allocation: TurnAllocation,
        private val recorder: CeilingRecorder,
        private val peer: SocketAddress,
    ) {
        /** Relay a payload of exactly [TurnAllocation.maxWritableSize]; answer the encoded wire size. */
        suspend fun sendAtCeiling(): Int = relay(allocation.maxWritableSize)

        /** Relay a payload sized by an arbitrary [reserve] off the ceiling; answer the encoded size. */
        suspend fun sendReserving(reserve: Int): Int = relay(CHANNEL_CEILING - reserve)

        private suspend fun relay(payloadBytes: Int): Int {
            recorder.forget()
            allocation.send(payloadOf(payloadBytes), to = peer)
            return recorder.largestSent
        }
    }

    /**
     * Declares a small [maxWritableSize] and records the largest datagram sent through it. Both halves
     * matter: the ceiling makes the reserve measurable against the *channel's* limit rather than a
     * 65507-byte vnet default, and the recording is what turns "the reserve is 39" into "the datagram
     * fits".
     */
    private class CeilingRecorder(
        private val inner: AddressedDatagramChannel,
        override val maxWritableSize: Int,
    ) : AddressedDatagramChannel by inner {
        var largestSent: Int = 0
            private set

        /** Drop the tally so the next relayed datagram is measured on its own, not against a prior one. */
        fun forget() {
            largestSent = 0
        }

        override suspend fun send(
            payload: ReadBuffer,
            to: SocketAddress,
            options: DatagramSendOptions,
        ) {
            largestSent = maxOf(largestSent, payload.remaining())
            inner.send(payload, to, options)
        }
    }

    private companion object {
        /**
         * The channel ceiling the fixture declares. Small enough to keep the buffers cheap, and NOT a
         * multiple of 4 — STUN pads a DATA value onto a 32-bit boundary, so a ceiling that happened to
         * align would hide whether the padding was reserved at all.
         */
        const val CHANNEL_CEILING = 1201

        /** RFC 8489 §14: an attribute value is padded onto a 32-bit boundary, so up to 3 bytes. */
        const val STUN_ATTRIBUTE_PADDING = 3

        /** The single fixed reserve this replaced — the IPv4 figure, applied to every family. */
        const val OLD_FIXED_RESERVE_BYTES = 40

        fun payloadOf(bytes: Int): ReadBuffer {
            val buffer = BufferFactory.Default.allocate(bytes)
            repeat(bytes) { buffer.writeByte(0x2A.toByte()) }
            buffer.resetForRead()
            return buffer
        }
    }
}
