@file:OptIn(ExperimentalDatagramApi::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.vnet.CountingBufferFactory
import com.ditchoom.webrtc.ice.vnet.Vnet
import com.ditchoom.webrtc.ice.vnet.Vnets
import com.ditchoom.webrtc.ice.vnet.vnetAddress
import com.ditchoom.webrtc.stun.IpAddress
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The **responder half** of mDNS (issue #88, RFC 6762 §6): we advertise our host candidates as
 * `<uuid>.local` and must answer the peer's queries for those names — and only those.
 *
 * Everything here runs over the in-memory vnet under `runTest`, on the identical `commonMain` [serve] loop
 * production runs over a real multicast socket, so the whole responder is exercised on every target with no
 * OS socket anywhere. The vnet has no multicast, which costs nothing: the shape that matters is the RFC 6762
 * §6.7 **one-shot legacy query** — a querier on an ephemeral port, answered by unicast — because that is
 * exactly what a resolve-only peer (and our own [MulticastMdnsResolver]) sends. The multicast shape is
 * asserted by binding the group address as an ordinary vnet endpoint and watching the response arrive there.
 */
class MdnsResponderTest {
    @Test
    fun answers_a_one_shot_query_for_a_name_it_advertises() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP)

            val answer = assertNotNull(f.ask(OUR_NAME, MdnsMessage.TYPE_A), "the responder answered our own name")
            assertEquals(OUR_IP, MdnsMessage.decodeAddress(answer, MdnsMessage.TYPE_A), "…with the address we advertised")
        }

    @Test
    fun refuses_a_name_it_does_not_advertise() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP)

            // Ask for a name that is not ours FIRST, then for one that is. Both queries cross the same
            // link in order, so if the first were answered its response would arrive first — the refusal is
            // proven by what comes back, not by waiting for a silence to elapse.
            f.query(NOT_OUR_NAME, MdnsMessage.TYPE_A)
            f.query(OUR_NAME, MdnsMessage.TYPE_A)

            val first = assertNotNull(f.receive(), "exactly one response crossed the link")
            assertEquals(
                OUR_IP,
                MdnsMessage.decodeAddress(first, MdnsMessage.TYPE_A),
                "the first response answers OUR name — the query for a name we do not advertise was never answered",
            )
            assertEquals(
                MdnsResponse.Silent(MdnsSilenceReason.NotOurs(NOT_OUR_NAME)),
                f.decisions.first(),
                "…and the refusal is typed, not a silent drop",
            )
        }

    @Test
    fun refuses_a_record_type_it_does_not_hold_for_one_of_its_own_names() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP) // a v4 address…

            f.query(OUR_NAME, MdnsMessage.TYPE_AAAA) // …asked for as AAAA
            f.query(OUR_NAME, MdnsMessage.TYPE_A)

            assertNotNull(f.receive(), "the A query is answered")
            val refusal = assertIs<MdnsResponse.Silent>(f.decisions.first())
            assertEquals(
                MdnsSilenceReason.UnsupportedType(MdnsMessage.TYPE_AAAA),
                refusal.reason,
                "a AAAA question about a name we hold an A for is refused, not answered with the v4 bytes",
            )
        }

    @Test
    fun a_withdrawn_name_stops_being_answered() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP)
            assertNotNull(f.ask(OUR_NAME, MdnsMessage.TYPE_A), "advertised: answered")

            f.responder.withdraw(OUR_NAME)
            f.query(OUR_NAME, MdnsMessage.TYPE_A)
            f.responder.advertise(OTHER_NAME, OTHER_IP)
            f.query(OTHER_NAME, MdnsMessage.TYPE_A)

            val next = assertNotNull(f.receive(), "the responder is still alive and answering")
            assertEquals(
                OTHER_IP,
                MdnsMessage.decodeAddress(next, MdnsMessage.TYPE_A),
                "the next response is for the OTHER name — the withdrawn one was not answered",
            )
        }

    @Test
    fun a_legacy_response_repeats_the_question_and_carries_the_short_ttl() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP)

            val answer = assertNotNull(f.ask(OUR_NAME, MdnsMessage.TYPE_A))
            val header = Header.read(answer)
            assertEquals(RESPONSE_FLAGS, header.flags, "QR=1 AA=1 — an authoritative response (RFC 6762 §18.2/§18.4)")
            assertEquals(1, header.questionCount, "RFC 6762 §6.7: a legacy response repeats the question")
            assertEquals(1, header.answerCount)
            // Step over the repeated question, then read the answer's CLASS + TTL.
            skipName(answer)
            answer.readUnsignedShort() // QTYPE
            answer.readUnsignedShort() // QCLASS
            skipName(answer)
            answer.readUnsignedShort() // TYPE
            val recordClass = answer.readUnsignedShort().toInt()
            assertEquals(CLASS_IN, recordClass, "no cache-flush bit — a legacy resolver has no cache to flush")
            assertEquals(
                MdnsMessage.LEGACY_TTL_SECONDS,
                answer.readUnsignedInt(),
                "RFC 6762 §6.7: 10 seconds, because a legacy querier does no cache maintenance",
            )
        }

    @Test
    fun a_query_from_the_well_known_port_is_answered_on_the_group() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP)
            // A full mDNS participant queries FROM 5353, and RFC 6762 §6 says the response is shared: it
            // goes to the group, where every resolver on the link can hear it. Bind the group as an
            // ordinary vnet endpoint and watch it land there rather than back at the querier.
            val participant = f.vnet.bind(vnetAddress(PARTICIPANT_IP, MDNS_UDP_PORT))
            val listener = f.vnet.bind(GROUP)

            participant.send(MdnsMessage.encodeQuery(OUR_NAME.value, MdnsMessage.TYPE_A, BufferFactory.Default), to = RESPONDER)

            val onGroup = assertNotNull(withTimeoutOrNull(TIMEOUT) { received(listener) }, "the response went to the group")
            assertEquals(OUR_IP, MdnsMessage.decodeAddress(onGroup, MdnsMessage.TYPE_A))
            val decision = assertIs<MdnsResponse.Answer>(f.decisions.first())
            assertEquals(MdnsDestination.Multicast, decision.destination, "…because the querier is on 5353, not a one-shot")
            assertEquals(listOf(OUR_NAME), decision.names, "and the answer names exactly what it answered for")
        }

    @Test
    fun a_datagram_that_is_not_a_query_is_a_named_silence() =
        runTest {
            val f = fixture()
            f.responder.advertise(OUR_NAME, OUR_IP)
            // A *response* — which is most of what lands on a shared group, since every host's answers do.
            val response =
                MdnsMessage.encodeResponse(
                    listOf(MdnsMessage.AnswerRecord(NOT_OUR_NAME.value, OTHER_IP)),
                    MdnsMessage.ResponseShape.Shared,
                    BufferFactory.Default,
                )
            f.querier.send(response, to = RESPONDER)
            f.query(OUR_NAME, MdnsMessage.TYPE_A) // …and a real question behind it, so we can stop waiting

            assertNotNull(f.receive(), "the query behind it is answered")
            assertEquals(
                MdnsResponse.Silent(MdnsSilenceReason.NotAQuery),
                f.decisions.first(),
                "a neighbour's response is routine, and named as such — never answered, never an error",
            )
        }

    @Test
    fun the_injected_buffer_factory_allocates_every_response() =
        runTest {
            val counting = CountingBufferFactory(BufferFactory.Default)
            val f = fixture(bufferFactory = counting)
            f.responder.advertise(OUR_NAME, OUR_IP)
            val before = counting.handedOut

            assertNotNull(f.ask(OUR_NAME, MdnsMessage.TYPE_A))

            assertTrue(
                counting.handedOut > before,
                "the response rode the caller's factory (directive #6) — a hardwired allocator would show zero",
            )
        }

    @Test
    fun a_minted_name_is_a_uuid_local_and_is_reproducible_from_the_injected_entropy() {
        val minted = MdnsHostName.random(Random(SEED))
        assertTrue(minted.value.endsWith(".local"), "the RFC 8828 §3.1 shape: <uuid>.local — was ${minted.value}")
        val uuid = minted.value.removeSuffix(".local")
        assertEquals(listOf(8, 4, 4, 4, 12), uuid.split('-').map { it.length }, "…an RFC 4122 UUID")
        assertTrue(uuid.all { it in "0123456789abcdef-" }, "…lowercase hex, exactly what a browser publishes")
        assertEquals('4', uuid[14], "version 4 (random), RFC 4122 §4.4")
        assertTrue(uuid[19] in "89ab", "…and the 10xx variant")
        assertEquals(minted, MdnsHostName.random(Random(SEED)), "minted from the injected seam, so a fixture can name it")
    }

    // ---- fixture plumbing ---------------------------------------------------------------------------

    private class Fixture(
        val vnet: Vnet,
        val responder: MdnsResponder,
        val querier: AddressedDatagramChannel,
        val decisions: MutableList<MdnsResponse>,
    ) {
        /** Send a one-shot legacy query (our source port is ephemeral, so RFC 6762 §6.7 applies). */
        suspend fun query(
            name: MdnsHostName,
            qType: Int,
        ) {
            querier.send(MdnsMessage.encodeQuery(name.value, qType, BufferFactory.Default), to = RESPONDER)
        }

        /** The next datagram back on the querier's socket, or null if none arrives within the watchdog. */
        suspend fun receive(): ReadBuffer? = withTimeoutOrNull(TIMEOUT) { received(querier) }

        /** Ask once and read the reply — the whole round trip a resolve-only peer performs. */
        suspend fun ask(
            name: MdnsHostName,
            qType: Int,
        ): ReadBuffer? {
            query(name, qType)
            return receive()
        }
    }

    // ── RFC 6762 §10.1 goodbye (webrtc#105) ─────────────────────────────────────────────────────────

    /**
     * Withdrawing a name we hold produces the TTL-0 record that retracts it.
     *
     * The zero is the entire mechanism, so it is read off the **wire bytes** rather than from a decoded
     * object: the shared TTL is 120 s, and a peer that keeps our binding for two minutes after the
     * interface behind it disappeared is precisely the stale binding #105 exists to remove.
     */
    @Test
    fun withdrawing_a_held_name_produces_a_ttl_zero_retraction() =
        runTest {
            val responder = MdnsResponder()
            responder.advertise(OUR_NAME, OUR_IP)

            val goodbye = assertIs<MdnsWithdrawal.Goodbye>(responder.withdraw(OUR_NAME))
            assertEquals(OUR_NAME, goodbye.name)
            assertEquals(OUR_IP, goodbye.address, "the retraction must name the address it is retracting")

            val header = Header.read(goodbye.payload)
            assertEquals(RESPONSE_FLAGS, header.flags, "a goodbye is an authoritative RESPONSE, not a query")
            assertEquals(0, header.questionCount, "unsolicited: there is no question to echo")
            assertEquals(1, header.answerCount)
            skipName(goodbye.payload)
            goodbye.payload.readUnsignedShort() // TYPE
            goodbye.payload.readUnsignedShort() // CLASS (cache-flush set — it is a shared response)
            assertEquals(
                0u,
                goodbye.payload.readUnsignedInt(),
                "TTL must be 0: anything else leaves the peer resolving a name we have stopped honouring, " +
                    "for up to the 120s shared TTL",
            )
        }

    /** Withdrawing a name we never held is a typed nothing, not an empty datagram put on the group. */
    @Test
    fun withdrawing_a_name_we_never_held_retracts_nothing() =
        runTest {
            val responder = MdnsResponder()
            responder.advertise(OUR_NAME, OUR_IP)

            assertEquals(
                MdnsWithdrawal.NotAdvertised,
                responder.withdraw(NOT_OUR_NAME),
                "speaking about a name we never advertised is exactly what this responder refuses to do",
            )
            assertEquals(setOf(OUR_NAME), responder.advertisedNames, "…and it must not disturb what we do hold")
        }

    private fun TestScope.fixture(bufferFactory: BufferFactory = BufferFactory.Default): Fixture {
        val vnet = Vnets.flat()
        val responder = MdnsResponder(bufferFactory)
        val decisions = mutableListOf<MdnsResponse>()
        val socket = vnet.bind(RESPONDER)
        backgroundScope.launch { responder.serve(socket, GROUP) { decisions += it } }
        return Fixture(vnet, responder, vnet.bind(vnetAddress(QUERIER_IP, QUERIER_PORT)), decisions)
    }

    /** A response header, read positionally — the fields RFC 6762 §6.7 constrains. */
    private class Header(
        val flags: Int,
        val questionCount: Int,
        val answerCount: Int,
    ) {
        companion object {
            fun read(buffer: ReadBuffer): Header {
                buffer.readUnsignedShort() // ID
                val flags = buffer.readUnsignedShort().toInt()
                val questions = buffer.readUnsignedShort().toInt()
                val answers = buffer.readUnsignedShort().toInt()
                buffer.readUnsignedShort() // NSCOUNT
                buffer.readUnsignedShort() // ARCOUNT
                return Header(flags, questions, answers)
            }
        }
    }

    private fun skipName(buffer: ReadBuffer) {
        while (true) {
            val length = buffer.readUnsignedByte().toInt()
            if (length == 0) return
            repeat(length) { buffer.readUnsignedByte() }
        }
    }

    private companion object {
        val TIMEOUT = 10.seconds
        const val SEED = 88L
        const val QUERIER_IP = "10.0.0.9"
        const val QUERIER_PORT = 41234 // ephemeral — i.e. a ONE-SHOT legacy querier (RFC 6762 §6.7)
        const val PARTICIPANT_IP = "10.0.0.8"
        val RESPONDER: SocketAddress = vnetAddress("10.0.0.1", MDNS_UDP_PORT)
        val GROUP: SocketAddress = vnetAddress("224.0.0.251", MDNS_UDP_PORT)
        val OUR_NAME = MdnsHostName("a1b2c3d4-0000-4000-8000-000000000001.local")
        val OTHER_NAME = MdnsHostName("a1b2c3d4-0000-4000-8000-000000000002.local")
        val NOT_OUR_NAME = MdnsHostName("somebody-elses.local")
        val OUR_IP: IpAddress = IpAddress.V4(0x0A000001u) // 10.0.0.1
        val OTHER_IP: IpAddress = IpAddress.V4(0x0A00000Au) // 10.0.0.10
        const val RESPONSE_FLAGS = 0x8400
        const val CLASS_IN = 0x0001

        suspend fun received(channel: AddressedDatagramChannel): ReadBuffer? =
            when (val result = channel.receive()) {
                is DatagramReadResult.Received -> result.datagram.payload
                is DatagramReadResult.Closed -> null
            }
    }
}
