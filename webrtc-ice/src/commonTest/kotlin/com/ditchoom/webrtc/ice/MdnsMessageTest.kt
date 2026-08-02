@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.IpAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Deterministic coverage for the pure mDNS wire codec ([MdnsMessage]) — the RFC 6762 / RFC 1035 message
 * format the multicast resolver speaks. No socket, no multicast: bytes in, bytes out, so it runs identically
 * on every target (jvm / native / node / wasm) under `runTest`, and a real-wire resolution bug can be
 * reproduced as a hand-crafted response fixture (standing directive #5).
 */
class MdnsMessageTest {
    @Test
    fun encodes_a_one_shot_qu_query_for_a_dot_local_name() {
        val query = MdnsMessage.encodeQuery("abcd.local", MdnsMessage.TYPE_A, BufferFactory.Default)

        assertEquals(0, query.readUnsignedShort().toInt(), "ID is 0 (ignored on multicast, RFC 6762 §18.1)")
        assertEquals(0, query.readUnsignedShort().toInt(), "flags: QR=0 query")
        assertEquals(1, query.readUnsignedShort().toInt(), "QDCOUNT")
        assertEquals(0, query.readUnsignedShort().toInt(), "ANCOUNT")
        assertEquals(0, query.readUnsignedShort().toInt(), "NSCOUNT")
        assertEquals(0, query.readUnsignedShort().toInt(), "ARCOUNT")
        assertEquals("abcd", readLabel(query))
        assertEquals("local", readLabel(query))
        assertEquals(0, query.readUnsignedByte().toInt(), "root label terminates the QNAME")
        assertEquals(MdnsMessage.TYPE_A, query.readUnsignedShort().toInt(), "QTYPE = A")
        assertEquals(0x8001, query.readUnsignedShort().toInt(), "QCLASS = IN with the QU unicast-response bit")
    }

    @Test
    fun encodes_aaaa_qtype_when_asked() {
        val query = MdnsMessage.encodeQuery("host.local", MdnsMessage.TYPE_AAAA, BufferFactory.Default)
        repeat(6) { query.readUnsignedShort() } // header
        readLabel(query)
        readLabel(query)
        query.readUnsignedByte() // root
        assertEquals(MdnsMessage.TYPE_AAAA, query.readUnsignedShort().toInt(), "QTYPE = AAAA")
    }

    @Test
    fun decodes_an_a_record_answer_with_a_compressed_name() {
        // Answer NAME is a compression pointer (0xC00C) — the common responder form; the codec must skip it.
        val response =
            response(answerCount = 1) {
                writeCompressionPointer()
                writeUShort(MdnsMessage.TYPE_A.toUShort())
                writeUShort(0x8001u) // CLASS IN + cache-flush bit — must be tolerated
                writeUInt(120u) // TTL
                writeUShort(4u) // RDLENGTH
                writeByte(10)
                writeByte(0)
                writeByte(0)
                writeByte(42) // 10.0.0.42
            }
        val ip = MdnsMessage.decodeAddress(response, MdnsMessage.TYPE_A)
        assertEquals("10.0.0.42", ip.toString(), "extracts the A record address")
    }

    @Test
    fun decodes_an_aaaa_record_answer() {
        val expected = IpAddress.V6.parse("2001:db8::1")!!
        val response =
            response(answerCount = 1) {
                writeCompressionPointer()
                writeUShort(MdnsMessage.TYPE_AAAA.toUShort())
                writeUShort(0x8001u)
                writeUInt(120u)
                writeUShort(16u)
                writeUInt((expected.hi shr 32).toUInt())
                writeUInt(expected.hi.toUInt())
                writeUInt((expected.lo shr 32).toUInt())
                writeUInt(expected.lo.toUInt())
            }
        assertEquals(expected, MdnsMessage.decodeAddress(response, MdnsMessage.TYPE_AAAA), "extracts the AAAA record")
    }

    @Test
    fun skips_a_full_owner_name_and_an_unwanted_record_before_the_match() {
        // First answer is an unwanted TXT (skipped by RDLENGTH), second is the A we want — with a FULL name.
        val response =
            response(answerCount = 2) {
                writeName("other", "local")
                writeUShort(16u) // TYPE TXT — not an address
                writeUShort(1u)
                writeUInt(120u)
                writeUShort(3u)
                writeByte(2)
                writeByte('h'.code.toByte())
                writeByte('i'.code.toByte())
                writeName("abcd", "local")
                writeUShort(MdnsMessage.TYPE_A.toUShort())
                writeUShort(1u)
                writeUInt(120u)
                writeUShort(4u)
                writeByte(192.toByte())
                writeByte(168.toByte())
                writeByte(1)
                writeByte(9) // 192.168.1.9
            }
        assertEquals("192.168.1.9", MdnsMessage.decodeAddress(response, MdnsMessage.TYPE_A).toString())
    }

    @Test
    fun returns_null_when_the_wanted_type_is_absent() {
        val response =
            response(answerCount = 1) {
                writeCompressionPointer()
                writeUShort(MdnsMessage.TYPE_A.toUShort()) // an A record...
                writeUShort(1u)
                writeUInt(120u)
                writeUShort(4u)
                writeByte(10)
                writeByte(0)
                writeByte(0)
                writeByte(1)
            }
        assertNull(MdnsMessage.decodeAddress(response, MdnsMessage.TYPE_AAAA), "...but AAAA was asked for")
    }

    @Test
    fun returns_null_on_a_truncated_datagram() {
        val truncated = BufferFactory.Default.allocate(4, ByteOrder.BIG_ENDIAN)
        truncated.writeUShort(0u)
        truncated.writeUShort(0u) // only 4 bytes — shorter than a header
        truncated.resetForRead()
        assertNull(MdnsMessage.decodeAddress(truncated, MdnsMessage.TYPE_A))
    }

    @Test
    fun returns_null_when_an_answer_is_promised_but_missing() {
        val response = response(answerCount = 1) { /* header claims 1 answer, but no RR bytes follow */ }
        assertNull(MdnsMessage.decodeAddress(response, MdnsMessage.TYPE_A))
    }

    @Test
    fun our_own_query_decodes_back_into_the_question_it_asked() {
        // The exact bytes the resolver puts on the wire, read by the responder half — the two ends of this
        // codec are each other's only real fixture, so they are pinned against each other.
        val query = MdnsMessage.encodeQuery("abcd.local", MdnsMessage.TYPE_A, BufferFactory.Default)
        val decoded = assertIs<MdnsMessage.QueryDecode.Decoded>(MdnsMessage.decodeQuery(query)).query
        assertEquals(1, decoded.questions.size)
        assertEquals("abcd.local", decoded.questions[0].name, "the QNAME is reassembled label by label")
        assertEquals(MdnsMessage.TYPE_A, decoded.questions[0].qType)
        assertTrue(decoded.questions[0].unicastResponse, "our queries set the QU bit (RFC 6762 §5.4)")
    }

    @Test
    fun a_response_is_not_a_query_and_says_so_distinctly() {
        val response = response(answerCount = 0) {}
        assertEquals(
            MdnsMessage.QueryDecode.NotAQuery,
            MdnsMessage.decodeQuery(response),
            "every host's responses land on the shared group; that is routine, not corruption",
        )
    }

    @Test
    fun a_truncated_query_is_a_typed_reject_not_a_throw() {
        val truncated = BufferFactory.Default.allocate(4, ByteOrder.BIG_ENDIAN)
        truncated.writeUShort(0u)
        truncated.writeUShort(0u)
        truncated.resetForRead()
        assertEquals(MdnsMessage.QueryDecode.Malformed, MdnsMessage.decodeQuery(truncated))
    }

    @Test
    fun a_question_promised_but_missing_is_malformed() {
        val query = BufferFactory.Default.allocate(HEADER_ONLY_CAPACITY, ByteOrder.BIG_ENDIAN)
        query.writeUShort(0u) // ID
        query.writeUShort(0u) // flags: QR=0
        query.writeUShort(1u) // QDCOUNT claims one question…
        query.writeUShort(0u)
        query.writeUShort(0u)
        query.writeUShort(0u) // …and the message ends here
        query.resetForRead()
        assertEquals(MdnsMessage.QueryDecode.Malformed, MdnsMessage.decodeQuery(query))
    }

    @Test
    fun a_self_referential_compression_pointer_terminates_and_names_nothing() {
        // A name that points at itself: the classic decompression bomb, and this codec is reachable by
        // anything on the local link. RFC 1035 §4.1.4 pointers are BACKWARD references, so one that does
        // not reach a strictly lower offset simply ends the name where it stands — the decode terminates,
        // the record after it is still read, and the empty name is nobody's, so a responder refuses it.
        val query = BufferFactory.Default.allocate(HEADER_ONLY_CAPACITY + 6, ByteOrder.BIG_ENDIAN)
        query.writeUShort(0u)
        query.writeUShort(0u)
        query.writeUShort(1u) // QDCOUNT
        query.writeUShort(0u)
        query.writeUShort(0u)
        query.writeUShort(0u)
        query.writeByte(0xC0.toByte())
        query.writeByte(0x0C.toByte()) // → offset 12, which is this very pointer
        query.writeUShort(MdnsMessage.TYPE_A.toUShort())
        query.writeUShort(1u) // QCLASS IN
        query.resetForRead()

        val decoded = assertIs<MdnsMessage.QueryDecode.Decoded>(MdnsMessage.decodeQuery(query)).query
        assertEquals("", decoded.questions.single().name, "the name is unreassemblable, so it is empty — never chased")
        assertEquals(
            MdnsResponse.Silent(MdnsSilenceReason.NotOurs(MdnsHostName(""))),
            MdnsResponder().respond(query.also { it.resetForRead() }, SocketAddress.ofLiteral("10.0.0.9", 40000)),
            "and a responder that advertises nothing under that name says so, rather than answering",
        )
    }

    @Test
    fun an_encoded_response_round_trips_with_the_owner_name_of_each_answer() {
        // The property the shared-socket endpoint depends on: with several resolutions outstanding, an
        // answer has to be attributable to the name it answers for, not merely to "a response arrived".
        val v6 = IpAddress.V6.parse("2001:db8::7")!!
        val encoded =
            MdnsMessage.encodeResponse(
                listOf(
                    MdnsMessage.AnswerRecord("one.local", IpAddress.V4(0x0A00000Au)),
                    MdnsMessage.AnswerRecord("two.local", v6),
                ),
                MdnsMessage.ResponseShape.Shared,
                BufferFactory.Default,
            )
        val decoded = MdnsMessage.decodeAnswers(encoded)
        assertEquals(listOf("one.local", "two.local"), decoded.map { it.name })
        assertEquals("10.0.0.10", decoded[0].address.toString())
        assertEquals(v6, decoded[1].address)
    }

    /**
     * A TTL-0 record is a **goodbye** (RFC 6762 §10.1) and must never decode as an answer.
     *
     * This was a live defect until webrtc#105: [MdnsMessage.decodeAnswers] read the TTL and discarded it,
     * so a retraction was indistinguishable from a resolution and would bind an ICE candidate to an address
     * that had just gone away. Not self-inflicted — Chrome, Firefox and avahi all multicast goodbyes when an
     * interface disappears or a page closes, so this arrives from foreign peers on any shared link.
     */
    @Test
    fun a_ttl_zero_goodbye_is_not_an_answer() {
        val goodbye =
            MdnsMessage.encodeResponse(
                answers = listOf(MdnsMessage.AnswerRecord(NAME, ADDRESS)),
                shape = MdnsMessage.ResponseShape.Goodbye,
                bufferFactory = BufferFactory.Default,
            )

        assertEquals(
            emptyList(),
            MdnsMessage.decodeAnswers(goodbye),
            "a retraction decoded as an answer binds a candidate to an address that has just been withdrawn",
        )
    }

    /** …and the same message shape with a live TTL still decodes, so the filter is TTL-specific. */
    @Test
    fun the_same_record_with_a_live_ttl_still_decodes() {
        val announcement =
            MdnsMessage.encodeResponse(
                answers = listOf(MdnsMessage.AnswerRecord(NAME, ADDRESS)),
                shape = MdnsMessage.ResponseShape.Shared,
                bufferFactory = BufferFactory.Default,
            )

        assertEquals(
            listOf(MdnsMessage.AnswerRecord(NAME, ADDRESS)),
            MdnsMessage.decodeAnswers(announcement),
            "only TTL 0 is a goodbye — filtering more than that would drop ordinary resolutions",
        )
    }

    @Test
    fun a_trailing_record_we_cannot_parse_does_not_cost_the_address_already_decoded() {
        val response =
            response(answerCount = 2) {
                writeName("abcd", "local")
                writeUShort(MdnsMessage.TYPE_A.toUShort())
                writeUShort(1u)
                writeUInt(120u)
                writeUShort(4u)
                writeByte(10)
                writeByte(0)
                writeByte(0)
                writeByte(7) // 10.0.0.7 — the answer we came for
                writeByte(0x09) // …followed by a second record that simply runs off the end
            }
        assertEquals("10.0.0.7", MdnsMessage.decodeAddress(response, MdnsMessage.TYPE_A).toString())
    }

    // ── helpers ──

    private fun readLabel(buffer: ReadBuffer): String {
        val length = buffer.readUnsignedByte().toInt()
        return buildString { repeat(length) { append(buffer.readUnsignedByte().toInt().toChar()) } }
    }

    // Build a response datagram: header (ANCOUNT = [answerCount], QDCOUNT = 0) then the [answers] body.
    private fun response(
        answerCount: Int,
        answers: WriteBuffer.() -> Unit,
    ): ReadBuffer {
        val buffer = BufferFactory.Default.allocate(RESPONSE_CAPACITY, ByteOrder.BIG_ENDIAN)
        buffer.writeUShort(0u) // ID
        buffer.writeUShort(0x8400u) // flags: QR=1 response, AA=1
        buffer.writeUShort(0u) // QDCOUNT
        buffer.writeUShort(answerCount.toUShort()) // ANCOUNT
        buffer.writeUShort(0u) // NSCOUNT
        buffer.writeUShort(0u) // ARCOUNT
        buffer.answers()
        buffer.resetForRead()
        return buffer
    }

    private fun WriteBuffer.writeCompressionPointer() {
        writeByte(0xC0.toByte())
        writeByte(0x0C.toByte()) // pointer to offset 12 (RFC 1035 §4.1.4)
    }

    private fun WriteBuffer.writeName(vararg labels: String) {
        for (label in labels) {
            writeByte(label.length.toByte())
            for (c in label) writeByte(c.code.toByte())
        }
        writeByte(0)
    }

    private companion object {
        const val RESPONSE_CAPACITY = 128
        const val HEADER_ONLY_CAPACITY = 12
        const val NAME = "a1b2c3d4-0000-4000-8000-000000000001.local"
        val ADDRESS: IpAddress = IpAddress.V4(0x0A000001u) // 10.0.0.1
    }
}
