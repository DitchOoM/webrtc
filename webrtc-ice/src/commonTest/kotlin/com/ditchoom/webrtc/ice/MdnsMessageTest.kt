package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.webrtc.stun.IpAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

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
    }
}
