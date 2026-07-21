package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Round-trip + robustness coverage for the pure-Kotlin DTLS wire codec (records, handshake framing +
 * reassembly, extensions, handshake bodies). Every structure must encode→decode byte-identically, and
 * every parser must reject a truncated/overrunning input with a typed null (T0 totality), never a throw.
 */
class DtlsWireTest {
    private fun buf(size: Int): PlatformBuffer = BufferFactory.managed().allocate(size, ByteOrder.BIG_ENDIAN)

    private fun bytes(vararg v: Int): ReadBuffer {
        val b = buf(v.size)
        v.forEach { b.writeByte(it.toByte()) }
        b.resetForRead()
        return b
    }

    private fun ReadBuffer.toList(): List<Int> {
        val p = position()
        val out = ArrayList<Int>(remaining())
        while (remaining() > 0) out += readByte().toInt() and 0xFF
        position(p)
        return out
    }

    @Test
    fun record_roundtrips_and_coalesced_records_split() {
        val r1 = DtlsRecord(ContentType.Handshake, ProtocolVersion.Dtls12, epoch = 0, sequenceNumber = 5, fragment = bytes(1, 2, 3))
        val r2 =
            DtlsRecord(
                ContentType.ApplicationData,
                ProtocolVersion.Dtls12,
                epoch = 1,
                sequenceNumber = 0x0102030405,
                fragment = bytes(9, 9),
            )
        val out = buf(r1.wireSize + r2.wireSize)
        r1.encodeInto(out)
        r2.encodeInto(out)
        out.resetForRead()

        val decoded = DtlsRecord.decodeAll(out)
        assertNotNull(decoded)
        assertEquals(2, decoded.size)
        assertEquals(ContentType.Handshake.value, decoded[0].contentType.value)
        assertEquals(5, decoded[0].sequenceNumber)
        assertEquals(listOf(1, 2, 3), decoded[0].fragment.toList())
        assertEquals(1, decoded[1].epoch)
        assertEquals(0x0102030405, decoded[1].sequenceNumber)
        assertEquals(listOf(9, 9), decoded[1].fragment.toList())
    }

    @Test
    fun record_rejects_a_fragment_that_overruns_the_datagram() {
        // A valid header claiming length 100 but only 3 body bytes present.
        val d = buf(DtlsRecord.HEADER_BYTES + 3)
        d.writeByte(22)
        d.writeByte(0xFE.toByte())
        d.writeByte(0xFD.toByte())
        d.writeByte(0)
        d.writeByte(0) // epoch
        repeat(6) { d.writeByte(0) } // seq
        d.writeByte(0)
        d.writeByte(100) // length = 100
        repeat(3) { d.writeByte(7) }
        d.resetForRead()
        assertNull(DtlsRecord.decodeAll(d))
    }

    @Test
    fun handshake_message_roundtrips_with_normalized_transcript_header() {
        val msg = HandshakeMessage(HandshakeType.ServerHelloDone, messageSeq = 3, body = bytes())
        val out = buf(msg.wireSize)
        msg.encodeInto(out)
        out.resetForRead()
        val frags = HandshakeFragment.decodeAll(out)
        assertNotNull(frags)
        assertEquals(1, frags.size)
        assertEquals(HandshakeType.ServerHelloDone.value, frags[0].msgType.value)
        assertEquals(3, frags[0].messageSeq)
        assertEquals(0, frags[0].fragmentOffset)
        assertEquals(0, frags[0].length)
    }

    @Test
    fun reassembler_stitches_out_of_order_fragments_in_message_seq_order() {
        val factory = BufferFactory.managed()
        val re = HandshakeReassembler(factory)
        // message_seq 0 is a 5-byte body split into [0,2) and [2,5), delivered reversed.
        val full = bytes(10, 20, 30, 40, 50)

        fun frag(
            off: Int,
            len: Int,
        ): HandshakeFragment =
            HandshakeFragment(
                HandshakeType.Certificate,
                length = 5,
                messageSeq = 0,
                fragmentOffset = off,
                fragmentLength = len,
                fragmentBody =
                    full.sliceOf(
                        off,
                        off + len,
                    ),
            )

        assertTrue(re.offer(frag(2, 3)).isEmpty()) // tail first — not yet complete
        val done = re.offer(frag(0, 2))
        assertEquals(1, done.size)
        assertEquals(listOf(10, 20, 30, 40, 50), done[0].body.toList())
        assertEquals(HandshakeType.Certificate.value, done[0].msgType.value)
    }

    @Test
    fun reassembler_drops_already_delivered_and_holds_future_until_gap_fills() {
        val re = HandshakeReassembler(BufferFactory.managed())

        fun whole(
            seq: Int,
            vararg v: Int,
        ): HandshakeFragment {
            val b = bytes(*v)
            return HandshakeFragment(
                HandshakeType.Finished,
                length = v.size,
                messageSeq = seq,
                fragmentOffset = 0,
                fragmentLength = v.size,
                fragmentBody = b,
            )
        }
        // seq 1 arrives before seq 0 — buffered, nothing delivered yet.
        assertTrue(re.offer(whole(1, 0xAA)).isEmpty())
        val burst = re.offer(whole(0, 0xBB))
        assertEquals(2, burst.size) // seq 0 then the buffered seq 1
        assertEquals(0, burst[0].messageSeq)
        assertEquals(1, burst[1].messageSeq)
        // A re-delivered seq 0 is now in the past — dropped.
        assertTrue(re.offer(whole(0, 0xBB)).isEmpty())
    }

    @Test
    fun client_hello_roundtrips_including_extensions() {
        val exts =
            listOf(
                Extension(ExtensionType.SupportedGroups, bytes(0, 2, 0, 23)),
                Extension(ExtensionType.ExtendedMasterSecret, bytes()),
            )
        val hello =
            ClientHello(
                version = ProtocolVersion.Dtls12,
                random = bytes(*IntArray(RANDOM_BYTES) { it }),
                sessionId = bytes(),
                cookie = bytes(0xC0, 0x0C),
                cipherSuites = listOf(CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256, CipherSuiteId.TlsAes128GcmSha256),
                extensions = exts,
            )
        val body = buf(512)
        hello.bodyInto(body)
        body.resetForRead()
        val parsed = ClientHello.parse(body)
        assertNotNull(parsed)
        assertEquals(ProtocolVersion.Dtls12.value, parsed.version.value)
        assertEquals(listOf(0xC0, 0x0C), parsed.cookie.toList())
        assertEquals(2, parsed.cipherSuites.size)
        assertEquals(CipherSuiteId.TlsEcdheEcdsaAes128GcmSha256.value, parsed.cipherSuites[0].value)
        assertEquals(2, parsed.extensions.size)
        assertEquals(ExtensionType.SupportedGroups.value, parsed.extensions[0].type.value)
    }

    @Test
    fun server_key_exchange_roundtrips_and_params_view_is_stable() {
        val point = bytes(*IntArray(65) { 0x04 })
        val ske =
            ServerKeyExchange(NamedGroup.Secp256r1, point, SignatureSchemeId.EcdsaSecp256r1Sha256, bytes(0x30, 0x06, 1, 2, 3, 4, 5, 6))
        val body = buf(256)
        ske.bodyInto(body)
        body.resetForRead()
        val parsed = ServerKeyExchange.parse(body)
        assertNotNull(parsed)
        assertEquals(NamedGroup.Secp256r1.value, parsed.curve.value)
        assertEquals(65, parsed.publicPoint.remaining())
        assertEquals(SignatureSchemeId.EcdsaSecp256r1Sha256.value, parsed.signatureScheme.value)
        // The signed-params view (curve_type ‖ namedcurve ‖ point) is 1 + 2 + 1 + 65 = 69 bytes.
        val params = buf(69)
        parsed.serverEcdhParamsInto(params)
        params.resetForRead()
        assertEquals(69, params.remaining())
    }

    @Test
    fun handshake_body_parsers_reject_truncation_without_throwing() {
        assertNull(ClientHello.parse(bytes(0xFE, 0xFD, 0, 0))) // too short for the 32-byte random
        assertNull(ServerHello.parse(bytes(0xFE)))
        assertNull(ServerKeyExchange.parse(bytes(3, 0, 23))) // named_curve + curve but no point length
        assertNull(HelloVerifyRequest.parse(bytes(0xFE)))
        assertNull(CertificateMessage.parse(bytes(0, 0, 10))) // claims 10 body bytes, none present
    }
}
