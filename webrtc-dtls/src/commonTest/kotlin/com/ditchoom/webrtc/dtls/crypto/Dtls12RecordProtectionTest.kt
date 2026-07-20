package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The DTLS 1.2 AES-128-GCM record protection: a record sealed by one side must decrypt on the other with
 * the mirrored key-block slices, and any AAD/nonce/ciphertext perturbation (a tampered byte, a replayed
 * or wrong record sequence number, a content-type confusion) must fail the AEAD tag and drop the record
 * rather than surface forged plaintext.
 */
class Dtls12RecordProtectionTest {
    private val factory = BufferFactory.managed()

    private fun keyBlock(): ReadBuffer {
        // 40 distinct bytes: client key / server key / client IV / server IV.
        val b = factory.allocate(Dtls12RecordProtection.KEY_BLOCK_BYTES, ByteOrder.BIG_ENDIAN)
        for (i in 0 until Dtls12RecordProtection.KEY_BLOCK_BYTES) b.writeByte((i + 1).toByte())
        b.resetForRead()
        return b
    }

    private fun bytes(vararg v: Int): ReadBuffer {
        val b = factory.allocate(v.size, ByteOrder.BIG_ENDIAN)
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
    fun client_sealed_record_opens_on_the_server() {
        val kb = keyBlock()
        val client = Dtls12RecordProtection.fromKeyBlock(kb, client = true, factory)
        val server = Dtls12RecordProtection.fromKeyBlock(kb, client = false, factory)
        try {
            val plaintext = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x2A)
            val epoch = 1
            val seq = 0L
            val fragment = client.seal(plaintext, epoch, seq, contentType = 23, version = 0xFEFD)
            // explicit_nonce(8) + ciphertext(5) + tag(16) = 29 bytes.
            assertEquals(29, fragment.remaining())
            val opened = server.open(fragment, epoch, seq, contentType = 23, version = 0xFEFD)
            assertNotNull(opened)
            assertEquals(listOf(0xDE, 0xAD, 0xBE, 0xEF, 0x2A), opened.toList())
        } finally {
            client.close()
            server.close()
        }
    }

    @Test
    fun a_tampered_byte_or_wrong_sequence_number_drops_the_record() {
        val kb = keyBlock()
        val client = Dtls12RecordProtection.fromKeyBlock(kb, client = true, factory)
        val server = Dtls12RecordProtection.fromKeyBlock(kb, client = false, factory)
        try {
            val fragment = client.seal(bytes(1, 2, 3, 4), epoch = 1, sequenceNumber = 7, contentType = 23, version = 0xFEFD)

            // Wrong sequence number in the AAD → tag mismatch → dropped.
            assertNull(server.open(fragment, epoch = 1, sequenceNumber = 8, contentType = 23, version = 0xFEFD))
            // Wrong content type in the AAD → dropped.
            assertNull(server.open(fragment, epoch = 1, sequenceNumber = 7, contentType = 22, version = 0xFEFD))

            // Flip a ciphertext byte → dropped.
            val bytesList = fragment.toList().toMutableList()
            bytesList[Dtls12RecordProtection.EXPLICIT_NONCE_BYTES] = bytesList[Dtls12RecordProtection.EXPLICIT_NONCE_BYTES] xor 0x01
            val tampered = factory.allocate(bytesList.size, ByteOrder.BIG_ENDIAN)
            bytesList.forEach { tampered.writeByte(it.toByte()) }
            tampered.resetForRead()
            assertNull(server.open(tampered, epoch = 1, sequenceNumber = 7, contentType = 23, version = 0xFEFD))

            // The untampered record still opens (proves the drops above were the perturbations, not a dead key).
            assertNotNull(server.open(fragment, epoch = 1, sequenceNumber = 7, contentType = 23, version = 0xFEFD))
        } finally {
            client.close()
            server.close()
        }
    }
}
