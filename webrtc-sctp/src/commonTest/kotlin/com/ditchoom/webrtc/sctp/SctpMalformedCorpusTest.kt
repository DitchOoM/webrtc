package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.managed
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * T0 floor (RFC §7): a hostile or truncated datagram must yield a **typed** [SctpDecodeResult.Reject],
 * never a throw-through or a crash. The committed cases pin specific reject reasons; the seeded
 * property loops assert the stronger invariant — decode is total (Success or Reject) over arbitrary
 * bytes, and every Success re-encodes and re-verifies without throwing, on every platform.
 */
class SctpMalformedCorpusTest {
    private fun reject(buf: PlatformBuffer): SctpRejectReason {
        val r = SctpPacket.decode(buf)
        return assertIs<SctpDecodeResult.Reject>(r).reason
    }

    @Test
    fun emptyIsShorterThanCommonHeader() {
        assertIs<SctpRejectReason.ShorterThanCommonHeader>(reject(bufferOf()))
    }

    @Test
    fun shorterThanCommonHeaderIsRejected() {
        assertIs<SctpRejectReason.ShorterThanCommonHeader>(reject(bufferOf(0, 0, 0, 0, 0, 0, 0, 0)))
    }

    @Test
    fun commonHeaderWithNoChunksIsRejected() {
        // 12-byte common header, nothing after → NoChunks.
        assertIs<SctpRejectReason.NoChunks>(reject(bufferOfHex("13881388deadbeef00000000")))
    }

    @Test
    fun chunkHeaderRunningOffTheEndIsRejected() {
        // Common header + 2 stray bytes (not a full 4-byte chunk header).
        assertIs<SctpRejectReason.MalformedChunkHeader>(reject(bufferOfHex("13881388deadbeef00000000" + "0700")))
    }

    @Test
    fun chunkLengthBelowHeaderIsRejected() {
        // Chunk declaredLength = 3 (< the 4-byte header).
        assertIs<SctpRejectReason.MalformedChunkHeader>(reject(bufferOfHex("13881388deadbeef00000000" + "07000003")))
    }

    @Test
    fun chunkLengthBeyondPacketIsRejected() {
        // Chunk claims length 0x0040 but only 4 bytes follow.
        assertIs<SctpRejectReason.ChunkLengthBeyondPacket>(reject(bufferOfHex("13881388deadbeef00000000" + "07000040")))
    }

    @Test
    fun malformedChunkBodyIsRejected() {
        // SHUTDOWN (type 7) with a 2-byte value (declaredLength 6) — must be exactly 4.
        assertIs<SctpRejectReason.MalformedChunkBody>(reject(bufferOfHex("13881388deadbeef00000000" + "07000006" + "00000000")))
    }

    @Test
    fun decodeIsTotalOverArbitraryBytes() {
        // Fast cross-platform totality smoke (kept small so it stays well under the JS-node 2s Mocha
        // budget — 20k flaked there at ~1.9s). Deep coverage-guided fuzzing is :webrtc-sctp:sctpCodecFuzz.
        val random = Random(0x5C_7C_1D)
        repeat(2_000) {
            val n = random.nextInt(0, 300)
            val buf = BufferFactory.managed().allocate(maxOf(1, n), ByteOrder.BIG_ENDIAN)
            repeat(n) { buf.writeByte(random.nextInt().toByte()) }
            buf.resetForRead()
            buf.setLimit(n)
            val result = SctpPacket.decode(buf)
            assertTrue(result is SctpDecodeResult.Success || result is SctpDecodeResult.Reject)
            // Anything reachable on a decoded packet must also be crash-free.
            if (result is SctpDecodeResult.Success) {
                result.packet.encode()
                result.packet.verifyChecksum()
            }
        }
    }

    @Test
    fun everySingleByteMutationOfAValidPacketStaysTotal() {
        val valid = validInitPacketBytes()
        for (i in valid.indices) {
            for (delta in listOf(1, 0x40, 0x80, 0xFF)) {
                val mutated = valid.toMutableList()
                mutated[i] = mutated[i] xor delta
                val buf = BufferFactory.managed().allocate(mutated.size, ByteOrder.BIG_ENDIAN)
                for (b in mutated) buf.writeByte(b.toByte())
                buf.resetForRead()
                buf.setLimit(mutated.size)
                when (val r = SctpPacket.decode(buf)) {
                    is SctpDecodeResult.Success -> {
                        r.packet.encode() // must not throw
                        r.packet.verifyChecksum() // must not throw
                    }
                    is SctpDecodeResult.Reject -> {} // typed reject is fine
                }
            }
        }
    }

    @Test
    fun abortWithCauseOverrunningItsChunkStaysTotal() {
        // Jazzer regression (seed regression-abort-cause-overrun.bin): an ABORT whose final error cause
        // declares padding that runs past the chunk region. The decoder truncates the padded view; the
        // bug was that valueSize was still computed from the untruncated paddedLength, so encode wrote
        // fewer bytes than allocated, resetForRead shrank the limit, and the checksum's bulk read ran
        // off the datagram. Decode + encode + verify must now all be crash-free.
        val bytes = bufferOfHex("1788178800000001000000000600001788000004070000088000000000000006040041aa")
        val packet = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(bytes)).packet
        val reencoded = packet.encode() // must not throw
        // The re-encoded packet must itself decode and verify (self-consistent chunk length + checksum).
        reencoded.position(0)
        val again = assertIs<SctpDecodeResult.Success>(SctpPacket.decode(reencoded)).packet
        assertTrue(again.verifyChecksum())
    }

    @Test
    fun rejectReasonsAreTypedValues() {
        assertEquals(SctpRejectReason.NoChunks, SctpRejectReason.NoChunks)
        assertEquals(SctpRejectReason.ShorterThanCommonHeader, SctpRejectReason.ShorterThanCommonHeader)
    }

    private fun validInitPacketBytes(): List<Int> {
        val init =
            SctpChunk.Init(
                VerificationTag(0x11223344u),
                0x10000u,
                256u,
                256u,
                Tsn(1u),
                listOf(SctpParameter.forwardTsnSupported(), SctpParameter.supportedExtensions(listOf(SctpChunkType.ForwardTsn))),
            )
        return SctpPacketBuilder(5000u, 5000u, VerificationTag(0xDEADBEEFu)).add(init).encode().toIntList()
    }
}
