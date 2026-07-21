package com.ditchoom.webrtc.dtls.wire

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer

/**
 * Reassembles fragmented DTLS handshake messages (RFC 6347 §4.2.3) and delivers them **in `message_seq`
 * order** — the order the handshake FSM must process them, regardless of datagram reordering or how a
 * message was split (inbound fragmentation is real: a 409-byte Certificate arrived in 95-byte fragments
 * in the spike). Each in-flight message accumulates into one assembly buffer from the injected factory,
 * with byte coverage tracked as merged intervals; a message is delivered once `[0, length)` is covered.
 *
 * Retransmitted fragments (a `message_seq` already delivered) are dropped. Out-of-order future messages
 * are buffered up to [maxPending] distinct sequences, then further ones are dropped (a DoS bound — a
 * peer cannot make us buffer unboundedly). Never throws (T0): a fragment inconsistent with a message
 * already partly assembled (a different total length) is dropped.
 */
internal class HandshakeReassembler(
    private val bufferFactory: BufferFactory,
    private val maxPending: Int = 16,
) {
    private class Assembly(
        val length: Int,
        val msgType: HandshakeType,
        val buffer: PlatformBuffer,
    ) {
        // Merged covered byte intervals [start, endExclusive); complete when it is exactly [0, length).
        val covered = mutableListOf<IntRange>()

        fun add(
            offset: Int,
            fragment: ReadBuffer,
        ) {
            val n = fragment.remaining()
            if (n == 0) {
                if (length == 0) markComplete()
                return
            }
            val save = fragment.position()
            buffer.position(offset)
            buffer.write(fragment)
            fragment.position(save)
            cover(offset, offset + n)
        }

        private fun markComplete() {
            if (covered.isEmpty()) covered += 0..0 // zero-length message: trivially complete
        }

        private fun cover(
            start: Int,
            endExclusive: Int,
        ) {
            var s = start
            var e = endExclusive
            val merged = mutableListOf<IntRange>()
            for (r in covered) {
                if (r.last < s || r.first > e) {
                    merged += r
                } else {
                    s = minOf(s, r.first)
                    e = maxOf(e, r.last)
                }
            }
            merged += s..e
            merged.sortBy { it.first }
            covered.clear()
            covered += merged
        }

        val isComplete: Boolean
            get() {
                if (length == 0) return covered.isNotEmpty()
                val r = covered.singleOrNull() ?: return false
                return r.first <= 0 && r.last >= length
            }
    }

    private var nextSeq = 0
    private val pending = HashMap<Int, Assembly>()

    /**
     * Feeds one parsed [fragment]; returns any handshake messages that became deliverable (in
     * `message_seq` order, possibly several as a gap fills), or empty. The returned bodies are views over
     * assembly buffers owned by this reassembler until the next call touches the same sequence — the FSM
     * consumes them synchronously within the step, matching the sans-io contract.
     */
    fun offer(fragment: HandshakeFragment): List<HandshakeMessage> {
        if (fragment.messageSeq < nextSeq) return emptyList() // already delivered — a retransmit
        if (fragment.messageSeq >= nextSeq + maxPending) return emptyList() // beyond the reorder window

        val existing = pending[fragment.messageSeq]
        val assembly =
            when {
                existing != null && existing.length == fragment.length -> existing
                existing != null -> return emptyList() // inconsistent re-report of the same seq — drop
                else ->
                    Assembly(
                        length = fragment.length,
                        msgType = fragment.msgType,
                        buffer = bufferFactory.allocate(maxOf(fragment.length, 1), ByteOrder.BIG_ENDIAN),
                    ).also { pending[fragment.messageSeq] = it }
            }
        assembly.add(fragment.fragmentOffset, fragment.fragmentBody)

        val ready = mutableListOf<HandshakeMessage>()
        while (true) {
            val a = pending[nextSeq] ?: break
            if (!a.isComplete) break
            a.buffer.position(0)
            a.buffer.setLimit(a.length)
            ready += HandshakeMessage(a.msgType, nextSeq, a.buffer.slice(ByteOrder.BIG_ENDIAN))
            pending.remove(nextSeq)
            nextSeq++
        }
        return ready
    }
}
