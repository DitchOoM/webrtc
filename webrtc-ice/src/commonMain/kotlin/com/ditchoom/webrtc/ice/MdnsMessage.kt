package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.WriteBuffer
import com.ditchoom.webrtc.stun.IpAddress

/**
 * The one-shot mDNS query/response **wire codec** (RFC 6762 over the RFC 1035 DNS message format) — pure,
 * sans-io, `commonMain`, so it is exercised deterministically on every target under `runTest`, while the
 * multicast socket that carries these bytes is a platform actual ([MulticastMdnsResolver] /
 * [MulticastMdnsEndpoint], non-browser targets only). A browser advertises an `<uuid>.local` host candidate
 * to hide its private IP (RFC 8828); to send a connectivity check to it we resolve the name to an address
 * with a single QM/QU query — and, since #88, we obfuscate our own host candidates the same way and must
 * therefore *answer* the peer's query for the names we mint.
 *
 * Both directions live here. [encodeQuery] / [decodeAddress] are the resolver half; [decodeQuery] /
 * [encodeResponse] are the responder half. Truncation or a malformed message is a **typed reject** (`null`),
 * never a throw (T0 discipline) — a hostile or corrupt datagram on the multicast group must not crash
 * either half, and the responder is reachable by anything on the link.
 */
internal object MdnsMessage {
    /** RFC 1035 §3.2.2 TYPE values we support — an A (IPv4) or AAAA (IPv6) address record. */
    const val TYPE_A: Int = 1
    const val TYPE_AAAA: Int = 28

    /** RFC 6762 §6.7 legacy-response TTL: 10 seconds, because a legacy resolver does no cache maintenance. */
    const val LEGACY_TTL_SECONDS: UInt = 10u

    /** RFC 6762 §10 address-record TTL for a shared (multicast) response — 120 seconds. */
    const val SHARED_TTL_SECONDS: UInt = 120u

    private const val HEADER_BYTES = 12
    private const val QUESTION_TAIL_BYTES = 4 // QTYPE(u16) + QCLASS(u16)
    private const val RECORD_TAIL_BYTES = 10 // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
    private const val CLASS_IN = 0x0001
    private const val CLASS_ANY = 0x00FF // RFC 1035 §3.2.5 QCLASS `*` — a querier that asks in every class
    private const val CLASS_MASK = 0x7FFF // the class field without the QU (question) / cache-flush (RR) top bit
    private const val CACHE_FLUSH_BIT = 0x8000 // RFC 6762 §10.2 — top bit of an ANSWER record's CLASS
    private const val QU_BIT = 0x8000 // RFC 6762 §5.4 unicast-response ("QU") bit in the question's QCLASS
    private const val QR_BIT = 0x8000 // RFC 1035 §4.1.1 — set on a response, clear on a query
    private const val OPCODE_SHIFT = 11
    private const val OPCODE_MASK = 0x000F
    private const val RESPONSE_FLAGS = 0x8400 // QR=1 (response) + AA=1 (authoritative), RFC 6762 §18.2/§18.4
    private const val COMPRESSION_MASK = 0xC0 // RFC 1035 §4.1.4: a label length byte with the top 2 bits set is a pointer
    private const val POINTER_OFFSET_MASK = 0x3F
    private const val POINTER_BYTES = 2
    private const val MAX_POINTER_HOPS = 8 // a name that chases more pointers than this is malicious, not compressed
    private const val LABEL_MAX = 0x3F
    private const val V4_RDLENGTH = 4
    private const val V6_RDLENGTH = 16

    /**
     * The most questions we will read out of one query. A real `.local` resolution asks one or two; a
     * QDCOUNT beyond this is either corrupt or an amplification attempt (every extra question is an extra
     * record we would be asked to emit), and is rejected as malformed rather than answered.
     */
    private const val MAX_QUESTIONS = 16

    /**
     * Encode a one-shot mDNS query for [name] (`<uuid>.local`) asking for [qType] (A or AAAA). The
     * transaction id is 0 (RFC 6762 §18.1: responders ignore it for multicast queries) and the QCLASS
     * carries the QU bit so a responder MAY unicast the reply straight back to our source port. Returns a
     * read-positioned [ReadBuffer] ready to hand to `DatagramChannel.send`.
     */
    fun encodeQuery(
        name: String,
        qType: Int,
        bufferFactory: BufferFactory,
    ): ReadBuffer {
        val buffer = bufferFactory.allocate(HEADER_BYTES + nameByteLength(name) + QUESTION_TAIL_BYTES, ByteOrder.BIG_ENDIAN)
        buffer.writeUShort(0u) // ID — 0 (ignored on multicast, RFC 6762 §18.1)
        buffer.writeUShort(0u) // flags — QR=0 (query), opcode 0, RD=0
        buffer.writeUShort(1u) // QDCOUNT
        buffer.writeUShort(0u) // ANCOUNT
        buffer.writeUShort(0u) // NSCOUNT
        buffer.writeUShort(0u) // ARCOUNT
        writeName(buffer, name)
        buffer.writeUShort(qType.toUShort())
        buffer.writeUShort((CLASS_IN or QU_BIT).toUShort())
        buffer.resetForRead()
        return buffer
    }

    /**
     * Walk a response [payload] and return the first address record of [wantType] (A→[IpAddress.V4],
     * AAAA→[IpAddress.V6]), or null if there is none or the datagram is truncated/malformed — the
     * name-blind view of [decodeAnswers], and what a resolver holding one outstanding query needs.
     */
    fun decodeAddress(
        payload: ReadBuffer,
        wantType: Int,
    ): IpAddress? =
        decodeAnswers(payload)
            .firstOrNull { record ->
                when (record.address) {
                    is IpAddress.V4 -> wantType == TYPE_A
                    is IpAddress.V6 -> wantType == TYPE_AAAA
                }
            }?.address

    /**
     * Every A / AAAA record in a response [payload], **with its owner name** — the shape a resolver sharing
     * one socket with the responder needs, because there the answer that lands may belong to any of several
     * outstanding queries and "the only responder is answering our exact query" stops being true.
     *
     * Tolerant by construction: it stops at the first record it cannot parse and returns what it read up to
     * there, rather than discarding the whole message. A responder is free to append records we have no
     * grammar for, and a trailing one we choke on must not cost us an address we already decoded.
     */
    fun decodeAnswers(payload: ReadBuffer): List<AnswerRecord> {
        val origin = payload.position()
        if (payload.remaining() < HEADER_BYTES) return emptyList()
        payload.readUnsignedShort() // ID
        payload.readUnsignedShort() // flags
        val questionCount = payload.readUnsignedShort().toInt()
        val answerCount = payload.readUnsignedShort().toInt()
        payload.readUnsignedShort() // NSCOUNT
        payload.readUnsignedShort() // ARCOUNT

        val records = mutableListOf<AnswerRecord>()
        repeat(questionCount) {
            readName(payload, origin) ?: return records
            if (payload.remaining() < QUESTION_TAIL_BYTES) return records
            payload.readUnsignedShort() // QTYPE
            payload.readUnsignedShort() // QCLASS
        }

        repeat(answerCount) {
            val name = readName(payload, origin) ?: return records
            if (payload.remaining() < RECORD_TAIL_BYTES) return records
            val type = payload.readUnsignedShort().toInt()
            payload.readUnsignedShort() // CLASS (top bit = cache-flush, RFC 6762 §10.2 — irrelevant here)
            payload.readUnsignedInt() // TTL
            val rdLength = payload.readUnsignedShort().toInt()
            if (rdLength < 0 || payload.remaining() < rdLength) return records
            when {
                type == TYPE_A && rdLength == V4_RDLENGTH -> records += AnswerRecord(name, readV4(payload))
                type == TYPE_AAAA && rdLength == V6_RDLENGTH -> records += AnswerRecord(name, readV6(payload))
                else -> skip(payload, rdLength) // a record we have no grammar for — step over its RDATA
            }
        }
        return records
    }

    /**
     * Decode an inbound **query** (RFC 1035 §4.1 header + question section) into an exhaustive
     * [QueryDecode]. Three outcomes, not a nullable [Query], because the two ways a datagram fails to be a
     * question put to us are worlds apart in what they mean: on a shared multicast group *every* response
     * every host on the link emits also lands on our socket ([QueryDecode.NotAQuery] — utterly routine),
     * whereas [QueryDecode.Malformed] is a truncated, over-long or corrupt message and worth noticing.
     * A well-formed query asking nothing decodes as [Decoded] with an empty question list.
     *
     * Known-answer suppression (RFC 6762 §7.1) is deliberately not honoured: we hold one address record per
     * name, so suppressing it would mean answering nothing at all where a querier that already has it asks
     * again — and a stale cache on the far side is exactly what an ICE candidate cannot afford.
     */
    fun decodeQuery(payload: ReadBuffer): QueryDecode {
        val origin = payload.position()
        if (payload.remaining() < HEADER_BYTES) return QueryDecode.Malformed
        val id = payload.readUnsignedShort()
        val flags = payload.readUnsignedShort().toInt()
        if (flags and QR_BIT != 0) return QueryDecode.NotAQuery // a response, not a question put to us
        if ((flags shr OPCODE_SHIFT) and OPCODE_MASK != 0) return QueryDecode.NotAQuery // not the standard QUERY opcode
        val questionCount = payload.readUnsignedShort().toInt()
        payload.readUnsignedShort() // ANCOUNT — known-answer suppression records, read past (see above)
        payload.readUnsignedShort() // NSCOUNT
        payload.readUnsignedShort() // ARCOUNT
        if (questionCount > MAX_QUESTIONS) return QueryDecode.Malformed

        val questions = mutableListOf<Question>()
        repeat(questionCount) {
            val name = readName(payload, origin) ?: return QueryDecode.Malformed
            if (payload.remaining() < QUESTION_TAIL_BYTES) return QueryDecode.Malformed
            val qType = payload.readUnsignedShort().toInt()
            val qClass = payload.readUnsignedShort().toInt()
            val klass = qClass and CLASS_MASK
            // A question in a class we do not serve is dropped rather than rejecting the whole query: the
            // querier may legitimately be asking several things, only some of them of us.
            if (klass == CLASS_IN || klass == CLASS_ANY) {
                questions += Question(name, qType, unicastResponse = qClass and QU_BIT != 0)
            }
        }
        return QueryDecode.Decoded(Query(id, questions))
    }

    /**
     * Encode an authoritative response carrying [answers], in the [shape] the querier's own transport
     * demands (RFC 6762 §6.7 legacy vs §6 shared). Returns a read-positioned [ReadBuffer].
     */
    fun encodeResponse(
        answers: List<AnswerRecord>,
        shape: ResponseShape,
        bufferFactory: BufferFactory,
    ): ReadBuffer {
        val echoed =
            when (shape) {
                ResponseShape.Shared -> emptyList()
                is ResponseShape.Legacy -> shape.query.questions
            }
        val ttl = if (shape is ResponseShape.Legacy) LEGACY_TTL_SECONDS else SHARED_TTL_SECONDS
        // A legacy resolver has no cache to flush and would not understand the bit (RFC 6762 §6.7 / §18.12).
        val recordClass = if (shape is ResponseShape.Legacy) CLASS_IN else (CLASS_IN or CACHE_FLUSH_BIT)
        val size =
            HEADER_BYTES +
                echoed.sumOf { nameByteLength(it.name) + QUESTION_TAIL_BYTES } +
                answers.sumOf { nameByteLength(it.name) + RECORD_TAIL_BYTES + rdLengthOf(it.address) }
        val buffer = bufferFactory.allocate(size, ByteOrder.BIG_ENDIAN)
        // A legacy response echoes the query's ID so the one-shot resolver can match it; a shared multicast
        // response carries 0, which every responder ignores (RFC 6762 §18.1).
        buffer.writeUShort(if (shape is ResponseShape.Legacy) shape.query.id else 0u)
        buffer.writeUShort(RESPONSE_FLAGS.toUShort())
        buffer.writeUShort(echoed.size.toUShort()) // QDCOUNT — the repeated question (legacy only)
        buffer.writeUShort(answers.size.toUShort()) // ANCOUNT
        buffer.writeUShort(0u) // NSCOUNT
        buffer.writeUShort(0u) // ARCOUNT
        for (question in echoed) {
            writeName(buffer, question.name)
            buffer.writeUShort(question.qType.toUShort())
            buffer.writeUShort(CLASS_IN.toUShort()) // echoed WITHOUT the QU bit — it was a request, not a fact
        }
        for (answer in answers) {
            writeName(buffer, answer.name)
            buffer.writeUShort(typeOf(answer.address).toUShort())
            buffer.writeUShort(recordClass.toUShort())
            buffer.writeUInt(ttl)
            buffer.writeUShort(rdLengthOf(answer.address).toUShort())
            writeAddress(buffer, answer.address)
        }
        buffer.resetForRead()
        return buffer
    }

    /** The RFC 1035 §3.2.2 TYPE that carries [address] — A for v4, AAAA for v6. */
    fun typeOf(address: IpAddress): Int =
        when (address) {
            is IpAddress.V4 -> TYPE_A
            is IpAddress.V6 -> TYPE_AAAA
        }

    /** One question from an inbound query (RFC 1035 §4.1.2), with RFC 6762 §5.4's QU bit read out of QCLASS. */
    data class Question(
        val name: String,
        val qType: Int,
        val unicastResponse: Boolean,
    )

    /** A decoded inbound query: the header [id] a legacy response must echo, and the questions asked. */
    data class Query(
        val id: UShort,
        val questions: List<Question>,
    )

    /** The exhaustive outcome of [decodeQuery] — see its KDoc for why the two failures are kept apart. */
    sealed interface QueryDecode {
        /** A well-formed standard query; [query] carries its id and every question in a class we serve. */
        data class Decoded(
            val query: Query,
        ) : QueryDecode

        /** A response, or an opcode other than QUERY — not addressed to us as a question. Routine. */
        data object NotAQuery : QueryDecode

        /** Truncated, over-long, or otherwise unparseable. A typed reject, never a throw (T0). */
        data object Malformed : QueryDecode
    }

    /** One address record — an owner [name] bound to an [address]. Both a decoded answer and one to emit. */
    data class AnswerRecord(
        val name: String,
        val address: IpAddress,
    )

    /**
     * Which of RFC 6762's two response shapes to emit. Sealed rather than a `legacy: Boolean`, because the
     * legacy shape needs the query it is answering (to echo its id and its questions) and the shared one
     * must not carry it — so "legacy without a query" is unrepresentable instead of merely wrong.
     */
    sealed interface ResponseShape {
        /** RFC 6762 §6: the ordinary multicast/QU response — no question section, cache-flush, full TTL. */
        data object Shared : ResponseShape

        /** RFC 6762 §6.7: a reply to a one-shot querier on an ephemeral port — echo [query], TTL 10, no cache-flush. */
        data class Legacy(
            val query: Query,
        ) : ResponseShape
    }

    private fun rdLengthOf(address: IpAddress): Int =
        when (address) {
            is IpAddress.V4 -> V4_RDLENGTH
            is IpAddress.V6 -> V6_RDLENGTH
        }

    private fun writeAddress(
        buffer: WriteBuffer,
        address: IpAddress,
    ) {
        when (address) {
            is IpAddress.V4 -> buffer.writeUInt(address.bits)
            is IpAddress.V6 -> {
                buffer.writeULong(address.hi)
                buffer.writeULong(address.lo)
            }
        }
    }

    // A wire-encoded DNS name's byte length: each label is len(u8)+bytes, then the zero root terminator.
    private fun nameByteLength(name: String): Int = labelsOf(name).sumOf { 1 + it.length } + 1

    private fun writeName(
        buffer: WriteBuffer,
        name: String,
    ) {
        for (label in labelsOf(name)) {
            buffer.writeByte(label.length.toByte())
            for (c in label) buffer.writeByte(c.code.toByte()) // `.local` names are ASCII
        }
        buffer.writeByte(0) // root label — terminates the name
    }

    private fun labelsOf(name: String): List<String> = name.trimEnd('.').split('.').filter { it.isNotEmpty() }

    private fun readV4(payload: ReadBuffer): IpAddress.V4 {
        var bits = 0u
        repeat(V4_RDLENGTH) { bits = (bits shl Byte.SIZE_BITS) or payload.readUnsignedByte().toUInt() }
        return IpAddress.V4(bits)
    }

    private fun readV6(payload: ReadBuffer): IpAddress.V6 {
        var hi = 0uL
        repeat(V6_RDLENGTH / 2) { hi = (hi shl Byte.SIZE_BITS) or payload.readUnsignedByte().toULong() }
        var lo = 0uL
        repeat(V6_RDLENGTH / 2) { lo = (lo shl Byte.SIZE_BITS) or payload.readUnsignedByte().toULong() }
        return IpAddress.V6(hi, lo)
    }

    /**
     * Read the DNS name at the current position and leave the buffer positioned just past it — a run of
     * length-prefixed labels ended by a zero byte, possibly redirected through RFC 1035 §4.1.4 compression
     * pointers ([origin] is where the *message* starts, since pointer offsets are message-relative). Null
     * means the message itself is unreadable from here; the caller stops.
     *
     * The buffer is left after the **first** pointer encountered, which is where the name ends on the wire,
     * so the caller reads the record that follows rather than whatever sits after the pointer's target.
     *
     * A pointer that does not point strictly **backwards**, one out of the message, or a chain longer than
     * [MAX_POINTER_HOPS] does not fail the message: the name simply ends there, with whatever labels were
     * read. Two reasons. It terminates — each hop must reach a strictly lower offset, so the classic
     * self-referential decompression bomb dies on its first hop rather than spinning forever. And it is what
     * the caller wants: pointer offsets are a compression detail of the *owner name*, while the record that
     * follows it is perfectly readable, so discarding a valid address over an unreassemblable name would
     * throw away the one thing the message was sent to carry.
     */
    private fun readName(
        payload: ReadBuffer,
        origin: Int,
    ): String? {
        val name = StringBuilder()
        var hops = 0
        var resumeAt = -1
        while (true) {
            if (payload.remaining() < 1) return truncated(payload, name, resumeAt)
            val length = payload.readUnsignedByte().toInt()
            when {
                length == 0 -> {
                    if (resumeAt >= 0) payload.position(resumeAt)
                    return name.toString()
                }
                (length and COMPRESSION_MASK) == COMPRESSION_MASK -> {
                    if (payload.remaining() < 1) return truncated(payload, name, resumeAt)
                    val low = payload.readUnsignedByte().toInt()
                    val pointerAt = payload.position() - POINTER_BYTES
                    if (resumeAt < 0) resumeAt = payload.position() // a pointer ends the name ON THE WIRE
                    val target = origin + (((length and POINTER_OFFSET_MASK) shl Byte.SIZE_BITS) or low)
                    if (++hops > MAX_POINTER_HOPS || target < origin || target >= pointerAt) {
                        payload.position(resumeAt)
                        return name.toString()
                    }
                    payload.position(target)
                }
                length <= LABEL_MAX -> {
                    if (payload.remaining() < length) return truncated(payload, name, resumeAt)
                    if (name.isNotEmpty()) name.append('.')
                    repeat(length) { name.append(payload.readUnsignedByte().toInt().toChar()) }
                }
                else -> return truncated(payload, name, resumeAt) // reserved 0b10 top bits — malformed
            }
        }
    }

    // A name that runs off the end: unreadable outright before any pointer was followed (the message is
    // truncated and the caller must stop), but merely unreassemblable once one was — there the wire position
    // after the pointer is known, so the record that follows is still readable.
    private fun truncated(
        payload: ReadBuffer,
        name: StringBuilder,
        resumeAt: Int,
    ): String? {
        if (resumeAt < 0) return null
        payload.position(resumeAt)
        return name.toString()
    }

    private fun skip(
        payload: ReadBuffer,
        count: Int,
    ) {
        payload.position(payload.position() + count)
    }
}
