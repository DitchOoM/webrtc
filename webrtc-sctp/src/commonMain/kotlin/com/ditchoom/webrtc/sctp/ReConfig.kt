package com.ditchoom.webrtc.sctp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.codec.DecodeContext
import com.ditchoom.buffer.codec.EncodeContext
import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import com.ditchoom.buffer.codec.annotations.RemainingBytes
import com.ditchoom.buffer.codec.annotations.When
import com.ditchoom.buffer.freeIfNeeded
import com.ditchoom.buffer.managed
import kotlin.jvm.JvmInline

// RFC 6525 "SCTP Stream Reconfiguration" — the six RE-CONFIG parameters (§4) that ride inside an
// [SctpChunk.ReConfig].
//
// Two layers, deliberately:
//   * the INTERNAL `*Wire` messages below are `@ProtocolMessage` data classes whose fields mirror the
//     wire one-for-one, so KSP generates the reads and writes. No hand-computed offsets — that is the
//     bug class `StateCookie`'s KDoc names ("indexed the buffer at base + 17 / base + 21 by hand, a
//     silent-corruption bug waiting for the next field"), and it is exactly what a run of `u32(0)`,
//     `u32(4)`, `u32(8)` would have reintroduced here.
//   * the PUBLIC [ReConfigParameter] hierarchy is the typed model the association handles: real
//     [StreamId]s, a [ReConfigResult] with named outcomes, and the two response TSNs paired so that
//     "one present, one absent" cannot be expressed.
//
// The two are separated because the wire cannot express what the model should. A stream id is a u16
// but [StreamId] wraps `Int` (and `@WireBytes` is unsupported on a value-class field), and an enum
// field's ordinal rides as a LEB128 varint rather than the fixed 32-bit assigned value RFC 6525 §4.4
// specifies. Mirroring the wire in the wire type and mapping once keeps both honest.
//
// Only the two parameters RFC 8831 §6.7 needs to close a data channel are ever ORIGINATED:
// [ReConfigParameter.OutgoingSsnReset] and [ReConfigParameter.Response]. The other four are decoded
// and answered with a typed refusal, never sent — a scope decision backed by what the interop peers
// actually implement: pion/sctp v1.8.19 ships exactly two RE-CONFIG parameter implementations
// (`param_outgoing_reset_request.go`, `param_reconfig_response.go`), and werift defines exactly one
// request class (`OutgoingSSNResetRequestParam`). Decoding all six keeps us correct against a peer
// that does send one.

/**
 * The RFC 6525 §4.1 Re-configuration Request Sequence Number — a 32-bit counter, one per endpoint,
 * that names a request so its [ReConfigParameter.Response] can be matched to it. Wrapped so it is
 * never confused with a [Tsn] or a raw `UInt`, both of which it sits beside in the same parameter.
 *
 * Its initial value is the endpoint's Initial TSN (RFC 6525 §5.1.1), which is why the association
 * seeds it from there rather than from zero. `@ProtocolMessage` over the scalar makes it a 4-byte
 * FixedSize field the generated codecs read and write directly, exactly as [Tsn] is.
 */
@JvmInline
@ProtocolMessage(wireOrder = Endianness.Big)
public value class ReConfigRequestSequenceNumber(
    public val value: UInt,
) {
    /** The next sequence number, wrapping modulo 2³². */
    public fun next(): ReConfigRequestSequenceNumber = ReConfigRequestSequenceNumber(value + 1u)

    /**
     * The previous sequence number, wrapping modulo 2³². Needed for RFC 6525 §4.1's Response Sequence
     * Number field, which a request that is *not* answering an incoming request fills with "the next
     * expected Re-configuration Request Sequence Number minus 1".
     */
    public fun previous(): ReConfigRequestSequenceNumber = ReConfigRequestSequenceNumber(value - 1u)
}

/**
 * The Result of a Re-configuration Response (RFC 6525 §4.4) — a closed set, so acting on a peer's
 * answer is an exhaustive `when` and a refusal carries its reason in the type system rather than as
 * an opaque integer.
 *
 * Not a wire type: [wireValue] is the fixed 32-bit encoding, mapped in [ReConfigParameter.Response]'s
 * conversion. It cannot be a codec field directly — an enum field's *ordinal* rides as a LEB128
 * varint, and `@WireBytes` is rejected on enum fields, so the generated form would be neither fixed
 * 32-bit nor keyed on these assigned values.
 */
@Suppress("MagicNumber") // the literals ARE the RFC 6525 §4.4 assigned codepoints; naming them twice adds nothing
public enum class ReConfigResult(
    public val wireValue: UInt,
) {
    /** `0` — the request was valid but there was nothing to do (the streams were already reset). */
    SuccessNothingToDo(0u),

    /** `1` — the reset was performed. */
    SuccessPerformed(1u),

    /** `2` — the receiver refuses to perform the request. */
    Denied(2u),

    /** `3` — a stream in the request had an SSN the receiver disagrees with. */
    ErrorWrongSsn(3u),

    /** `4` — another request from this peer is still outstanding (RFC 6525 §5.1.2). */
    ErrorRequestAlreadyInProgress(4u),

    /** `5` — the Request Sequence Number was not the one expected. */
    ErrorBadSequenceNumber(5u),

    /** `6` — the receiver accepted the request but cannot complete it yet (a deferred reset). */
    InProgress(6u),
    ;

    /** True for the two results that mean the peer honoured the request. */
    public val isSuccess: Boolean get() = this == SuccessNothingToDo || this == SuccessPerformed

    internal companion object {
        /** Decodes [wire], or null when it is not an assigned RFC 6525 §4.4 result. */
        internal fun ofWire(wire: UInt): ReConfigResult? = entries.firstOrNull { it.wireValue == wire }
    }
}

/**
 * One RFC 6525 §4 stream-reconfiguration parameter, as a **sealed hierarchy** — so handling a received
 * RE-CONFIG is an exhaustive `when` with no `else`, and adding a parameter kind is a compile error at
 * every call site until it is handled (DESIGN_PRINCIPLES §3).
 *
 * These are the *interpreted* views. The wire form is an ordinary [SctpParameter] inside an
 * [SctpChunk.ReConfig] — decode with [SctpParameter.asReConfigParameter], encode with [toParameter] —
 * which is what keeps a decoded chunk re-encoding byte-for-byte even when it carries a parameter this
 * model does not interpret.
 */
public sealed interface ReConfigParameter {
    /** The RFC 6525 §4 parameter type this variant encodes to. */
    public val type: ParameterType

    /** Encodes this parameter into its wire [SctpParameter] (TLV framing is owned by the chunk). */
    public fun toParameter(): SctpParameter

    /**
     * Outgoing SSN Reset Request (RFC 6525 §4.1) — "reset **my** outgoing streams", which are the
     * receiver's *incoming* streams. This is the one RFC 8831 §6.7 uses to close a data channel: each
     * side resets its own outgoing stream, and a peer that sees an incoming reset for a live channel
     * resets its outgoing half in turn.
     *
     * [senderLastAssignedTsn] is the last TSN the sender assigned on the streams being reset. A
     * receiver that has not yet seen every TSN up to it must **defer** the reset and answer
     * [ReConfigResult.InProgress] (RFC 6525 §5.2.2); resetting sooner would drop the SSN state out
     * from under data still in flight.
     *
     * An empty [streams] list means **every** outgoing stream (RFC 6525 §4.1) — kept in the type via
     * [resetsAllStreams], because "reset nothing" is not a thing the wire can say.
     */
    public data class OutgoingSsnReset(
        public val requestSequenceNumber: ReConfigRequestSequenceNumber,
        public val responseSequenceNumber: ReConfigRequestSequenceNumber,
        public val senderLastAssignedTsn: Tsn,
        public val streams: List<StreamId>,
    ) : ReConfigParameter {
        override val type: ParameterType get() = ParameterType.OutgoingSsnResetRequest

        /** True when this request applies to every outgoing stream (RFC 6525 §4.1: an empty list). */
        public val resetsAllStreams: Boolean get() = streams.isEmpty()

        override fun toParameter(): SctpParameter =
            encode(
                type,
                OutgoingSsnResetWire(
                    requestSequenceNumber,
                    responseSequenceNumber,
                    senderLastAssignedTsn,
                    streams.map { ResetStreamId(it.value.toUShort()) },
                ),
                OutgoingSsnResetWireCodec::encode,
            )
    }

    /**
     * Incoming SSN Reset Request (RFC 6525 §4.2) — "reset **your** outgoing streams". Decoded and
     * answered, never originated (see the file header). An empty [streams] means all.
     */
    public data class IncomingSsnReset(
        public val requestSequenceNumber: ReConfigRequestSequenceNumber,
        public val streams: List<StreamId>,
    ) : ReConfigParameter {
        override val type: ParameterType get() = ParameterType.IncomingSsnResetRequest

        override fun toParameter(): SctpParameter =
            encode(
                type,
                IncomingSsnResetWire(requestSequenceNumber, streams.map { ResetStreamId(it.value.toUShort()) }),
                IncomingSsnResetWireCodec::encode,
            )
    }

    /**
     * SSN/TSN Reset Request (RFC 6525 §4.3) — reset every SSN *and* restart both TSN spaces. Decoded
     * and refused, never originated: honouring it would have to unwind the retransmission queue, the
     * congestion controller's outstanding-bytes accounting and FORWARD-TSN together, and no peer in
     * the WebRTC profile asks for it.
     */
    public data class SsnTsnReset(
        public val requestSequenceNumber: ReConfigRequestSequenceNumber,
    ) : ReConfigParameter {
        override val type: ParameterType get() = ParameterType.SsnTsnResetRequest

        override fun toParameter(): SctpParameter = encode(type, SsnTsnResetWire(requestSequenceNumber), SsnTsnResetWireCodec::encode)
    }

    /**
     * Re-configuration Response (RFC 6525 §4.4) — the [result] of the request named by
     * [responseSequenceNumber].
     *
     * [tsns] is the RFC's optional 8-byte tail, present only when answering an SSN/TSN reset. It is
     * one nullable *pair* rather than two independent nullable TSNs, so "one present, one absent" is
     * unrepresentable in the model — the wire type keeps them separate because the wire does.
     */
    public data class Response(
        public val responseSequenceNumber: ReConfigRequestSequenceNumber,
        public val result: ReConfigResult,
        public val tsns: TsnPair? = null,
    ) : ReConfigParameter {
        override val type: ParameterType get() = ParameterType.ReConfigResponse

        override fun toParameter(): SctpParameter =
            encode(
                type,
                ReConfigResponseWire(
                    responseSequenceNumber,
                    result.wireValue,
                    tsns?.senderNextTsn,
                    tsns?.receiverNextTsn,
                ),
                ReConfigResponseWireCodec::encode,
            )
    }

    /** Add Outgoing Streams Request (RFC 6525 §4.5). Decoded and refused, never originated. */
    public data class AddOutgoingStreams(
        public val requestSequenceNumber: ReConfigRequestSequenceNumber,
        public val count: UShort,
    ) : ReConfigParameter {
        override val type: ParameterType get() = ParameterType.AddOutgoingStreamsRequest

        override fun toParameter(): SctpParameter =
            encode(type, AddStreamsWire(requestSequenceNumber, count, 0u), AddStreamsWireCodec::encode)
    }

    /** Add Incoming Streams Request (RFC 6525 §4.6). Decoded and refused, never originated. */
    public data class AddIncomingStreams(
        public val requestSequenceNumber: ReConfigRequestSequenceNumber,
        public val count: UShort,
    ) : ReConfigParameter {
        override val type: ParameterType get() = ParameterType.AddIncomingStreamsRequest

        override fun toParameter(): SctpParameter =
            encode(type, AddStreamsWire(requestSequenceNumber, count, 0u), AddStreamsWireCodec::encode)
    }

    /**
     * The two TSNs a Re-configuration Response carries in its long form (RFC 6525 §4.4) — always both
     * or neither, which is why they are one type rather than two nullable fields.
     */
    public data class TsnPair(
        public val senderNextTsn: Tsn,
        public val receiverNextTsn: Tsn,
    )

    private companion object {
        // Encodes a generated wire message into a caller-owned parameter value. The codec's own
        // wireSize is not consulted: `SctpParameter.ofValue` measures the buffer it is handed, so the
        // buffer is sized generously and its limit set to what was actually written.
        private inline fun <T> encode(
            type: ParameterType,
            message: T,
            encoder: (com.ditchoom.buffer.WriteBuffer, T, EncodeContext) -> Unit,
        ): SctpParameter {
            val buf = BufferFactory.managed().allocate(MAX_PARAMETER_VALUE_BYTES, ByteOrder.BIG_ENDIAN)
            encoder(buf, message, EncodeContext.Empty)
            val written = buf.position()
            buf.resetForRead()
            buf.setLimit(written)
            return SctpParameter.ofValue(type, buf)
        }

        // Upper bound on a RE-CONFIG parameter value: the 12-byte outgoing-reset prefix plus a stream
        // id for every stream in the 16-bit space. Nothing here ever approaches it — a data-channel
        // close names one stream — but sizing off the protocol's own ceiling rather than a guess keeps
        // the encode total for any input the model can hold.
        private const val MAX_PARAMETER_VALUE_BYTES = 12 + 2 * 0xFFFF
    }
}

// ── Wire messages (RFC 6525 §4) — one `@ProtocolMessage` per parameter value, fields mirroring the
// wire so KSP generates every read and write. Internal: the public model above is what callers see. ──

/**
 * One stream id inside a reset request's trailing list. A one-field message rather than a bare
 * scalar because `@RemainingBytes List<T>` requires `T` to be a `@ProtocolMessage` (the scalar-element
 * shape was retired in buffer-codec). `UShort` gives the RFC's 2-byte width at natural width, so no
 * `@WireBytes` is needed — which matters, since `@WireBytes` is rejected on a value-class field and
 * [StreamId] wraps `Int`.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class ResetStreamId(
    val value: UShort,
)

/** Outgoing SSN Reset Request value (RFC 6525 §4.1): 12 fixed bytes then a run of stream ids. */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class OutgoingSsnResetWire(
    val requestSequenceNumber: ReConfigRequestSequenceNumber,
    val responseSequenceNumber: ReConfigRequestSequenceNumber,
    val senderLastAssignedTsn: Tsn,
    @RemainingBytes val streams: List<ResetStreamId>,
)

/** Incoming SSN Reset Request value (RFC 6525 §4.2): 4 fixed bytes then a run of stream ids. */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class IncomingSsnResetWire(
    val requestSequenceNumber: ReConfigRequestSequenceNumber,
    @RemainingBytes val streams: List<ResetStreamId>,
)

/** SSN/TSN Reset Request value (RFC 6525 §4.3): the request sequence number alone. */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class SsnTsnResetWire(
    val requestSequenceNumber: ReConfigRequestSequenceNumber,
)

/**
 * Re-configuration Response value (RFC 6525 §4.4) — 8 bytes, optionally followed by both TSNs.
 *
 * The tail is the generator's cascading-optional-trailer shape (`@When("remaining >= N")`, the same
 * one MQTT v5's PUBACK/PUBREC family uses): after the two fixed fields, 8 bytes remaining means the
 * long form. [result] is a raw `UInt` rather than [ReConfigResult] because an enum field's ordinal
 * rides as a varint; the mapping to the typed result happens on the way out of this type.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class ReConfigResponseWire(
    val responseSequenceNumber: ReConfigRequestSequenceNumber,
    val result: UInt,
    @When("remaining >= 8") val senderNextTsn: Tsn?,
    @When("remaining >= 4") val receiverNextTsn: Tsn?,
)

/** Add Outgoing / Add Incoming Streams Request value (RFC 6525 §4.5, §4.6) — identical shapes. */
@ProtocolMessage(wireOrder = Endianness.Big)
internal data class AddStreamsWire(
    val requestSequenceNumber: ReConfigRequestSequenceNumber,
    val count: UShort,
    val reserved: UShort,
)

/**
 * The outcome of interpreting an [SctpParameter] as an RFC 6525 §4 parameter. A **typed reject**, not
 * a nullable — "this is not a RE-CONFIG parameter" and "this is one, but malformed" call for different
 * handling (ignore vs. answer with an error), and collapsing them into `null` would make the
 * association guess. Parse failure is never a throw (T0 discipline).
 */
public sealed interface ReConfigParameterDecode {
    /** The parameter was a well-formed RFC 6525 §4 parameter. */
    public data class Interpreted(
        public val parameter: ReConfigParameter,
    ) : ReConfigParameterDecode

    /** The parameter type is not one of the six RFC 6525 §4 types — not an error, just not ours. */
    public data object NotReConfig : ReConfigParameterDecode

    /**
     * The parameter type *is* an RFC 6525 §4 type, but its body does not match that type's required
     * shape — a truncated value, a stream-id run that is not a whole number of ids, or (for a
     * response) a Result field that is not an assigned RFC 6525 §4.4 value.
     */
    public data class Malformed(
        public val type: ParameterType,
        public val reason: ReConfigMalformedReason,
    ) : ReConfigParameterDecode
}

/** Why an RFC 6525 §4 parameter body was rejected. Sealed — the discriminant is the type, never a string. */
public sealed interface ReConfigMalformedReason {
    /** The value region was shorter than the parameter's fixed prefix, or not its exact fixed size. */
    public data class WrongLength(
        public val actual: Int,
    ) : ReConfigMalformedReason

    /** A reset request's trailing region was not a whole number of 2-byte stream ids. */
    public data class RaggedStreamList(
        public val trailingBytes: Int,
    ) : ReConfigMalformedReason

    /** A response carried a Result field that is not an assigned RFC 6525 §4.4 value. */
    public data class UnassignedResult(
        public val wireValue: UInt,
    ) : ReConfigMalformedReason
}

/**
 * Interprets this wire parameter as its RFC 6525 §4 [ReConfigParameter]. Total: a hostile length
 * yields a [ReConfigParameterDecode.Malformed] rather than a throw or an out-of-bounds read, so the
 * chunk still re-encodes byte-for-byte and the association decides what to answer.
 *
 * Lengths are validated *before* the generated codec runs — which is also what distinguishes the
 * response's short form from its long one — so the codec only ever sees a body it can read.
 */
public fun SctpParameter.asReConfigParameter(): ReConfigParameterDecode =
    when (type) {
        ParameterType.OutgoingSsnResetRequest -> decodeOutgoingSsnReset()
        ParameterType.IncomingSsnResetRequest -> decodeIncomingSsnReset()
        ParameterType.SsnTsnResetRequest -> decodeSsnTsnReset()
        ParameterType.ReConfigResponse -> decodeResponse()
        ParameterType.AddOutgoingStreamsRequest, ParameterType.AddIncomingStreamsRequest -> decodeAddStreams()
        else -> ReConfigParameterDecode.NotReConfig
    }

// The declared value length, bounded by what is actually there — decoded parameters are views over the
// datagram, so a lying length must not read past the slice.
private val SctpParameter.bodyLength: Int get() = minOf(length, value.remaining())

// The value region bounded to its declared length. Every decode below validates the length FIRST, so a
// generated codec only ever runs against a body whose shape it can read — which is what keeps the
// interpretation total (T0) without wrapping the codec in a catch.
// The value region bounded to its declared length, released the moment the codec has read it.
//
// `slice()` on a pooled datagram is `addRef()`, and `TrackedSlice` re-parents to the ROOT chunk — so
// this borrow is a reference against the received buffer. Every call site consumes it synchronously
// (the generated wire types hold value types only, never a view), so the release belongs here rather
// than at five call sites that could each forget it: "released exactly once" becomes a property of the
// shape. This used to be a bare `body()` whose result was dropped, which pinned the datagram once per
// RE-CONFIG parameter — the last pin in a full session.
private inline fun <T> SctpParameter.withBody(block: (ReadBuffer) -> T): T {
    val body = value.slice().also { it.setLimit(bodyLength) }
    return try {
        block(body)
    } finally {
        body.freeIfNeeded()
    }
}

private fun SctpParameter.malformed(reason: ReConfigMalformedReason) = ReConfigParameterDecode.Malformed(type, reason)

// Shared shape check for the two reset requests: a fixed prefix followed by a whole number of 2-byte
// stream ids. Returns the reject, or null when the body is well-formed.
private fun SctpParameter.checkStreamList(fixed: Int): ReConfigParameterDecode? {
    val n = bodyLength
    val trailing = n - fixed
    return when {
        n < fixed -> malformed(ReConfigMalformedReason.WrongLength(n))
        trailing % STREAM_ID_BYTES != 0 -> malformed(ReConfigMalformedReason.RaggedStreamList(trailing))
        else -> null
    }
}

private fun SctpParameter.decodeOutgoingSsnReset(): ReConfigParameterDecode {
    checkStreamList(OUTGOING_FIXED_BYTES)?.let { return it }
    val w = withBody { OutgoingSsnResetWireCodec.decode(it, DecodeContext.Empty) }
    return ReConfigParameterDecode.Interpreted(
        ReConfigParameter.OutgoingSsnReset(
            w.requestSequenceNumber,
            w.responseSequenceNumber,
            w.senderLastAssignedTsn,
            w.streams.map { StreamId(it.value.toInt()) },
        ),
    )
}

private fun SctpParameter.decodeIncomingSsnReset(): ReConfigParameterDecode {
    checkStreamList(INCOMING_FIXED_BYTES)?.let { return it }
    val w = withBody { IncomingSsnResetWireCodec.decode(it, DecodeContext.Empty) }
    return ReConfigParameterDecode.Interpreted(
        ReConfigParameter.IncomingSsnReset(w.requestSequenceNumber, w.streams.map { StreamId(it.value.toInt()) }),
    )
}

private fun SctpParameter.decodeSsnTsnReset(): ReConfigParameterDecode {
    val n = bodyLength
    if (n != SEQ_BYTES) return malformed(ReConfigMalformedReason.WrongLength(n))
    val w = withBody { SsnTsnResetWireCodec.decode(it, DecodeContext.Empty) }
    return ReConfigParameterDecode.Interpreted(ReConfigParameter.SsnTsnReset(w.requestSequenceNumber))
}

private fun SctpParameter.decodeResponse(): ReConfigParameterDecode {
    val n = bodyLength
    if (n != RESPONSE_SHORT_BYTES && n != RESPONSE_LONG_BYTES) return malformed(ReConfigMalformedReason.WrongLength(n))
    val w = withBody { ReConfigResponseWireCodec.decode(it, DecodeContext.Empty) }
    val result = ReConfigResult.ofWire(w.result) ?: return malformed(ReConfigMalformedReason.UnassignedResult(w.result))
    // The generated cascading trailer makes the two TSNs independently nullable because the wire does;
    // the model pairs them. The length check above already guaranteed both or neither, so a half-present
    // tail can only mean a body that lied about its shape.
    val tsns = pairTsns(w.senderNextTsn, w.receiverNextTsn) ?: return malformed(ReConfigMalformedReason.WrongLength(n))
    return ReConfigParameterDecode.Interpreted(
        ReConfigParameter.Response(w.responseSequenceNumber, result, tsns.value),
    )
}

// Both TSNs or neither. Returns null for the illegal half-present case — distinct from a successful
// "neither", which is why the success carries a nested nullable rather than collapsing the two.
private fun pairTsns(
    sender: Tsn?,
    receiver: Tsn?,
): Optional<ReConfigParameter.TsnPair>? =
    when {
        sender != null && receiver != null -> Optional(ReConfigParameter.TsnPair(sender, receiver))
        sender == null && receiver == null -> Optional(null)
        else -> null
    }

/** A present-but-possibly-null result, so "absent legally" and "malformed" stay distinguishable. */
private class Optional<T>(
    val value: T?,
)

private fun SctpParameter.decodeAddStreams(): ReConfigParameterDecode {
    val n = bodyLength
    if (n != ADD_STREAMS_BYTES) return malformed(ReConfigMalformedReason.WrongLength(n))
    val w = withBody { AddStreamsWireCodec.decode(it, DecodeContext.Empty) }
    val parameter =
        if (type == ParameterType.AddOutgoingStreamsRequest) {
            ReConfigParameter.AddOutgoingStreams(w.requestSequenceNumber, w.count)
        } else {
            ReConfigParameter.AddIncomingStreams(w.requestSequenceNumber, w.count)
        }
    return ReConfigParameterDecode.Interpreted(parameter)
}

private const val SEQ_BYTES = 4
private const val STREAM_ID_BYTES = 2
private const val OUTGOING_FIXED_BYTES = 12 // req seq(4) + response seq(4) + last assigned TSN(4)
private const val INCOMING_FIXED_BYTES = 4 // req seq(4)
private const val RESPONSE_SHORT_BYTES = 8 // response seq(4) + result(4)
private const val RESPONSE_LONG_BYTES = 16 // + sender next TSN(4) + receiver next TSN(4)
private const val ADD_STREAMS_BYTES = 8 // req seq(4) + count(2) + reserved(2)
