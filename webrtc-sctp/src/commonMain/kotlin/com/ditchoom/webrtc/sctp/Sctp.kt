package com.ditchoom.webrtc.sctp

import kotlin.jvm.JvmInline

/**
 * W5 placeholder. The real module is a pure-Kotlin dcSCTP-style subset over DTLS: chunks as
 * buffer-codec schemas, reassembly over `StreamProcessor`, the DataChannel exposing `StreamMux`.
 */
public object Sctp {
    public const val MODULE: String = "webrtc-sctp"
}

/** An SCTP stream identifier, wrapped so it is never confused with a [Tsn] or a raw `Int`. */
@JvmInline
public value class StreamId(
    public val value: Int,
) {
    init {
        require(value in 0..UShort.MAX_VALUE.toInt()) { "SCTP stream id is a u16, got $value" }
    }
}

/** An SCTP Transmission Sequence Number, distinct in the type system from [StreamId]. */
@JvmInline
public value class Tsn(
    public val value: UInt,
)
