package com.ditchoom.webrtc.sdp

import kotlin.jvm.JvmInline

/**
 * W6 placeholder. The real module is a hand-written text parser/writer (RFC 8866) held to the same
 * T0 rigor + fuzz floor as the binary codecs. Placeholder only, to build/publish the module tree.
 */
public object Sdp {
    public const val MODULE: String = "webrtc-sdp"
}

/** A media-section identifier (`a=mid:`), wrapped so it is never interchangeable with a bare string. */
@JvmInline
public value class Mid(
    public val value: String,
) {
    init {
        require(value.isNotBlank()) { "mid must not be blank" }
    }
}
