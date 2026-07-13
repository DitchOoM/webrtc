package com.ditchoom.webrtc.sdp

/**
 * One SDP line (RFC 8866 §5): a single-character [type] and its verbatim [value] (the text after the
 * `=`, with the trailing CRLF stripped). This is the round-trip-faithful unit — the parser keeps every
 * line, known or not, exactly as written, and the serializer re-emits `"$type=$value\r\n"`, so a
 * canonical CRLF document survives parse→encode byte-for-byte (mirrors STUN's `RawAttribute` keeping
 * unrecognized attributes intact). Typed meaning is layered on top by the field interpreters
 * ([Origin], [MediaLine], [attribute]); the line itself makes no semantic claim.
 */
public data class SdpLine(
    public val type: Char,
    public val value: String,
) {
    /**
     * Interprets this line as an attribute (`a=<name>` or `a=<name>:<value>`, RFC 8866 §5.13), or
     * null if it is not an `a=` line. A **property** attribute (`a=recvonly`) has a null
     * [Attribute.value]; a **value** attribute (`a=mid:0`) carries the text after the first `:`.
     */
    public fun attribute(): Attribute? {
        if (type != ATTRIBUTE_TYPE) return null
        val colon = value.indexOf(':')
        return if (colon < 0) {
            Attribute(value, null)
        } else {
            Attribute(value.substring(0, colon), value.substring(colon + 1))
        }
    }

    public companion object {
        /** The `a=` attribute line type (RFC 8866 §5.13). */
        public const val ATTRIBUTE_TYPE: Char = 'a'
    }
}

/**
 * A parsed `a=` attribute (RFC 8866 §5.13). [name] is the attribute name; [value] is the text after
 * the first `:`, or null for a property (flag) attribute with no value.
 */
public data class Attribute(
    public val name: String,
    public val value: String?,
)
