package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sdp.SdpParseResult.Reject
import com.ditchoom.webrtc.sdp.SdpParseResult.Success

/**
 * A parsed or hand-built SDP document (RFC 8866 §5): the session-level [sessionLines] (everything
 * before the first `m=`) and the ordered [mediaDescriptions]. This is the top of the round-trip-faithful
 * model — every line is retained verbatim, so [parse] followed by [encode] reproduces a canonical
 * CRLF document byte-for-byte, and the typed readers ([origin], [SdpSection.fingerprints], …) interpret
 * lines on demand without mutating the model (the SDP analogue of STUN's view-based decode).
 *
 * Text is decoded from the datagram exactly once (RFC §6, zero-copy as far as a text grammar allows);
 * from there parsing is index-based over that single [CharSequence] and produces line-value substrings
 * only, never a re-encode or per-token buffer.
 */
public class SessionDescription internal constructor(
    override val lines: List<SdpLine>,
    public val mediaDescriptions: List<MediaDescription>,
) : SdpSection {
    /** The session-level lines (before the first `m=`) — an alias for [lines] read at session scope. */
    public val sessionLines: List<SdpLine> get() = lines

    /** The typed origin line (`o=`, RFC 8866 §5.2), or null if absent/malformed. */
    public fun origin(): Origin? = lines.firstOrNull { it.type == 'o' }?.let { Origin.parse(it.value) }

    /** The session name (`s=`, RFC 8866 §5.3), or null if absent. */
    public fun sessionName(): String? = lines.firstOrNull { it.type == 's' }?.value

    /**
     * The BUNDLE groups (`a=group:BUNDLE <mid>…`, RFC 9143 §7) as lists of [Mid]. A group token that
     * is blank is dropped; a group with no semantics or an unknown one yields no entry.
     */
    public fun bundleGroups(): List<List<Mid>> =
        attributeValues("group").mapNotNull { v ->
            val sp = v.indexOf(' ')
            if (sp < 0) return@mapNotNull null
            val semantics = v.substring(0, sp)
            if (semantics != Sdp.GROUP_BUNDLE) return@mapNotNull null
            v
                .substring(sp + 1)
                .split(' ')
                .filter { it.isNotBlank() }
                .map(::Mid)
        }

    /** The media section for [mid], or null if none carries it. */
    public fun mediaFor(mid: Mid): MediaDescription? = mediaDescriptions.firstOrNull { it.mid() == mid }

    /**
     * Serializes this document to canonical CRLF text (RFC 8866 §5): each session line, then each
     * media section's `m=` line followed by its lines, every line terminated with CRLF. A document
     * from [parse] re-encodes byte-for-byte.
     */
    public fun toText(): String {
        val sb = StringBuilder()
        for (line in lines) {
            sb
                .append(line.type)
                .append('=')
                .append(line.value)
                .append(Sdp.CRLF)
        }
        for (m in mediaDescriptions) {
            sb
                .append(m.media.type)
                .append('=')
                .append(m.media.value)
                .append(Sdp.CRLF)
            for (line in m.lines) {
                sb
                    .append(line.type)
                    .append('=')
                    .append(line.value)
                    .append(Sdp.CRLF)
            }
        }
        return sb.toString()
    }

    /** Serializes [toText] into a freshly allocated read-ready buffer (UTF-8), sized exactly. */
    public fun encode(factory: BufferFactory = BufferFactory.Default): PlatformBuffer {
        val text = toText()
        val dest = factory.allocate(utf8ByteLength(text), ByteOrder.BIG_ENDIAN)
        dest.writeString(text, Charset.UTF8)
        dest.resetForRead()
        return dest
    }

    public companion object {
        /**
         * Parses one SDP document from [source] (from its current position to its limit). Never throws
         * on malformed bytes — every failure is a typed [Reject]. The text is read from the datagram
         * once; line values are substrings of that single decode.
         */
        public fun parse(source: ReadBuffer): SdpParseResult {
            val remaining = source.remaining()
            if (remaining == 0) return Reject(SdpRejectReason.Empty)
            val text =
                try {
                    source.readString(remaining, Charset.UTF8)
                } catch (_: Throwable) {
                    // Kotlin/JS's TextDecoder throws a raw JS error (not an Exception) on invalid UTF-8;
                    // catch Throwable so a hostile datagram is a typed reject, never a crash (STUN lesson).
                    return Reject(SdpRejectReason.NotText)
                }
            return parseText(text)
        }

        /**
         * Parses SDP already decoded to text (accepts any [CharSequence] — the datagram decode returns
         * one, avoiding a re-copy). Total — every failure is a typed [Reject].
         */
        public fun parseText(text: CharSequence): SdpParseResult {
            if (text.isEmpty()) return Reject(SdpRejectReason.Empty)

            val lines = ArrayList<SdpLine>()
            var index = 0
            var start = 0
            val n = text.length
            while (start < n) {
                var end = text.indexOf('\n', start)
                if (end < 0) end = n
                // Strip the CR of a CRLF terminator; a lone LF (or the unterminated final line) is fine.
                val lineEnd = if (end > start && text[end - 1] == '\r') end - 1 else end
                if (lineEnd == start && end == n) break // trailing empty segment after the final CRLF
                val parsed =
                    parseLine(text, start, lineEnd) ?: return Reject(SdpRejectReason.MalformedLine(index, text.substring(start, lineEnd)))
                lines += parsed
                index++
                start = end + 1
            }

            if (lines.isEmpty()) return Reject(SdpRejectReason.Empty)
            val first = lines[0]
            if (first.type != 'v') return Reject(SdpRejectReason.MissingVersion)
            if (first.value != Sdp.SUPPORTED_VERSION) return Reject(SdpRejectReason.UnsupportedVersion(first.value))

            return Success(split(lines))
        }

        /** Parses `text[start until lineEnd]` as a `<type>=<value>` line, or null if malformed. */
        private fun parseLine(
            text: CharSequence,
            start: Int,
            lineEnd: Int,
        ): SdpLine? {
            // RFC 8866 §5: a line is a single-character type, then '=', then the value.
            if (lineEnd - start < MIN_LINE_LENGTH) return null
            if (text[start + 1] != '=') return null
            return SdpLine(text[start], text.substring(start + 2, lineEnd))
        }

        /** Splits the flat line list at each `m=` into the session block and the media sections. */
        private fun split(lines: List<SdpLine>): SessionDescription {
            val firstMedia = lines.indexOfFirst { it.type == 'm' }
            if (firstMedia < 0) return SessionDescription(lines, emptyList())

            val sessionLines = lines.subList(0, firstMedia).toList()
            val media = ArrayList<MediaDescription>()
            var i = firstMedia
            while (i < lines.size) {
                val mLine = lines[i]
                var j = i + 1
                while (j < lines.size && lines[j].type != 'm') j++
                media += MediaDescription(mLine, lines.subList(i + 1, j).toList())
                i = j
            }
            return SessionDescription(sessionLines, media)
        }

        private const val MIN_LINE_LENGTH = 2 // "<type>=" — value may be empty (e.g. "a=")

        /** UTF-8 byte length of [text] without allocating (SDP lines are OpaqueString/token text). */
        private fun utf8ByteLength(text: String): Int {
            var bytes = 0
            var i = 0
            while (i < text.length) {
                val cp = text[i].code
                bytes +=
                    when {
                        cp < 0x80 -> 1
                        cp < 0x800 -> 2
                        cp in 0xD800..0xDBFF -> {
                            i++
                            4
                        } // high surrogate → 4-byte code point, skip the low surrogate
                        else -> 3
                    }
                i++
            }
            return bytes
        }
    }
}
