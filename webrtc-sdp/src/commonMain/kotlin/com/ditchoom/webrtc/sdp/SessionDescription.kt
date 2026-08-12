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
 * Text is decoded from the datagram exactly once (ARCHITECTURE §6, zero-copy as far as a text grammar allows);
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

    /**
     * Serializes [toText] into a freshly allocated read-ready buffer (UTF-8), sized exactly.
     *
     * **Never throws** — the contract `SdpCodecFuzzer` and `SdpMalformedCorpusTest` both assert. Holding
     * it requires [wellFormed], because the line values reaching here are arbitrary application text
     * ([SessionDescriptionBuilder.line] takes a raw `String`), and buffer's `writeString` answers invalid
     * UTF-16 three different ways at 6.28.1 — **measured, not assumed** (`SdpEncodeLoneSurrogateTest`):
     *
     * | target | `writeString("\uD800€")` |
     * |---|---|
     * | JVM | throws `MalformedInputException` |
     * | Apple, JS | writes 6 (substitutes U+FFFD) |
     * | Linux K/N | writes 0, position unchanged (buffer's own `WriteStringLoneSurrogateTest`) |
     *
     * So a lone surrogate was an exception on one target, a 2-byte under-allocation on two (the counter
     * charged 4 for the pair it assumed), and a silent truncation on the fourth. Substituting first makes
     * every target write the same bytes, which is also what two of them already did.
     */
    public fun encode(factory: BufferFactory = BufferFactory.Default): PlatformBuffer {
        val text = wellFormed(toText())
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

        private const val ONE_BYTE_LIMIT = 0x80
        private const val TWO_BYTE_LIMIT = 0x800
        private const val HIGH_SURROGATE_FIRST = 0xD800
        private const val HIGH_SURROGATE_LAST = 0xDBFF
        private const val LOW_SURROGATE_FIRST = 0xDC00
        private const val LOW_SURROGATE_LAST = 0xDFFF

        /** U+FFFD REPLACEMENT CHARACTER — what a surrogate that is not part of a pair is encoded as. */
        private const val REPLACEMENT = '�'

        /** True when [text] holds a low surrogate at [i] — i.e. the char at [i] - 1 was a real pair's lead. */
        private fun lowSurrogateAt(
            text: String,
            i: Int,
        ): Boolean = i < text.length && text[i].code in LOW_SURROGATE_FIRST..LOW_SURROGATE_LAST

        /**
         * [text] with every surrogate that is not part of a well-formed pair replaced by [REPLACEMENT],
         * or [text] itself when there is none — the overwhelmingly common case, since SDP line values are
         * token/OpaqueString text. See [encode] for why this cannot be skipped.
         *
         * Kotlin has no common-source `String.isWellFormedUtf16`, and buffer's own `utf8Length()` carries
         * the same unpaired-surrogate defect this replaced (DitchOoM/buffer — reported 2026-08-12), so
         * neither is available to delegate to. Fold this into a shared helper if buffer grows one.
         */
        private fun wellFormed(text: String): String {
            var out: StringBuilder? = null
            var i = 0
            while (i < text.length) {
                val c = text[i]
                val code = c.code
                when {
                    code in HIGH_SURROGATE_FIRST..HIGH_SURROGATE_LAST && lowSurrogateAt(text, i + 1) -> {
                        out?.append(c)?.append(text[i + 1])
                        i += 2
                    }
                    code in HIGH_SURROGATE_FIRST..LOW_SURROGATE_LAST -> {
                        // A high surrogate with no low after it, or a low surrogate with no high before it.
                        if (out == null) out = StringBuilder(text.length).append(text, 0, i)
                        out.append(REPLACEMENT)
                        i++
                    }
                    else -> {
                        out?.append(c)
                        i++
                    }
                }
            }
            return out?.toString() ?: text
        }

        /**
         * UTF-8 byte length of [text] without allocating (SDP lines are OpaqueString/token text).
         *
         * Only ever called on [wellFormed] text, but correct standalone: a high surrogate is charged 4 —
         * and its low half consumed — **only when one follows**. Charging 4 unconditionally, as this did,
         * swallowed the next char without counting its bytes at all, so `"\uD800€"` measured 4 against the
         * 6 that Apple and JS write.
         */
        private fun utf8ByteLength(text: String): Int {
            var bytes = 0
            var i = 0
            while (i < text.length) {
                val cp = text[i].code
                bytes +=
                    when {
                        cp < ONE_BYTE_LIMIT -> 1
                        cp < TWO_BYTE_LIMIT -> 2
                        cp in HIGH_SURROGATE_FIRST..HIGH_SURROGATE_LAST && lowSurrogateAt(text, i + 1) -> {
                            i++
                            4
                        } // a real pair → one 4-byte code point; consume the low half
                        else -> 3
                    }
                i++
            }
            return bytes
        }
    }
}
