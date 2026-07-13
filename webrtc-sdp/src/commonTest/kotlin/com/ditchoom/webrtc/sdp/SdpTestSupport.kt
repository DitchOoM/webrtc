package com.ditchoom.webrtc.sdp

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.PlatformBuffer

/**
 * Shared fixtures for the SDP T0 floor (RFC §7 / TESTING.md): real-world data-channel offers/answers
 * captured from the dominant stacks, plus buffer helpers. The vectors are the interop-grade corpus —
 * SDP has no RFC sample-vector suite (TESTING.md §3), so these stand in: each must parse to typed
 * fields and round-trip byte-for-byte. Every vector is built via [crlf] so it is canonical CRLF text
 * (each line terminated, including the last) — the form the codec emits and round-trips exactly.
 */
object SdpTestVectors {
    /** Joins [lines] into canonical SDP: CRLF between lines and a trailing CRLF (RFC 8866 §5). */
    fun crlf(vararg lines: String): String = lines.joinToString(Sdp.CRLF, postfix = Sdp.CRLF)

    /** A Chrome (libwebrtc) data-channel offer — BUNDLE, actpass, trickle, 256 KiB max message. */
    val chromeDataChannelOffer: String =
        crlf(
            "v=0",
            "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0",
            "a=extmap-allow-mixed",
            "a=msid-semantic: WMS",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=ice-ufrag:4ZcD",
            "a=ice-pwd:2/1muCWoOi3uLifh0NuRHlB5",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3B:8B:8A:1B:12:1C:AA:E9:2F:6A:0A:5F",
            "a=setup:actpass",
            "a=mid:0",
            "a=sctp-port:5000",
            "a=max-message-size:262144",
        )

    /** A Firefox data-channel offer — session-level fingerprint/ice-options, a host candidate, EOC. */
    val firefoxDataChannelOffer: String =
        crlf(
            "v=0",
            "o=mozilla...THIS_IS_SDPARTA-99.0 3987757614933345432 0 IN IP4 0.0.0.0",
            "s=-",
            "t=0 0",
            "a=sendrecv",
            "a=fingerprint:sha-256 6B:8A:1B:12:1C:AA:E9:2F:6A:0A:5F:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3B",
            "a=group:BUNDLE 0",
            "a=ice-options:trickle",
            "a=msid-semantic:WMS *",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=candidate:0 1 UDP 2122252543 192.168.1.5 52511 typ host",
            "a=sendrecv",
            "a=end-of-candidates",
            "a=ice-pwd:b6adf4e6f0f3a7e0c9d8b7a6f5e4d3c2",
            "a=ice-ufrag:6f2a1b3c",
            "a=mid:0",
            "a=setup:actpass",
            "a=sctp-port:5000",
            "a=max-message-size:1073741823",
        )

    /** A Pion (Go) data-channel answer — the answerer resolved setup:active. */
    val pionDataChannelAnswer: String =
        crlf(
            "v=0",
            "o=- 7194409909564976571 1719000000 IN IP4 0.0.0.0",
            "s=-",
            "t=0 0",
            "a=fingerprint:sha-256 12:1C:AA:E9:2F:6A:0A:5F:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3B:8B:8A:1B",
            "a=group:BUNDLE 0",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=setup:active",
            "a=mid:0",
            "a=sendrecv",
            "a=sctp-port:5000",
            "a=ice-ufrag:aQwErTyU",
            "a=ice-pwd:0123456789abcdef0123456789abcdef",
            "a=candidate:1 1 UDP 2130706431 10.0.0.7 43210 typ host",
            "a=end-of-candidates",
        )

    val all: List<String> = listOf(chromeDataChannelOffer, firefoxDataChannelOffer, pionDataChannelAnswer)
}

/** A read-ready UTF-8 [PlatformBuffer] over [text], sized exactly (the datagram the parser sees). */
fun sdpBufferOf(text: String): PlatformBuffer {
    val bytes = utf8Bytes(text)
    val buf = BufferFactory.Default.allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
    buf.writeString(text, Charset.UTF8)
    buf.resetForRead()
    buf.setLimit(bytes.size)
    return buf
}

private fun utf8Bytes(text: String): ByteArray {
    // A tiny independent UTF-8 sizer so tests don't lean on the code under test for the datagram length.
    val out = ArrayList<Byte>(text.length)
    var i = 0
    while (i < text.length) {
        val c = text[i]
        val cp =
            if (c.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate()) {
                val v = 0x10000 + ((c.code - 0xD800) shl 10) + (text[i + 1].code - 0xDC00)
                i++
                v
            } else {
                c.code
            }
        when {
            cp < 0x80 -> out += cp.toByte()
            cp < 0x800 -> {
                out += (0xC0 or (cp shr 6)).toByte()
                out += (0x80 or (cp and 0x3F)).toByte()
            }
            cp < 0x10000 -> {
                out += (0xE0 or (cp shr 12)).toByte()
                out += (0x80 or ((cp shr 6) and 0x3F)).toByte()
                out += (0x80 or (cp and 0x3F)).toByte()
            }
            else -> {
                out += (0xF0 or (cp shr 18)).toByte()
                out += (0x80 or ((cp shr 12) and 0x3F)).toByte()
                out += (0x80 or ((cp shr 6) and 0x3F)).toByte()
                out += (0x80 or (cp and 0x3F)).toByte()
            }
        }
        i++
    }
    return out.toByteArray()
}
