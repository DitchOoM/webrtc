package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer

// A test-only buffer helper for the vnet servers. The SocketAddress <-> TransportAddress converters
// these servers use are production code — they live in com.ditchoom.webrtc.ice.toTransportAddress /
// toSocketAddress (the driver's I/O-edge bridge) and are imported from there.

/** A read-ready buffer of [text]'s UTF-8 bytes — a STUN short-term-credential key or attribute value. */
internal fun utf8Buffer(text: String): ReadBuffer {
    val buffer = BufferFactory.Default.allocate(text.encodeToByteArray().size, ByteOrder.BIG_ENDIAN)
    buffer.writeString(text, Charset.UTF8)
    buffer.resetForRead()
    return buffer
}
