package com.ditchoom.webrtc.sctp.datachannel

import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import kotlin.test.fail

/**
 * Receive-side helpers that assert the message **variant** a fixture expects before reading it.
 *
 * Deliberately not production API. A `payload.bytesOrEmpty`-style accessor would read a `Text` message as
 * zero bytes and let a test that meant to check content pass while checking nothing — the class of green
 * test this repo has been bitten by. Here a wrong variant fails loudly, naming what arrived.
 */
internal fun DataChannelPayload.expectBinary(): ReadBuffer =
    when (this) {
        is DataChannelPayload.Binary -> bytes
        is DataChannelPayload.Text -> fail("expected a Binary message, got Text(\"$text\")")
    }

internal fun DataChannelPayload.expectText(): CharSequence =
    when (this) {
        is DataChannelPayload.Text -> text
        is DataChannelPayload.Binary -> fail("expected a Text message, got Binary(${bytes.remaining()} bytes)")
    }

/** The UTF-8 content of a **binary** message — for fixtures that ship readable bytes through the wire. */
internal fun DataChannelPayload.expectBinaryAsString(): String {
    val buffer = expectBinary()
    return buffer.readString(buffer.remaining(), Charset.UTF8).toString()
}
