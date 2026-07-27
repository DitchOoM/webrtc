@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import kotlinx.coroutines.CancellationException

/**
 * Read one datagram, treating a socket that **throws** because it was closed under the read exactly as
 * one that politely returned [DatagramReadResult.Closed].
 *
 * The buffer-flow contract says a closed channel yields [DatagramReadResult.Closed], and an in-memory
 * channel obliges. A real-UDP actual need not: socket-udp's `NioDatagramChannel.receive()` reaches into
 * its selector before re-checking its own closed flag, so a `close()` landing between the select
 * returning and that call raises `ClosedSelectorException` instead.
 *
 * That difference was invisible until ICE restart, because nothing in this stack closed a socket while a
 * read was in flight. Retiring the outgoing generation's sockets on nomination (RFC 8445 §9) does exactly
 * that, at three sites — the per-socket forwarder, the TURN allocation's demux loop, and server-reflexive
 * gathering — each of which reads in a coroutine launched into the **consumer's** scope. An escaped throw
 * there does not merely end that loop: it cancels the caller's scope and takes the process down. The
 * `jvm-restart` interop lane died twice on this, once per site.
 *
 * [CancellationException] is rethrown — structured cancellation is not a socket condition. Anything else
 * ends the read, which never wedges the agent: the pair simply stops receiving, and ICE's own consent and
 * establishment backstops reach a typed terminal on their own schedule.
 */
internal suspend fun DatagramChannel.receiveOrClosed(): DatagramReadResult =
    try {
        receive()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        DatagramReadResult.Closed()
    }
