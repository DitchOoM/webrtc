package com.ditchoom.webrtc

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sctp.datachannel.send
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.promise
import kotlinx.coroutines.withTimeout
import kotlin.js.Promise
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * The W6 browser-delegation Karma test: drives two real in-browser `RTCPeerConnection`s through our
 * [RtcPeerConnection] delegation (offer/answer, trickle, a data-channel message) over a localhost
 * loopback — proving `peerConnectionSupport()` as a `BrowserDelegated.create(...)` maps our API onto the browser's own
 * `RTCPeerConnection` (ARCHITECTURE §1.1: the one target we wrap).
 *
 * Under Node (`RTCPeerConnection` absent) there is nothing to delegate to, so the loopback body no-ops
 * and the suite stays green on `jsNodeTest` — but it no-ops *after* asserting what the platform reports,
 * which is the regression guard for webrtc#126. This used to return [PeerConnectionSupport.Native], and a
 * caller that believed it got a session that gathered and checked normally and then died at the DTLS
 * handshake. The Node branch is now a stated, tested fact rather than an untested fallthrough.
 */
@OptIn(DelicateCoroutinesApi::class)
class PeerConnectionDelegationTest {
    @Test
    fun delegates_to_rtc_peer_connection_over_a_loopback(): Promise<Unit> =
        GlobalScope.promise {
            val support = peerConnectionSupport()
            if (support !is PeerConnectionSupport.BrowserDelegated) {
                // Node: nothing to delegate to — and the platform must SAY so rather than claim Native.
                assertEquals(
                    PeerConnectionSupport.Unavailable(PeerConnectionUnavailableReason.NoBlockingKeyAgreement),
                    support,
                    "js outside a browser must report the missing blocking raw-ECDH premaster at config time",
                )
                return@promise
            }

            val scope = CoroutineScope(Dispatchers.Default)
            val alice = support.create(scope)
            val bob = support.create(scope)

            trickle(scope, from = alice, to = bob)
            trickle(scope, from = bob, to = alice)

            val channel = alice.createDataChannel(DataChannelConfig(label = "chat"))

            val offer = alice.createOffer()
            alice.setLocalDescription(SdpType.Offer, offer)
            bob.setRemoteDescription(SdpType.Offer, offer)
            val answer = bob.createAnswer()
            bob.setLocalDescription(SdpType.Answer, answer)
            alice.setRemoteDescription(SdpType.Answer, answer)

            withTimeout(20.seconds) {
                val incoming = bob.incomingDataChannels.first()
                channel.send(textBuffer("hi-over-rtcpeerconnection"))
                assertEquals("hi-over-rtcpeerconnection", incoming.receive().first().contentAsString())
            }

            alice.close()
            bob.close()
        }

    private fun trickle(
        scope: CoroutineScope,
        from: RtcPeerConnection,
        to: RtcPeerConnection,
    ) {
        scope.launch {
            from.localIceCandidates.collect { to.addIceCandidate(it) }
        }
    }

    private fun textBuffer(s: String): ReadBuffer {
        val bytes = s.encodeToByteArray()
        val buf = BufferFactory.Default.allocate(maxOf(1, bytes.size), ByteOrder.BIG_ENDIAN)
        for (b in bytes) buf.writeByte(b)
        buf.resetForRead()
        buf.setLimit(bytes.size)
        return buf
    }

    private fun ReadBuffer.text(): String {
        val out = StringBuilder()
        for (i in position() until limit()) out.append((get(i).toInt() and 0xFF).toChar())
        return out.toString()
    }
}
