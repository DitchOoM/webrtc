@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.ice.vnet

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.ice.toTransportAddress
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * A **virtual STUN server** (RFC 8489 Binding) bound as an ordinary [Vnet] endpoint: it answers a
 * Binding request with an XOR-MAPPED-ADDRESS reporting the source it observed. Behind a NAT that
 * observed source is the client's external mapping, so this is exactly how a host learns its
 * server-reflexive (srflx) candidate — and, crucially, a **symmetric** NAT hands this server a
 * different mapping than it hands a peer, which is what makes the vnet's srflx candidates behave (fail
 * to connect) the way they do on a real symmetric NAT.
 */
internal class StunServer(
    val address: SocketAddress,
    private val vnet: Vnet,
    private val scope: CoroutineScope,
) {
    private val channel: DatagramChannel = vnet.bind(address)

    fun start(): Job =
        scope.launch {
            while (true) {
                val received =
                    when (val result = channel.receive()) {
                        is DatagramReadResult.Received -> result
                        is DatagramReadResult.Closed -> return@launch
                    }
                val message =
                    when (val decoded = StunMessage.decode(received.datagram.payload)) {
                        is StunDecodeResult.Success -> decoded.message
                        is StunDecodeResult.Reject -> continue
                    }
                if (message.messageType.stunClass != StunClass.Request || message.messageType.method != StunMethod.Binding) continue
                val response =
                    StunMessageBuilder
                        .of(StunClass.SuccessResponse, StunMethod.Binding, message.transactionId)
                        .add(RawAttribute.ofXorMappedAddress(received.datagram.peer.toTransportAddress(), message.transactionId))
                        .addFingerprint()
                        .encode()
                channel.send(response, to = received.datagram.peer)
            }
        }
}
