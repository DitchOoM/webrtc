@file:OptIn(ExperimentalDatagramApi::class)

package com.ditchoom.webrtc.testsuite.vnet

import com.ditchoom.buffer.flow.AddressedDatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.buffer.use
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
 * server-reflexive (srflx) candidate — and a **symmetric** NAT hands this server a different mapping
 * than it hands a peer, which is what makes the vnet's srflx candidates fail to connect the way they do
 * on a real symmetric NAT.
 */
internal class StunServer(
    val address: SocketAddress,
    private val vnet: Vnet,
    private val scope: CoroutineScope,
) {
    private val channel: AddressedDatagramChannel = vnet.bind(address)

    fun start(): Job =
        scope.launch {
            while (true) {
                val received =
                    when (val result = channel.receive()) {
                        is DatagramReadResult.Received -> result
                        is DatagramReadResult.Closed -> return@launch
                    }
                // This loop is the LAST READER of every datagram it takes: a decoded attribute is a borrow
                // that dies with the parse, and nothing downstream keeps a view. So it consumes it —
                // scoped to `use`, which releases on every way out of the block, which is what lets a
                // consumer's [com.ditchoom.webrtc.testsuite.harness.BufferCensus] read zero.
                received.datagram.payload.use { payload ->
                    val message =
                        when (val decoded = StunMessage.decode(payload)) {
                            is StunDecodeResult.Success -> decoded.message
                            is StunDecodeResult.Reject -> return@use
                        }
                    // Decoding takes a REFERENCE per attribute — on a pooled payload each `RawAttribute` is
                    // an `addRef`'d slice — so freeing the datagram is not enough: without this the chunk
                    // stays pinned, invisible to every free-counting check and visible only to the pool.
                    try {
                        if (message.messageType.stunClass != StunClass.Request ||
                            message.messageType.method != StunMethod.Binding
                        ) {
                            return@use
                        }
                        // The encoded response is scoped the same way: `send` has finished reading by the
                        // time it returns — the vnet copies on the delivery path — so it is spent at the call.
                        StunMessageBuilder
                            .of(StunClass.SuccessResponse, StunMethod.Binding, message.transactionId)
                            .add(RawAttribute.ofXorMappedAddress(received.datagram.peer.toTransportAddress(), message.transactionId))
                            .addFingerprint()
                            .encode()
                            .use { channel.send(it, to = received.datagram.peer) }
                    } finally {
                        message.release()
                    }
                }
            }
        }
}
