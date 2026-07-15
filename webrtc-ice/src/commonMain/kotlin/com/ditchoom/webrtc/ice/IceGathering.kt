@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.flow.DatagramChannel
import com.ditchoom.buffer.flow.DatagramReadResult
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.buffer.flow.SocketAddress
import com.ditchoom.webrtc.stun.StunAttributeType
import com.ditchoom.webrtc.stun.StunClass
import com.ditchoom.webrtc.stun.StunDecodeResult
import com.ditchoom.webrtc.stun.StunMessage
import com.ditchoom.webrtc.stun.StunMessageBuilder
import com.ditchoom.webrtc.stun.StunMethod
import com.ditchoom.webrtc.stun.TransactionId
import com.ditchoom.webrtc.stun.TransportAddress
import com.ditchoom.webrtc.stun.asXorMappedAddress
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.jvm.JvmInline
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * A network interface identity (RFC §5.3 timelines: a Wi-Fi→cellular flip is a `NetworkId` change).
 * When the id set changes under a live session, the driver triggers an ICE restart — the
 * `NetworkId`-change→restart fixture. Wrapped so it is never a bare `String`.
 */
@JvmInline
public value class NetworkId(
    public val value: String,
)

/** A local interface address to gather host candidates on, tagged with the [NetworkId] it belongs to. */
public data class LocalInterface(
    public val networkId: NetworkId,
    public val address: SocketAddress,
)

/**
 * The interface-enumeration seam (webrtc-owned, thin — RFC §11.4 note: `NetworkMonitor` proper lives in
 * socket core, but the ICE driver needs only this shape). A production actual watches the OS; a test
 * double drives interface flaps deterministically. Injected, so a `NetworkId` change is a scripted
 * timeline event, not a real Wi-Fi radio.
 */
public interface NetworkMonitor {
    /** The interfaces currently available to gather on. */
    public fun interfaces(): List<LocalInterface>

    /** Emits the new interface set whenever it changes (an interface up/down, Wi-Fi↔cellular). */
    public val changes: Flow<List<LocalInterface>>
}

/**
 * The mDNS resolution seam (RFC 8838 privacy candidates; RFC §11.4 decision: **resolve-only** in W3,
 * responder deferred). A browser peer advertises an `<uuid>.local` host candidate to hide its private
 * IP; before we can send checks to it we must resolve it to an address. Injected — a deterministic stub
 * in tests, a real multicast resolver in production — never a hardwired `224.0.0.251` socket in a core.
 */
public fun interface MdnsResolver {
    /** Resolve an `<uuid>.local` name to an address, or null if it cannot be resolved. */
    public suspend fun resolve(hostname: String): SocketAddress?
}

/**
 * Gather a **server-reflexive** address (RFC 8445 §5.1.1.2): send a STUN Binding to [stunServer] over
 * [socket] and read back the XOR-MAPPED-ADDRESS the server observed — behind a NAT, our external
 * mapping. A driver step (it does I/O), so it is a `suspend` function, clocked by the caller's
 * dispatcher; under `runTest` the [withTimeoutOrNull] rides virtual time. Returns null if no response
 * arrives (the STUN server is unreachable — gathering simply yields no srflx candidate).
 *
 * Must run **before** the socket is handed to the agent's receive loop, so this transient owns
 * `socket.receive()` without racing the checklist.
 */
@OptIn(ExperimentalTime::class)
public suspend fun gatherServerReflexive(
    socket: DatagramChannel,
    stunServer: SocketAddress,
    random: Random,
    timeout: Duration = DEFAULT_GATHER_TIMEOUT,
    retransmitInterval: Duration = DEFAULT_GATHER_RTO,
): TransportAddress? {
    val transactionId = TransactionId.random(random)
    val request = StunMessageBuilder.of(StunClass.Request, StunMethod.Binding, transactionId).addFingerprint().encode()
    // Retransmit the Binding every [retransmitInterval] until a matching response arrives or [timeout]
    // elapses (RFC 8489 §6.2.1 spirit) — a single lost request or response must not cost the whole srflx.
    return withTimeoutOrNull(timeout) {
        while (true) {
            socket.send(request, to = stunServer)
            val response = withTimeoutOrNull(retransmitInterval) { receiveMatchingResponse(socket, transactionId) }
            when {
                response == null -> Unit // no answer within the interval — retransmit
                // A success carries our reflexive address; an error response means no srflx here — give up.
                response.messageType.stunClass == StunClass.SuccessResponse ->
                    return@withTimeoutOrNull response.firstOrNull(StunAttributeType.XorMappedAddress)?.asXorMappedAddress(transactionId)
                else -> return@withTimeoutOrNull null
            }
        }
        @Suppress("UNREACHABLE_CODE")
        null
    }
}

// Read from [socket] until a STUN response bearing [transactionId] arrives (success or error), or the
// channel closes. The caller bounds this with a timeout to drive retransmission.
@OptIn(ExperimentalTime::class)
private suspend fun receiveMatchingResponse(
    socket: DatagramChannel,
    transactionId: TransactionId,
): StunMessage? {
    while (true) {
        val datagram =
            when (val result = socket.receive()) {
                is DatagramReadResult.Received -> result.datagram
                is DatagramReadResult.Closed -> return null
            }
        val message = (StunMessage.decode(datagram.payload) as? StunDecodeResult.Success)?.message ?: continue
        val stunClass = message.messageType.stunClass
        val isResponse = stunClass == StunClass.SuccessResponse || stunClass == StunClass.ErrorResponse
        if (message.transactionId == transactionId && isResponse) return message
    }
}

/** Default gathering round-trip budget — generous under virtual time, tight enough on a real network. */
public val DEFAULT_GATHER_TIMEOUT: Duration = 3.seconds

/** Default gather retransmit interval (RFC 8489 §6.2.1 initial RTO). */
public val DEFAULT_GATHER_RTO: Duration = 500.milliseconds
