@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.flow.AddressedDatagramChannel
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
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.jvm.JvmInline
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * A network interface identity (ARCHITECTURE §5.3 timelines: a Wi-Fi→cellular flip is a `NetworkId` change).
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
 * The interface-enumeration seam (webrtc-owned, thin — the ICE driver needs only this shape).
 * [SystemNetworkMonitor] is the production implementation; a test double drives interface flaps
 * deterministically. Injected, so a `NetworkId` change is a scripted timeline event, not a real Wi-Fi radio.
 *
 * This is **not** a duplicate of `com.ditchoom:network-monitor`'s contract, and the distinction is
 * structural. Socket's monitor reports one sealed `NetworkState` carrying a link identity
 * (`Link(kind, handle)`, whose discriminator is documented as a numeric OS handle, "never an
 * interface-name string"); it carries no addresses. This one reports the **addresses** ICE can gather on, because
 * [IceAgentDriver.pathRidesOneOf] compares the selected pair's local IP against them. So
 * [SystemNetworkMonitor] consumes socket's monitor as its *trigger* and enumerates the addresses itself —
 * the two answer different questions and both are needed.
 */
public interface NetworkMonitor {
    /** The interfaces currently available to gather on. */
    public fun interfaces(): List<LocalInterface>

    /** Emits the new interface set whenever it changes (an interface up/down, Wi-Fi↔cellular). */
    public val changes: Flow<List<LocalInterface>>

    /**
     * Emits when a probe **failed**, so a caller can tell "the interfaces did not change" from "we could
     * not find out" — two very different things that [changes] alone renders identically, since a failed
     * probe correctly emits nothing (an empty set would read as *"the selected pair's interface is
     * gone"*, restarting a healthy session).
     *
     * Defaulted to empty so a test double or an existing implementation need not supply one; a monitor
     * whose enumeration cannot fail has nothing to report here.
     */
    public val probeFailures: Flow<InterfaceEnumerationFailure> get() = emptyFlow()
}

/**
 * The mDNS resolution seam (RFC 8838 privacy candidates; ARCHITECTURE §11.4: **resolve-only** here,
 * responder deferred). A browser peer advertises an `<uuid>.local` host candidate to hide its private
 * IP; before we can send checks to it we must resolve it to an address. Injected — a deterministic stub
 * in tests, a real multicast resolver in production — never a hardwired `224.0.0.251` socket in a core.
 */
public fun interface MdnsResolver {
    /** Resolve an `<uuid>.local` name to a [MdnsResolution]. */
    public suspend fun resolve(hostname: String): MdnsResolution
}

/**
 * The outcome of an mDNS resolution — a sealed result, never a nullable address, so "resolved" always
 * carries the address it found and a future state (e.g. "resolving") is a new case, not an overloaded
 * `null`. A caller `when`s over it exhaustively.
 */
public sealed interface MdnsResolution {
    /** The `.local` name resolved to [address]. */
    public data class Resolved(
        public val address: SocketAddress,
    ) : MdnsResolution

    /** The name could not be resolved (no responder, or not a resolvable `.local` name). */
    public data object Unresolved : MdnsResolution
}

/**
 * Resolve a parsed [CandidateParse.MdnsHost] to a concrete host [IceCandidate] via this resolver, or null
 * if the `<uuid>.local` name has no responder ([MdnsResolution.Unresolved]) — an unresolvable privacy
 * candidate is simply dropped, never checked. mDNS resolves a **name to an address** (RFC 6762); the
 * candidate's own [port][CandidateParse.MdnsHost.port] and browser-supplied foundation/priority ride the
 * line unobfuscated, so the resolved IP is combined with them (the resolution's port, if any, is ignored).
 */
public suspend fun MdnsResolver.resolveHostCandidate(mdns: CandidateParse.MdnsHost): IceCandidate? =
    when (val resolution = resolve(mdns.hostname)) {
        is MdnsResolution.Resolved ->
            IceCandidate.Host(
                address = TransportAddress(resolution.address.toTransportAddress().ip, mdns.port.toUShort()),
                component = mdns.component,
                transport = IceTransport.Udp,
                foundation = mdns.foundation,
                priority = mdns.priority,
            )
        MdnsResolution.Unresolved -> null
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
 *
 * **One buffer, every transmission, released once.** The Binding is built once and re-sent as-is:
 * socket's datagram channels are contractually *send-does-not-consume* — every backend transmits the
 * window `[position, limit)` without advancing it (io_uring reads `nativeAddress + position()`; the
 * NIO, Node and Apple paths each take their own internal view). So there is no need to hand `send` a
 * fresh slice per attempt, and doing so would take a reference on a pooled chunk that this function
 * would then have to give back one-for-one. What it does owe is the request itself: nothing upstream
 * can release it, because this runs before the agent that would do the releasing exists.
 */
@OptIn(ExperimentalTime::class)
public suspend fun gatherServerReflexive(
    socket: AddressedDatagramChannel,
    stunServer: SocketAddress,
    random: Random,
    timeout: Duration = DEFAULT_GATHER_TIMEOUT,
    retransmitInterval: Duration = DEFAULT_GATHER_RTO,
    // The datagram allocator — MUST be the injected one on a real socket: a native-UDP send (socket-udp's
    // io_uring) rejects a GC-heap buffer, so the default is only safe on the in-memory vnet. The driver
    // threads `IceConfig.bufferFactory` here (a real-network fix; the vnet never exercised this).
    bufferFactory: BufferFactory = networkBuffer(),
): ServerReflexiveResult {
    val transactionId = TransactionId.random(random)
    val request =
        StunMessageBuilder
            .of(
                StunClass.Request,
                StunMethod.Binding,
                transactionId,
                bufferFactory,
            ).addFingerprint()
            .encode(bufferFactory)
    // Retransmit the Binding every [retransmitInterval] until a matching response arrives or [timeout]
    // elapses (RFC 8489 §6.2.1 spirit) — a single lost request or response must not cost the whole srflx.
    // `finally`, not a release after the loop: the answered path returns from inside it, the silent path
    // is unwound by the enclosing timeout, and a cancelled gather (the socket closed under us, an ICE
    // restart superseding this one) never reaches either. All three owe the same one release.
    // Remembers the last refusal so a gather in which *nothing* was ever transmitted can say so, instead
    // of reporting the STUN server as silent. Only meaningful while [everSent] stays false — see
    // [ServerReflexiveResult.Unavailable.SendFailed].
    var lastSendFailure: Throwable? = null
    var everSent = false
    try {
        val result =
            withTimeoutOrNull(timeout) {
                while (true) {
                    // A refused send is *this attempt* failing, not the gather failing. The loop exists
                    // precisely so a single lost request does not cost the whole srflx candidate, and a
                    // raised `sendto` bypassed that tolerance entirely — one transient refusal and the
                    // exception left the loop, the `withTimeoutOrNull`, and the gather. Falling through
                    // to the interval wait retransmits exactly as a dropped datagram already does.
                    //
                    // Tolerance is not the same as silence, though: a *permanent* refusal — a heap
                    // bufferFactory on a native socket (#125), a closed channel — would otherwise burn
                    // the whole budget and report `NoResponse`, blaming a server we never contacted. So
                    // the outcome is remembered, and a gather that never got a single datagram out ends
                    // as `SendFailed` instead.
                    when (val sent = socket.sendOrFailure(request, to = stunServer)) {
                        IceTransmitResult.Sent -> everSent = true
                        is IceTransmitResult.Failed -> {
                            lastSendFailure = sent.cause
                            // The one reason worth short-circuiting: the socket has already measured
                            // this payload against its limit, so re-sending the same bytes every
                            // [retransmitInterval] until [timeout] cannot do anything but waste the
                            // budget. Every other reason stays retryable (see IceTransmitFailureReason).
                            if (sent.reason is IceTransmitFailureReason.PayloadTooLarge) {
                                return@withTimeoutOrNull ServerReflexiveResult.Unavailable.SendFailed(sent.cause)
                            }
                        }
                    }
                    val response = withTimeoutOrNull(retransmitInterval) { receiveMatchingResponse(socket, transactionId) }
                    when {
                        response == null -> Unit // no answer within the interval — retransmit
                        response.messageType.stunClass == StunClass.SuccessResponse -> {
                            val mapped = response.firstOrNull(StunAttributeType.XorMappedAddress)?.asXorMappedAddress(transactionId)
                            return@withTimeoutOrNull mapped?.let { ServerReflexiveResult.Discovered(it) }
                                ?: ServerReflexiveResult.Unavailable.MalformedResponse
                        }
                        else -> return@withTimeoutOrNull ServerReflexiveResult.Unavailable.Rejected
                    }
                }
                @Suppress("UNREACHABLE_CODE")
                ServerReflexiveResult.Unavailable.NoResponse
            }
        // Overall timeout. Which silence it was depends on whether anything ever left the socket.
        result?.let { return it }
        val neverSent = lastSendFailure
        return if (!everSent && neverSent != null) {
            ServerReflexiveResult.Unavailable.SendFailed(neverSent)
        } else {
            ServerReflexiveResult.Unavailable.NoResponse // the server genuinely never answered
        }
    } finally {
        request.freeNativeMemory()
    }
}

/**
 * The outcome of server-reflexive gathering — a sealed result rather than a nullable address, so a
 * discovered srflx always carries its transport address and the absence of one is an exhaustively
 * handled cause. [Unavailable] is itself a sealed hierarchy: the reasons a srflx is missing are
 * protocol-distinct (no answer vs a rejection vs a malformed reply), so they are separate cases, not a
 * single lumped sentinel. A caller that only needs success/failure matches `is Unavailable`; one that
 * wants the cause `when`s over its variants — both exhaustive, no overloaded `null`.
 */
public sealed interface ServerReflexiveResult {
    /** The STUN server observed and returned our reflexive [address]. */
    public data class Discovered(
        public val address: TransportAddress,
    ) : ServerReflexiveResult

    /** No srflx candidate was gathered — see the exhaustive cause. */
    public sealed interface Unavailable : ServerReflexiveResult {
        /** No response arrived within the budget — the server is unreachable, silent, or the path is lossy. */
        public data object NoResponse : Unavailable

        /** The server answered the Binding with an error response (it declined to reflect the address). */
        public data object Rejected : Unavailable

        /** The server answered success, but with no readable XOR-MAPPED-ADDRESS (a malformed reflection). */
        public data object MalformedResponse : Unavailable

        /**
         * **Not one Binding left the socket** — every transmission was refused locally, so the server was
         * never asked and its silence means nothing.
         *
         * Distinct from [NoResponse] on purpose, and the distinction is the whole reason this variant
         * exists. Both end with no srflx candidate, but they point in opposite directions: [NoResponse]
         * says look at the network or the server, while this says look at *this process* — a closed
         * socket, a payload past the interface MTU, or the case that motivated it, a `bufferFactory`
         * whose buffers the platform's socket cannot send from (webrtc#125). Collapsing them would make a
         * local misconfiguration present as an unreachable STUN server, which is the exact
         * "an absent candidate is indistinguishable from a server that failed to answer" failure the
         * typed gathering notices exist to prevent.
         *
         * Only reported when **no** attempt succeeded. A gather that got one Binding out and then failed
         * is a lossy path, which retransmission already covers and [NoResponse] already describes.
         */
        public data class SendFailed(
            /** What the socket raised on the last refused attempt. Diagnostic payload, never a discriminant. */
            public val cause: Throwable,
        ) : Unavailable
    }
}

// Read from [socket] until a STUN response bearing [transactionId] arrives (success or error), or the
// channel closes. The caller bounds this with a timeout to drive retransmission.
@OptIn(ExperimentalTime::class)
private suspend fun receiveMatchingResponse(
    socket: AddressedDatagramChannel,
    transactionId: TransactionId,
): StunMessage? {
    while (true) {
        val datagram =
            when (val result = socket.receiveOrClosed()) {
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
