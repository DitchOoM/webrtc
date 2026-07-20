@file:OptIn(ExperimentalTime::class, ExperimentalCoroutinesApi::class)

package com.ditchoom.webrtc

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.dtls.CertificateFingerprint
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.dtls.DtlsEngine
import com.ditchoom.webrtc.dtls.DtlsException
import com.ditchoom.webrtc.dtls.DtlsFailureReason
import com.ditchoom.webrtc.dtls.DtlsState
import com.ditchoom.webrtc.dtls.DtlsStep
import com.ditchoom.webrtc.ice.IceDataTransport
import com.ditchoom.webrtc.sctp.datachannel.SctpDatagramTransport
import com.ditchoom.webrtc.sdp.Fingerprint
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import com.ditchoom.webrtc.dtls.DtlsRole as EngineRole

/**
 * The real DTLS transport (W4) — a **driver** for the caller-clocked, sans-io [DtlsEngine] (RFC §5.1:
 * cores own truth, drivers own I/O). The [DtlsEngine] it drives is now the **pure-Kotlin** DTLS 1.3/1.2
 * engine (W4b — no native dependency), which is why this class is named for that, not for BoringSSL: it
 * has never been a BoringSSL wrapper on this branch, and BoringSSL now lives only as a `linuxTest`
 * differential oracle. It is the swap that replaces [PlaintextDtls] at [DtlsTransportFactory.secure]:
 * nothing above (SCTP, PeerConnection) or below (ICE) changes shape.
 *
 * The engine has no clock, no coroutine and no socket of its own, so this class supplies all three:
 * one **pump** coroutine owns the engine and serializes every interaction with it — inbound records from
 * the ICE seam, outbound application data, and expired DTLS timers all funnel through a single `select`,
 * exactly as [com.ditchoom.webrtc.ice.IceAgentDriver] clocks the ICE core. The engine is not
 * thread-safe, and this is what makes that safe by construction rather than by convention. Time comes
 * from the injected [clock], so a whole handshake — retransmissions included — replays under `runTest`
 * at zero wall-clock.
 *
 * **One factory is one endpoint identity.** The certificate is generated when this object is
 * constructed, which is what lets [localFingerprint] be advertised in the offer before `a=setup`
 * decides the role (RFC 8842). Construct one per [NativePeerConnection] and [secure] once:
 *
 * ```kotlin
 * val dtls = PureKotlinDtls(scope, clock)         // identity exists now — the a=fingerprint is readable
 * NativePeerConnection(scope, clock, random, binder, gathering, dtls = dtls)
 * ```
 *
 * The pure-Kotlin engine runs on **every non-browser target** (JVM/Android/Apple/Linux) over
 * buffer-crypto's blocking primitives. Browsers never construct this — `peerConnectionSupport()`
 * delegates to `RTCPeerConnection` there — because the one async-only crypto seam (raw ECDH on
 * js/wasm) fails a handshake with a typed [DtlsFailureReason.BackendUnavailable] rather than blocking.
 *
 * @param config DTLS seams. Pass a **pooled native** `bufferFactory` in production — a native-backed
 *   buffer skips the staging copy the GC-heap default needs on the record layer's hot path.
 */
public class PureKotlinDtls(
    private val scope: CoroutineScope,
    private val clock: () -> Instant,
    private val config: DtlsConfig = DtlsConfig(),
) : DtlsTransportFactory {
    private val engine: DtlsEngine =
        try {
            DtlsEngine(config)
        } catch (e: DtlsException) {
            throw WebRtcException(PeerConnectionFailureReason.Dtls(e.reason), e)
        }

    override val localFingerprint: Fingerprint = Fingerprint("sha-256", engine.localFingerprint.sdpValue)

    private var secured = false

    override suspend fun secure(
        iceData: IceDataTransport,
        role: DtlsRole,
        peerFingerprint: Fingerprint,
    ): SctpDatagramTransport {
        // One engine per factory, so one handshake per factory: a second secure() would drive an
        // already-established SSL and silently corrupt it. Caller contract, hence a check (DESIGN §3).
        check(!secured) { "PureKotlinDtls.secure() is single-use — construct one factory per PeerConnection" }
        secured = true

        // Verify the peer's advertised digest is one we can actually check BEFORE handshaking: an
        // unverifiable peer is refused, never trusted (RFC 8827). Doing it up front also means we never
        // burn a handshake on a session we would have to reject anyway.
        val expected = expectedFingerprint(peerFingerprint)

        val transport = Session(iceData)
        transport.start(role)
        try {
            transport.awaitEstablished(expected)
        } catch (e: Throwable) {
            transport.close()
            throw e
        }
        return transport
    }

    /** The SHA-256 digest the peer advertised, or a typed refusal if there isn't a usable one. */
    private fun expectedFingerprint(peerFingerprint: Fingerprint): CertificateFingerprint {
        if (!peerFingerprint.hashFunction.equals("sha-256", ignoreCase = true)) {
            throw dtlsFailure(DtlsFailureReason.FingerprintMissing)
        }
        val hex = peerFingerprint.value.replace(":", "")
        // 32 bytes of hex, nothing else: a malformed digest can never accidentally compare equal.
        if (hex.length != 64 || !hex.all { it in "0123456789abcdefABCDEF" }) {
            throw dtlsFailure(DtlsFailureReason.FingerprintMissing)
        }
        return CertificateFingerprint.ofHex(hex)
    }

    private fun dtlsFailure(
        reason: DtlsFailureReason,
        cause: Throwable? = null,
    ): WebRtcException = WebRtcException(PeerConnectionFailureReason.Dtls(reason), cause)

    /**
     * One secured session: the pump coroutine plus the [SctpDatagramTransport] face it presents to the
     * data-channel stack. Every field is touched only by the pump or by thread-safe channels.
     */
    private inner class Session(
        private val iceData: IceDataTransport,
    ) : SctpDatagramTransport {
        // Records arriving from the ICE app-data seam. A forwarder coroutine feeds this because
        // IceDataTransport.receive() is a plain suspend fun and cannot be `select`ed on directly — the
        // same merged-inbox shape IceAgentDriver uses.
        private val inbound = Channel<ReadBuffer>(Channel.UNLIMITED)

        // Decrypted application data, drained by receive().
        private val appData = Channel<ReadBuffer>(Channel.UNLIMITED)

        // Plaintext the SCTP stack wants encrypted. Each request carries its own ack so send() reports
        // the real outcome (and stays backpressure-honest) instead of failing silently in the pump.
        private val outbound = Channel<SendRequest>(Channel.UNLIMITED)

        private val established = CompletableDeferred<DtlsState.Established>()
        private var forwarder: Job? = null
        private var pump: Job? = null
        private var closed = false

        fun start(role: DtlsRole) {
            forwarder =
                scope.launch {
                    while (true) {
                        val record = iceData.receive() ?: break
                        inbound.send(record)
                    }
                    // The pair went away: unblock a handshake that would otherwise wait out its budget.
                    inbound.close()
                }
            pump = scope.launch { pumpLoop(if (role == DtlsRole.Client) EngineRole.Client else EngineRole.Server) }
        }

        /** Suspend until the handshake completes, then hold it to the digest the peer advertised. */
        suspend fun awaitEstablished(expected: CertificateFingerprint) {
            val state =
                withTimeoutOrNull(config.handshakeTimeout) { established.await() }
                    ?: throw dtlsFailure(DtlsFailureReason.HandshakeTimeout)
            // THE check the engine deliberately does not make (it is signaling-agnostic): the peer's
            // certificate must be the one its SDP promised. Without this, DTLS would authenticate an
            // anonymous self-signed cert — i.e. nothing at all — and any on-path attacker who can answer
            // the ICE checks could terminate the session (RFC 8827 §6.5). Constant-time is unnecessary:
            // both digests are public values, and there is no secret to leak by comparison timing.
            if (state.peerFingerprint != expected) throw dtlsFailure(DtlsFailureReason.FingerprintMismatch)
        }

        override suspend fun send(packet: ReadBuffer) {
            val ack = CompletableDeferred<Unit>()
            val request = SendRequest(packet, ack)
            // trySend, not send: an UNLIMITED channel never suspends, and a closed one must surface the
            // typed reason rather than suspend forever after teardown.
            if (outbound.trySend(request).isFailure) throw dtlsFailure(DtlsFailureReason.RecordLayerError)
            ack.await()
        }

        override suspend fun receive(): ReadBuffer? = appData.receiveCatching().getOrNull()

        override fun close() {
            if (closed) return
            closed = true
            // Order matters: stop feeding the pump, let it run down (it frees the engine), then release
            // the ICE seam. The engine's pooled scratch buffers are released in the pump's finally, so
            // they are freed exactly once, on the coroutine that owns them — never concurrently with a
            // live handshake.
            inbound.close()
            outbound.close()
            pump?.cancel()
            forwarder?.cancel()
            appData.close()
            iceData.close()
        }

        private suspend fun pumpLoop(role: EngineRole) {
            try {
                // The engine reports state only through a step, so the pump carries it — it is the one
                // coroutine that ever sees a step, so this cannot drift from the engine's own view.
                var state = engine.start(role, clock()).also { apply(it) }.state
                while (state !is DtlsState.Failed && state !is DtlsState.Closed) {
                    val deadline = engine.nextDeadline(clock())
                    val step =
                        if (deadline == null) {
                            selectWithoutTimer() ?: break
                        } else {
                            // select, not withTimeout: a timeout that cancels receive() *after* it was
                            // handed a record would drop that record on the floor and stall the
                            // handshake until the peer retransmits (the IceAgentDriver lesson).
                            val wait = (deadline - clock()).coerceAtLeast(Duration.ZERO)
                            selectWithTimer(wait) ?: break
                        }
                    apply(step)
                    state = step.state
                }
            } finally {
                // Whatever ended us — established-then-closed, failure, or cancellation — the engine and
                // its pooled scratch buffers are freed here, on the one coroutine that owns them.
                engine.close()
                // Close outbound BEFORE draining it: once closed, send()'s trySend fails fast with a
                // typed reason. Draining first would leave the window where a send() lands in an open
                // channel that no pump will ever read, and awaits its ack forever (RFC §5.3 #5).
                outbound.close()
                failPendingSends()
                appData.close()
                if (!established.isCompleted) {
                    established.completeExceptionally(dtlsFailure(DtlsFailureReason.HandshakeFailure))
                }
            }
        }

        private suspend fun selectWithoutTimer(): DtlsStep? =
            select {
                inbound.onReceiveCatching { result ->
                    result.getOrNull()?.let { engine.onDatagram(it, clock()) }
                }
                outbound.onReceiveCatching { result ->
                    result.getOrNull()?.let { encrypt(it) }
                }
            }

        private suspend fun selectWithTimer(wait: Duration): DtlsStep? =
            select {
                inbound.onReceiveCatching { result ->
                    result.getOrNull()?.let { engine.onDatagram(it, clock()) }
                }
                outbound.onReceiveCatching { result ->
                    result.getOrNull()?.let { encrypt(it) }
                }
                onTimeout(wait) { engine.onTimeout(clock()) }
            }

        private fun encrypt(request: SendRequest): DtlsStep {
            val step = engine.send(request.payload, clock())
            if (step.state is DtlsState.Failed) {
                request.ack.completeExceptionally(dtlsFailure((step.state as DtlsState.Failed).reason))
            } else {
                request.ack.complete(Unit)
            }
            return step
        }

        /** Put this step's records on the wire, surface its app data, and publish the resulting state. */
        private suspend fun apply(step: DtlsStep) {
            // A whole flight is drained and sent as ONE datagram. Valid: DTLS records self-delimit, and
            // it is correct on the vnet — a real-MTU path may need per-record datagram framing / PMTU
            // fragmentation (a W7 concern, documented in HANDOFF).
            for (record in step.records) iceData.send(record)
            for (data in step.applicationData) {
                // trySend can fail if a concurrent close() already closed appData (a final inbound
                // record decrypted mid-teardown). Release that buffer instead of dropping it on the
                // floor: freeNativeMemory() returns a pooled buffer to its pool (or frees native memory,
                // or no-ops for GC-managed), so a pooled factory doesn't leak it (directive #6).
                if (appData.trySend(data).isFailure) (data as? PlatformBuffer)?.freeNativeMemory()
            }
            when (val state = step.state) {
                is DtlsState.Established -> established.complete(state)
                is DtlsState.Failed ->
                    if (!established.isCompleted) established.completeExceptionally(dtlsFailure(state.reason))
                is DtlsState.Handshaking, is DtlsState.Closed -> Unit
            }
        }

        private fun failPendingSends() {
            while (true) {
                val request = outbound.tryReceive().getOrNull() ?: break
                request.ack.completeExceptionally(dtlsFailure(DtlsFailureReason.RecordLayerError))
            }
        }
    }

    private class SendRequest(
        val payload: ReadBuffer,
        val ack: CompletableDeferred<Unit>,
    )
}
