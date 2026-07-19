package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Negotiated DTLS version (RFC 6347 / 9147). [Unknown] covers a value we don't model. */
public enum class DtlsVersion { Dtls12, Dtls13, Unknown }

/**
 * Construction parameters for a [DtlsEngine], all seams with production defaults (directive #2/#6).
 * The one un-seamed source of entropy is BoringSSL's internal RNG shaping the ClientHello / keys —
 * the documented ±1-datagram Tier-B drift residue (RFC §5.1), not a Kotlin `Random.Default`.
 *
 * @param bufferFactory pooled buffers for the record I/O edge. Pass a **pooled native** factory in
 *   production: a native-backed buffer hands BoringSSL its own address (no staging copy), while a
 *   GC-heap buffer (the `managed()` default) is staged through an internal native scratch.
 * @param enableDtls13 negotiate up to DTLS 1.3; min always stays 1.2 (§11.3). **On by default**: both
 *   major browser engines now ship DTLS 1.3 for WebRTC (Firefox in Release, Chrome/BoringSSL on by
 *   default since the libwebrtc flip in 2025), and BoringSSL itself defaults to it. Version negotiation
 *   falls back to 1.2 for peers that lack 1.3 — notably Pion, whose released v3 is still 1.2-only. Set
 *   this false to pin 1.2 (e.g. to reproduce a 1.2-only interop lane).
 * @param maxDatagramSize the largest record datagram we read out of the backend in one step.
 * @param handshakeTimeout how long a driver waits for the handshake before failing it with
 *   [DtlsFailureReason.HandshakeTimeout]. DTLS itself retransmits a lost flight with exponential
 *   backoff and never gives up, so without a budget a peer that goes silent mid-handshake would hang
 *   the session forever; this is the liveness bound (RFC §5.3 #5: reach a state or a typed failure,
 *   never hang). Unused by the sans-io engine, which has no clock of its own — the driver enforces it.
 */
public class DtlsConfig(
    public val bufferFactory: BufferFactory = BufferFactory.managed(),
    public val enableDtls13: Boolean = true,
    public val maxDatagramSize: Int = 1500,
    public val handshakeTimeout: Duration = 30.seconds,
)

/**
 * The observable state of a [DtlsEngine] — a sealed hierarchy where each state carries exactly the
 * data valid in it (DESIGN §4: no boolean/nullable soup). [Handshaking] → [Established] | [Failed];
 * [Closed] after an orderly shutdown. Illegal combinations are unrepresentable.
 */
public sealed interface DtlsState {
    /** The handshake is in flight; records are still being exchanged. */
    public object Handshaking : DtlsState

    /**
     * The handshake completed. [peerFingerprint] is the SHA-256 of the peer's certificate — the
     * caller verifies it against the SDP-advertised `a=fingerprint` (webrtc root), since the engine
     * is signaling-agnostic.
     */
    public class Established(
        public val peerFingerprint: CertificateFingerprint,
        public val negotiatedVersion: DtlsVersion,
    ) : DtlsState

    /** An orderly close_notify was completed in both directions (or begun locally). */
    public object Closed : DtlsState

    /** The transport failed with a typed [reason]; terminal. */
    public class Failed(
        public val reason: DtlsFailureReason,
    ) : DtlsState
}

/**
 * The result of one caller-clocked step: DTLS records to put on the wire ([records]), any decrypted
 * application data produced ([applicationData]), and the resulting [state]. Buffers are owned by the
 * caller after return.
 */
public class DtlsStep(
    public val records: List<ReadBuffer>,
    public val applicationData: List<ReadBuffer>,
    public val state: DtlsState,
)

/**
 * A caller-clocked, sans-io DTLS endpoint (RFC §5.1) — the swap that replaces the plaintext seam at
 * `DtlsTransportFactory.secure(...)`. There is no dispatcher, no `Clock.System`, no I/O and no
 * coroutine inside it: the driver (webrtc root) owns the socket and the clock, feeds this engine
 * inbound records + a virtual `nowMicros`, and puts the returned records on the wire. BoringSSL's DTLS
 * timers are driven through an injected `current_time_cb`, so handshake retransmission replays under
 * `runTest` virtual time.
 *
 * `nowMicros` is epoch-microseconds from the driver's injected clock; the same value must be passed to
 * every call within one logical instant. [nextTimeoutMicros] returns the absolute epoch-micros at which
 * [onTimeout] must next be called (null = no timer armed).
 *
 * **Identity at construction, role at [start].** The engine generates its self-signed certificate when
 * it is constructed, so [localFingerprint] is readable immediately — which is what the session layer
 * needs, because the `a=fingerprint` goes into the *offer*, long before `a=setup` negotiates who is
 * client (RFC 8842). The role is therefore not a constructor parameter: an endpoint has an identity
 * from birth and learns its role from signaling later, exactly as WebRTC models it.
 *
 * Lifecycle: construct → [start] → feed [onDatagram]/[onTimeout] until [DtlsState.Established] → [send]
 * / receive application data → [beginClose] → [close]. Not thread-safe; confine to one driver coroutine.
 */
public expect class DtlsEngine(
    config: DtlsConfig,
) {
    /**
     * Our own certificate's SHA-256 fingerprint — the `a=fingerprint` we advertise. Readable from
     * construction, before [start], so it can be put in the offer (see the class note on role).
     */
    public val localFingerprint: CertificateFingerprint

    /**
     * Adopt [role] (from the negotiated `a=setup`) and begin the handshake; a [DtlsRole.Client] sends
     * the ClientHello. Returns the first flight to send. Call exactly once, before any [onDatagram].
     */
    public fun start(
        role: DtlsRole,
        nowMicros: Long,
    ): DtlsStep

    /** Feed one inbound DTLS record datagram; drives the handshake or decrypts application data. */
    public fun onDatagram(
        record: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep

    /** Fire an expired DTLS timer (retransmits the current flight). */
    public fun onTimeout(nowMicros: Long): DtlsStep

    /** Encrypt and enqueue application data once [DtlsState.Established]. */
    public fun send(
        applicationData: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep

    /** Begin an orderly close (queues a close_notify to send). */
    public fun beginClose(nowMicros: Long): DtlsStep

    /** Absolute epoch-micros at which [onTimeout] must next run, or null if no timer is armed. */
    public fun nextTimeoutMicros(nowMicros: Long): Long?

    /** Free all native resources. Idempotent. */
    public fun close()
}
