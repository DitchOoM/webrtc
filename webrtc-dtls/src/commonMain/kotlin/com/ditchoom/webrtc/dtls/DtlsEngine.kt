package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed

/** Negotiated DTLS version (RFC 6347 / 9147). [Unknown] covers a value we don't model. */
public enum class DtlsVersion { Dtls12, Dtls13, Unknown }

/**
 * Construction parameters for a [DtlsEngine], all seams with production defaults (directive #2/#6).
 * The one un-seamed source of entropy is BoringSSL's internal RNG shaping the ClientHello / keys —
 * the documented ±1-datagram Tier-B drift residue (RFC §5.1), not a Kotlin `Random.Default`.
 *
 * @param bufferFactory pooled buffers for the record I/O edge (default: the managed factory).
 * @param enableDtls13 raise the negotiated max to DTLS 1.3; min stays 1.2, the WebRTC field floor
 *   (§11.3). Off by default so the portable interop floor matches the future `boringssl-kmp` (1.2-only).
 * @param maxDatagramSize the largest record datagram we read out of the backend in one step.
 */
public class DtlsConfig(
    public val bufferFactory: BufferFactory = BufferFactory.managed(),
    public val enableDtls13: Boolean = false,
    public val maxDatagramSize: Int = 1500,
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
 * Lifecycle: construct → [start] → feed [onDatagram]/[onTimeout] until [DtlsState.Established] → [send]
 * / receive application data → [beginClose] → [close]. Not thread-safe; confine to one driver coroutine.
 */
public expect class DtlsEngine(
    role: DtlsRole,
    config: DtlsConfig,
) {
    /** Our own certificate's SHA-256 fingerprint — the `a=fingerprint` we advertise (available now). */
    public val localFingerprint: CertificateFingerprint

    /** Begin the handshake (client sends ClientHello). Returns the first flight to send. */
    public fun start(nowMicros: Long): DtlsStep

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
