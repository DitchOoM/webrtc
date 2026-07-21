@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.dtls.DtlsStep
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The sans-io surface shared by the per-version handshake state machines ([Dtls12Handshake],
 * [Dtls13Handshake]). [com.ditchoom.webrtc.dtls.DtlsEngine] selects one at [start] time (the client from
 * its configured max version, the server by peeking the ClientHello) and then drives it through this one
 * interface — so the engine holds no version-specific branching past the initial choice.
 *
 * Every method is caller-clocked ([now], the driver's injected [Instant]); there is no coroutine, no wall
 * clock, and no I/O inside an implementation — the same clock model ICE and SCTP use ([nextDeadline]
 * returns an absolute [Instant]). Not thread-safe; confined to the one driver coroutine.
 */
internal interface DtlsHandshakeFsm {
    /** Begin the handshake (a client sends its first flight); returns the first records to put on the wire. */
    fun start(now: Instant): DtlsStep

    /** Feed one inbound datagram; drives the handshake or decrypts application data. */
    fun onDatagram(
        datagram: ReadBuffer,
        now: Instant,
    ): DtlsStep

    /** Fire an expired retransmission timer (re-sends the current flight). */
    fun onTimeout(now: Instant): DtlsStep

    /** Encrypt and frame application data once established. */
    fun sealApplicationData(
        applicationData: ReadBuffer,
        now: Instant,
    ): DtlsStep

    /** Begin an orderly close (queues an encrypted close_notify when keys exist). */
    fun beginClose(now: Instant): DtlsStep

    /** Absolute instant at which [onTimeout] must next run, or null if no timer is armed. */
    fun nextDeadline(now: Instant): Instant?

    /**
     * Export keying material — the TLS exporter (RFC 5705 for DTLS 1.2, RFC 8446 §7.5 for DTLS 1.3) that
     * DTLS-SRTP (RFC 5764) derives its keys from. Returns [length] pseudo-random bytes bound to [label] and
     * optional [context] (null = no context, the DTLS-SRTP case), or null if the handshake is not yet
     * established (no exportable secret exists). Both peers derive identical material from the shared secret.
     */
    fun exportKeyingMaterial(
        label: String,
        context: ReadBuffer?,
        length: Int,
    ): ReadBuffer?

    /** Free key material held by the handshake. Idempotent. */
    fun close()
}
