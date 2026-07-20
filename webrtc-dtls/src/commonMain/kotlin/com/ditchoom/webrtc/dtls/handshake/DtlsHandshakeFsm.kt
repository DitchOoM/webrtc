package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.webrtc.dtls.DtlsStep

/**
 * The sans-io surface shared by the per-version handshake state machines ([Dtls12Handshake],
 * [Dtls13Handshake]). [com.ditchoom.webrtc.dtls.DtlsEngine] selects one at [start] time (the client from
 * its configured max version, the server by peeking the ClientHello) and then drives it through this one
 * interface — so the engine holds no version-specific branching past the initial choice.
 *
 * Every method is caller-clocked (`nowMicros` epoch-microseconds); there is no coroutine, no wall clock,
 * and no I/O inside an implementation. Not thread-safe; confined to the one driver coroutine.
 */
internal interface DtlsHandshakeFsm {
    /** Begin the handshake (a client sends its first flight); returns the first records to put on the wire. */
    fun start(nowMicros: Long): DtlsStep

    /** Feed one inbound datagram; drives the handshake or decrypts application data. */
    fun onDatagram(
        datagram: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep

    /** Fire an expired retransmission timer (re-sends the current flight). */
    fun onTimeout(nowMicros: Long): DtlsStep

    /** Encrypt and frame application data once established. */
    fun sealApplicationData(
        applicationData: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep

    /** Begin an orderly close (queues an encrypted close_notify when keys exist). */
    fun beginClose(nowMicros: Long): DtlsStep

    /** Absolute epoch-micros at which [onTimeout] must next run, or null if no timer is armed. */
    fun nextTimeoutMicros(nowMicros: Long): Long?

    /** Free key material held by the handshake. Idempotent. */
    fun close()
}
