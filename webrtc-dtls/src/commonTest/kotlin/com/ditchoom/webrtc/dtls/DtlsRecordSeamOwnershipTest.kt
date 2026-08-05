@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.freeIfNeeded
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * **The DTLS record seam gives back every chunk it took**, for both negotiable versions.
 *
 * `DtlsSessionBufferOwnershipTest` (webrtc/linuxTest) proves the same property through a whole
 * `PeerConnection`, which is the configuration a user actually runs. This one exists beside it for two
 * reasons the end-to-end fixture cannot serve:
 *
 * - **It reaches DTLS 1.2.** A `PeerConnection` between two of our own peers negotiates 1.3 every time, so
 *   [Dtls12Handshake]'s release paths were only ever *inferred* from their 1.3 twins. Here the version is
 *   a parameter ([DtlsConfig.enableDtls13]), so both FSMs are measured.
 * - **It attributes.** Three trackers, one per seam, so a number can be pinned on the peer that produced
 *   it rather than on "the session".
 *
 * ## The contract this fixture reproduces
 *
 * It is the DTLS pump's, transcribed — see `PureKotlinDtls.apply` — because an ownership fixture that
 * invents its own contract measures the fixture:
 *
 * - a record in `DtlsStep.records` is the caller's to free once it has been put on the wire;
 * - a buffer handed to `onDatagram` is the caller's to free **after** the step has been applied, since
 *   everything the decoders read within the call is a borrow over it;
 * - a buffer in `DtlsStep.applicationData` is the caller's outright.
 *
 * The wire between the two peers **copies**, exactly as `TestNet` does, because a real path does: feeding
 * the sender's own record object back in would make one chunk answer to two owners and turn the second
 * release into a double free. The copy's own factory is tracked too — that is the stand-in for the
 * socket's receive buffer, and the seam the decode *borrows* land on.
 *
 * ## Why [LeakTrackingFactory.assertPoolDrained] and not just `assertNoLeaks`
 *
 * `assertNoLeaks` is structurally blind to a borrow: `freed` is set by the first `freeNativeMemory()`
 * whatever the refcount does. Every unreleased `sliceOf` in a wire decoder is invisible to it and visible
 * here. That is the whole point of the file.
 */
class DtlsRecordSeamOwnershipTest {
    private var now: Instant = Instant.fromEpochSeconds(0)

    @Test
    fun a_dtls13_session_returns_every_chunk_of_both_seams() = sessionDrains(enableDtls13 = true)

    @Test
    fun a_dtls12_session_returns_every_chunk_of_both_seams() = sessionDrains(enableDtls13 = false)

    private fun sessionDrains(enableDtls13: Boolean) {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val version = if (enableDtls13) "DTLS 1.3" else "DTLS 1.2"
        val clientRecords = LeakTrackingFactory()
        val serverRecords = LeakTrackingFactory()
        val wire = LeakTrackingFactory()

        val client = DtlsEngine(config(clientRecords, enableDtls13))
        val server = DtlsEngine(config(serverRecords, enableDtls13))
        val net = Wire(wire)
        try {
            val (c, s) = net.handshake(client, server)
            assertIs<DtlsState.Established>(c, "client established ($version), was $c")
            assertIs<DtlsState.Established>(s, "server established ($version), was $s")

            // Both directions: each peer must be a releasing *receiver* of records, not only a sender.
            assertEquals("deadbeef", net.exchange(from = client, to = server, hex = "deadbeef"))
            assertEquals("0123456789", net.exchange(from = server, to = client, hex = "0123456789"))

            // An orderly close_notify is a flight like any other, and its records are owed a release too.
            net.deliver(client.beginClose(now), from = client, to = server)
        } finally {
            client.close()
            server.close()
        }

        clientRecords.assertNoLeaks("the client's $version record seam")
        serverRecords.assertNoLeaks("the server's $version record seam")
        wire.assertNoLeaks("the $version wire")
        // The strictly stronger claim, and the one an unreleased decode *borrow* shows up in.
        clientRecords.assertPoolDrained("the client's $version record seam")
        serverRecords.assertPoolDrained("the server's $version record seam")
        wire.assertPoolDrained("the $version wire")
    }

    private fun config(
        factory: LeakTrackingFactory,
        enableDtls13: Boolean,
    ) = DtlsConfig(bufferFactory = factory, enableDtls13 = enableDtls13, random = Random(11))

    /**
     * A copying, synchronous two-endpoint conductor — the pump's ownership contract and nothing else.
     *
     * Every buffer that crosses it is accounted for at the moment its last reader is done with it, which is
     * what makes the three trackers' end-of-run numbers attributable. Note the deliberate ordering in
     * [feed]: the inbound copy is released *after* the resulting step has been applied, never before,
     * because the decoders' views over it are alive for the duration of the call.
     */
    private inner class Wire(
        private val factory: LeakTrackingFactory,
    ) {
        fun handshake(
            client: DtlsEngine,
            server: DtlsEngine,
        ): Pair<DtlsState, DtlsState> {
            val toServer = ArrayDeque<ReadBuffer>()
            val toClient = ArrayDeque<ReadBuffer>()
            var cState: DtlsState = drain(client.start(DtlsRole.Client, now), toServer)
            var sState: DtlsState = drain(server.start(DtlsRole.Server, now), toClient)

            var guard = 0
            while (guard++ < GUARD) {
                if (cState is DtlsState.Established && sState is DtlsState.Established) break
                if (cState is DtlsState.Failed || sState is DtlsState.Failed) break
                when {
                    toServer.isNotEmpty() -> sState = feed(server, toServer.removeFirst(), toClient)
                    toClient.isNotEmpty() -> cState = feed(client, toClient.removeFirst(), toServer)
                    else -> {
                        val deadlines = listOfNotNull(client.nextDeadline(now), server.nextDeadline(now))
                        if (deadlines.isEmpty()) break
                        now = maxOf(now + 1.microseconds, deadlines.min())
                        cState = drain(client.onTimeout(now), toServer)
                        sState = drain(server.onTimeout(now), toClient)
                    }
                }
            }
            return cState to sState
        }

        /** Seals [hex] at [from], delivers every record to [to], and returns what [to] decrypted. */
        fun exchange(
            from: DtlsEngine,
            to: DtlsEngine,
            hex: String,
        ): String {
            val plaintext = bytes(hex)
            val step =
                try {
                    from.send(plaintext, now)
                } finally {
                    // `send` does not take ownership of the caller's payload (`PureKotlinDtls` keeps it for
                    // the SCTP sender); here this fixture is that caller.
                    plaintext.freeIfNeeded()
                }
            return deliver(step, from = from, to = to)
        }

        /** Puts [step]'s records on the wire toward [to] and returns the hex of whatever [to] surfaced. */
        fun deliver(
            step: DtlsStep,
            from: DtlsEngine,
            to: DtlsEngine,
        ): String {
            val back = ArrayDeque<ReadBuffer>()
            val forward = ArrayDeque<ReadBuffer>()
            drain(step, forward)
            val decrypted = StringBuilder()
            while (forward.isNotEmpty()) {
                feed(to, forward.removeFirst(), back) { decrypted.append(hexOf(it)) }
            }
            // A response flight (an ACK, or the peer's own close_notify) comes back on the same contract.
            while (back.isNotEmpty()) feed(from, back.removeFirst(), forward)
            while (forward.isNotEmpty()) feed(to, forward.removeFirst(), back)
            return decrypted.toString()
        }

        /**
         * Copies [step]'s records onto [out] and releases the originals — the fixture's stand-in for
         * `iceData.send(record)` followed by `record.releaseAfterSend()`.
         */
        private fun drain(
            step: DtlsStep,
            out: ArrayDeque<ReadBuffer>,
        ): DtlsState {
            for (record in step.records) {
                try {
                    out.addLast(copyOf(record))
                } finally {
                    record.freeIfNeeded()
                }
            }
            // Application data surfaced by a plain drain has no reader here; this is its last one.
            for (data in step.applicationData) data.freeIfNeeded()
            return step.state
        }

        private fun feed(
            engine: DtlsEngine,
            datagram: ReadBuffer,
            out: ArrayDeque<ReadBuffer>,
            onAppData: (ReadBuffer) -> Unit = {},
        ): DtlsState {
            val step = engine.onDatagram(datagram, now)
            for (record in step.records) {
                try {
                    out.addLast(copyOf(record))
                } finally {
                    record.freeIfNeeded()
                }
            }
            for (data in step.applicationData) {
                try {
                    onAppData(data)
                } finally {
                    data.freeIfNeeded()
                }
            }
            // AFTER the step, deliberately: every field the decoders read within the call is a borrow over
            // this datagram, so releasing it earlier would hand the parse reclaimed memory.
            datagram.freeIfNeeded()
            return step.state
        }

        /**
         * The wire copy. `slice()` on a pooled buffer is `addRef()`, so the read view has to be released
         * even though it is dead the instant the copy is made — leaving it pins the **sender's** chunk and
         * reports the harness's own bug as a production leak. `TestNet.copyOf` carries the same comment
         * because it made exactly that mistake.
         */
        private fun copyOf(payload: ReadBuffer): PlatformBuffer {
            val slice = payload.slice()
            return try {
                val len = slice.remaining()
                val copy = factory.allocate(maxOf(1, len), ByteOrder.BIG_ENDIAN)
                copy.write(slice)
                copy.resetForRead()
                copy.setLimit(len)
                copy
            } finally {
                slice.freeIfNeeded()
            }
        }

        private fun bytes(hex: String): PlatformBuffer {
            val b = factory.allocate(hex.length / 2, ByteOrder.BIG_ENDIAN)
            for (i in hex.indices step 2) b.writeByte(hex.substring(i, i + 2).toInt(HEX).toByte())
            b.resetForRead()
            b.setLimit(hex.length / 2)
            return b
        }

        private fun hexOf(buf: ReadBuffer): String {
            val sb = StringBuilder()
            for (i in buf.position() until buf.limit()) {
                val v = buf.get(i).toInt() and 0xFF
                sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0xF])
            }
            return sb.toString()
        }
    }
}

private const val GUARD = 500
private const val HEX = 16
private const val HEX_DIGITS = "0123456789abcdef"
