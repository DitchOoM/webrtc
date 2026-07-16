@file:OptIn(ExperimentalTime::class)

package com.ditchoom.webrtc.sctp.association

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Default
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * The timing, sizing, and buffer seams of an [SctpAssociation] (RFC 4960 defaults, tuned for the
 * WebRTC dcSCTP subset — RFC 8831 / RFC §11.2: no multihoming, no stream interleaving). Every value is
 * injected so a test can compress the schedule and assert **observable state**, never a wall-clock
 * budget (directive #4). Nothing here is read from an ambient clock or RNG — the association is pure
 * `handle(event, now)` (RFC §5.1); `now` and the injected [BufferFactory]/`Random` are the only seams.
 */
public data class SctpConfig(
    /** RTO.Initial (RFC 4960 §15) — the retransmission timeout before any RTT sample. */
    public val rtoInitial: Duration = 3.seconds,
    /** RTO.Min (RFC 4960 §15) — the floor an RTT-derived RTO is clamped to. */
    public val rtoMin: Duration = 1.seconds,
    /** RTO.Max (RFC 4960 §15) — the ceiling for an RTO after exponential backoff. */
    public val rtoMax: Duration = 60.seconds,
    /** Max.Init.Retransmits (RFC 4960 §15) — INIT/COOKIE-ECHO attempts before the association fails. */
    public val maxInitRetransmits: Int = 8,
    /** Association.Max.Retrans (RFC 4960 §15) — total DATA retransmit errors before the association aborts. */
    public val maxAssociationRetransmits: Int = 10,
    /** The largest DATA-chunk *user-data* payload per fragment (MTU minus SCTP/DTLS/UDP/IP overhead). */
    public val maxPayloadBytes: Int = 1200,
    /** a_rwnd (RFC 4960 §3.3.2) — the receive window this endpoint advertises. */
    public val receiveWindowBytes: UInt = 1024u * 1024u,
    /** Initial cwnd = min(4*MTU, max(2*MTU, 4380)) (RFC 4960 §7.2.1), expressed in MTUs of [maxPayloadBytes]. */
    public val initialCwndMtus: Int = 4,
    /** SACK delay (RFC 4960 §6.2) — how long a receiver may defer a SACK when nothing forces it out. */
    public val sackDelay: Duration = 200.milliseconds,
    /** Number of outbound streams to request in INIT (RFC 8831 uses many; the DataChannel layer picks ids). */
    public val outboundStreams: UShort = 1024u,
    /** Number of inbound streams to allow in INIT. */
    public val inboundStreams: UShort = 1024u,
    /** T2-shutdown / SHUTDOWN-ACK retransmit budget before the association aborts. */
    public val maxShutdownRetransmits: Int = 5,
    /** The buffer allocator for encoded packets and reassembly copies — inject a tracking factory in tests. */
    public val bufferFactory: BufferFactory = BufferFactory.Default,
)
