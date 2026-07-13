package com.ditchoom.webrtc.sctp

/**
 * Module marker for `webrtc-sctp`.
 *
 * This module is the **pure-Kotlin, sans-io SCTP wire codec** (RFC 4960 chunk framing as carried by
 * RFC 8831) plus the **DCEP** open/ack messages (RFC 8832) — commonMain-only, zero I/O, zero platform
 * code. Decode is total and typed-reject (never throws); chunk values are zero-copy slice views over
 * the datagram. See [SctpPacket] (the packet layer), [SctpChunk] (the sealed chunk hierarchy),
 * [com.ditchoom.webrtc.sctp.dcep.DataChannelMessage] (DCEP), and [Crc32c] (the SCTP checksum).
 *
 * The SCTP association state machine (handshake, TSN/SACK/RTO, congestion control, reassembly over
 * `StreamProcessor`) and the `DataChannel` implementing buffer-flow `StreamMux` are the rest of W5:
 * they sit above this codec floor on the DTLS/UDP track and are intentionally out of scope here.
 */
public object Sctp {
    public const val MODULE: String = "webrtc-sctp"
}
