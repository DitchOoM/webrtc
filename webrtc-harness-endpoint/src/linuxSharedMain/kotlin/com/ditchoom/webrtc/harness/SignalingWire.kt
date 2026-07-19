package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.codec.annotations.Endianness
import com.ditchoom.buffer.codec.annotations.LengthPrefix
import com.ditchoom.buffer.codec.annotations.LengthPrefixed
import com.ditchoom.buffer.codec.annotations.ProtocolMessage
import com.ditchoom.buffer.codec.annotations.RemainingBytes

/**
 * The signaling **rendezvous wire schema** — buffer-codec `@ProtocolMessage` types, so KSP generates the
 * `PutRequestCodec` / `GetRequestCodec` / `MailboxResponseCodec` byte-for-byte (no hand-rolled offset
 * math — the same discipline STUN/SDP/SCTP use). Every field's on-wire layout is explicit in the
 * annotations, so the Python relay (`test-harness/rendezvous/rendezvous.py`) mirrors it from this one
 * spec. All big-endian.
 *
 * The relay is a stateless keyed mailbox: `key = "<session>/<slot>"`, records appended in `recordId`
 * order (id-keyed so a UDP retransmit is idempotent). Slots: `offer`, `answer`, `cand/offerer`,
 * `cand/answerer`. `op` is the first byte so the relay dispatches PUT vs GET without a full decode.
 *
 * ```
 * PutRequest : op=1(u8)  nonce(u32)  key(u16-len)  recordId(u32)  payload(u32-len)
 * GetRequest : op=2(u8)  nonce(u32)  key(u16-len)  since(u32)
 * Response   : status(u8)  nonce(u32)  total(u32)  records[]  (each: payload(u32-len), read to buffer end)
 * ```
 *
 * **`nonce` is the request↔response correlator.** UDP has no request/response pairing and the client
 * blindly consumes the next datagram on its socket — so without a correlator, a delayed or duplicate reply
 * (arriving after the client's per-request timeout) sits in the RX buffer and permanently offsets the
 * socket by one, mis-pairing every later reply (e.g. an answer-SDP reply later consumed by a candidate
 * poll → fed into `addIceCandidate`, and a real candidate skipped). The client stamps a fresh nonce per
 * request; the relay echoes it; the client drains + discards any reply whose nonce ≠ the request it awaits.
 * Not reachable on a fast local RTT (why the harness passes today), but a real flake on the L3 path.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class PutRequest(
    /** Opcode discriminator — always [OP_PUT]. */
    public val op: UByte,
    /** Request↔response correlator, echoed in [MailboxResponse.nonce]. */
    public val nonce: UInt,
    @LengthPrefixed(LengthPrefix.Short) public val key: String,
    public val recordId: UInt,
    @LengthPrefixed(LengthPrefix.Int) public val payload: String,
)

@ProtocolMessage(wireOrder = Endianness.Big)
public data class GetRequest(
    /** Opcode discriminator — always [OP_GET]. */
    public val op: UByte,
    /** Request↔response correlator, echoed in [MailboxResponse.nonce]. */
    public val nonce: UInt,
    @LengthPrefixed(LengthPrefix.Short) public val key: String,
    /** Return records at or after this index (the caller's high-water mark). */
    public val since: UInt,
)

/** One stored record (a signaling blob: an SDP body or a `candidate:` line). */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class MailboxRecord(
    @LengthPrefixed(LengthPrefix.Int) public val payload: String,
)

/**
 * The relay's reply: [status] (0 = OK), the echoed request [nonce] (correlator), the slot's [total] record
 * count (informational — the caller tracks its own `since`), then the records at or after the requested
 * index. [RemainingBytes] loops reading self-delimiting [MailboxRecord]s until the datagram's end, so no
 * count field is needed. A PUT ack is the same shape with zero records.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class MailboxResponse(
    public val status: UByte,
    /** Echo of the request's [PutRequest.nonce] / [GetRequest.nonce]. */
    public val nonce: UInt,
    public val total: UInt,
    @RemainingBytes public val records: List<MailboxRecord>,
)

/** PUT opcode. */
public const val OP_PUT: UByte = 1u

/** GET opcode. */
public const val OP_GET: UByte = 2u
