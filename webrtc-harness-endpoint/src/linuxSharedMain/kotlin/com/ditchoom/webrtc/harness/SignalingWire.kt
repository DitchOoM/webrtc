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
 * PutRequest : op=1(u8)  key(u16-len)  recordId(u32)  payload(u32-len)
 * GetRequest : op=2(u8)  key(u16-len)  since(u32)
 * Response   : status(u8)  total(u32)  records[]  (each: payload(u32-len), read to buffer end)
 * ```
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class PutRequest(
    /** Opcode discriminator — always [OP_PUT]. */
    public val op: UByte,
    @LengthPrefixed(LengthPrefix.Short) public val key: String,
    public val recordId: UInt,
    @LengthPrefixed(LengthPrefix.Int) public val payload: String,
)

@ProtocolMessage(wireOrder = Endianness.Big)
public data class GetRequest(
    /** Opcode discriminator — always [OP_GET]. */
    public val op: UByte,
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
 * The relay's reply to a GET: [status] (0 = OK), the slot's [total] record count (informational — the
 * caller tracks its own `since`), then the records at or after the requested index. [RemainingBytes]
 * loops reading self-delimiting [MailboxRecord]s until the datagram's end, so no count field is needed.
 */
@ProtocolMessage(wireOrder = Endianness.Big)
public data class MailboxResponse(
    public val status: UByte,
    public val total: UInt,
    @RemainingBytes public val records: List<MailboxRecord>,
)

/** PUT opcode. */
public const val OP_PUT: UByte = 1u

/** GET opcode. */
public const val OP_GET: UByte = 2u
