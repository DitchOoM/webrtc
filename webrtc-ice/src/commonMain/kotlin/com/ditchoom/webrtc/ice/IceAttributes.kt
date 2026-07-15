package com.ditchoom.webrtc.ice

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.Default
import com.ditchoom.webrtc.stun.RawAttribute
import com.ditchoom.webrtc.stun.StunAttributeType

/**
 * The ICE-specific STUN attributes carried on a connectivity check (RFC 8445 §7.1.1, §16.1). These are
 * not in webrtc-stun's typed set — that module is the generic STUN/TURN codec — so they are built here
 * on the public [RawAttribute.ofRaw] escape hatch. The [StunAttributeType] constructor is public, so
 * each is just a registry point plus a fixed-shape value.
 */
public object IceAttributes {
    /** PRIORITY (RFC 8445 §16.1) — the priority the sender would assign the prflx candidate. */
    public val PRIORITY: StunAttributeType = StunAttributeType(0x0024u)

    /** USE-CANDIDATE (RFC 8445 §16.1) — a 0-length flag; the controlling agent nominates this pair. */
    public val USE_CANDIDATE: StunAttributeType = StunAttributeType(0x0025u)

    /** ICE-CONTROLLED (RFC 8445 §16.1) — an 8-byte tie-breaker; sender believes it is controlled. */
    public val ICE_CONTROLLED: StunAttributeType = StunAttributeType(0x8029u)

    /** ICE-CONTROLLING (RFC 8445 §16.1) — an 8-byte tie-breaker; sender believes it is controlling. */
    public val ICE_CONTROLLING: StunAttributeType = StunAttributeType(0x802Au)

    private const val U32_BYTES = 4
    private const val U64_BYTES = 8

    /** PRIORITY carrying a candidate [priority] (its low 32 bits; the value is a 32-bit field). */
    public fun priority(
        priority: Long,
        factory: BufferFactory = BufferFactory.Default,
    ): RawAttribute {
        val value = factory.allocate(U32_BYTES, ByteOrder.BIG_ENDIAN)
        value.writeUInt(priority.toUInt())
        value.resetForRead()
        return RawAttribute.ofRaw(PRIORITY, value)
    }

    /** USE-CANDIDATE (empty value). */
    public fun useCandidate(factory: BufferFactory = BufferFactory.Default): RawAttribute {
        val value = factory.allocate(1, ByteOrder.BIG_ENDIAN)
        value.resetForRead()
        value.setLimit(0)
        return RawAttribute.ofRaw(USE_CANDIDATE, value)
    }

    /** ICE-CONTROLLING with the sender's [tieBreaker]. */
    public fun controlling(
        tieBreaker: TieBreaker,
        factory: BufferFactory = BufferFactory.Default,
    ): RawAttribute = tieBreakerAttr(ICE_CONTROLLING, tieBreaker, factory)

    /** ICE-CONTROLLED with the sender's [tieBreaker]. */
    public fun controlled(
        tieBreaker: TieBreaker,
        factory: BufferFactory = BufferFactory.Default,
    ): RawAttribute = tieBreakerAttr(ICE_CONTROLLED, tieBreaker, factory)

    private fun tieBreakerAttr(
        type: StunAttributeType,
        tieBreaker: TieBreaker,
        factory: BufferFactory,
    ): RawAttribute {
        val value = factory.allocate(U64_BYTES, ByteOrder.BIG_ENDIAN)
        value.writeULong(tieBreaker.value.toULong())
        value.resetForRead()
        return RawAttribute.ofRaw(type, value)
    }

    /** The PRIORITY value (RFC 8445 §16.1), or null if the attribute is not a u32. */
    public fun RawAttribute.asPriority(): Long? = if (type == PRIORITY && length == U32_BYTES) value.getUnsignedInt(0).toLong() else null

    /** The tie-breaker from ICE-CONTROLLING / ICE-CONTROLLED, or null if not an 8-byte value. */
    public fun RawAttribute.asTieBreaker(): TieBreaker? =
        if ((type == ICE_CONTROLLING || type == ICE_CONTROLLED) &&
            length == U64_BYTES
        ) {
            TieBreaker(value.getUnsignedLong(0).toLong())
        } else {
            null
        }
}
