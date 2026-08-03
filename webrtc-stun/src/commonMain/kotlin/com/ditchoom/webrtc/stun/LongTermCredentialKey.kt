package com.ditchoom.webrtc.stun

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.Charset
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.buffer.toReadBuffer

/** Byte the long-term key formula joins its three fields with (RFC 8489 §9.2.2). */
private const val FIELD_SEPARATOR = ':'.code.toByte()

/**
 * Derives the **long-term credential key** for STUN/TURN MESSAGE-INTEGRITY:
 * `MD5(username ":" realm ":" password)` (RFC 8489 §9.2.2, inherited by TURN in RFC 8656 §7.1).
 *
 * Pass the result to [StunMessageBuilder.addMessageIntegrity] / [StunMessage.verifyMessageIntegrity]
 * as the HMAC-SHA1 key. It depends only on the credential and the server's realm, so derive it once
 * per challenge and reuse it — HMAC reads the key non-destructively.
 *
 * **The MD5 here is the wire format's key derivation, not a security hash.** RFC 8489 mandates it
 * verbatim; a server computes the same value from its own user table, so substituting a stronger
 * digest does not harden anything — it just fails to authenticate. See [Md5Core] for why the
 * implementation is pure Kotlin and lives in this module rather than in `buffer-crypto`.
 *
 * The short-term-credential form (RFC 8489 §9.1.1) uses the UTF-8 password directly as the key and
 * needs no derivation at all; only the long-term form goes through here.
 *
 * **Not SASLprep'd.** RFC 8489 §9.2.2 applies the OpaqueString profile (RFC 8265) to [password]
 * before hashing. This encodes it as UTF-8 as given, which is identical for the ASCII credentials
 * every practical TURN deployment uses, and differs only for a password carrying non-ASCII
 * whitespace or unnormalized code points.
 *
 * @param factory allocator for the returned 16-byte key. Defaults to [BufferFactory.managed] — the
 *   key outlives the call with no explicit release point, so a GC-managed allocation is the one that
 *   cannot leak native memory. Pass a factory only if you own the result's lifetime.
 * @return a read-ready [ReadBuffer] of exactly [Md5Core.MD5_DIGEST_BYTES] bytes.
 */
public fun longTermCredentialKey(
    username: String,
    realm: String,
    password: String,
    factory: BufferFactory = BufferFactory.managed(),
): ReadBuffer {
    val md5 = Md5Core()
    md5.update(username.toReadBuffer(Charset.UTF8))
    md5.absorbByte(FIELD_SEPARATOR)
    md5.update(realm.toReadBuffer(Charset.UTF8))
    md5.absorbByte(FIELD_SEPARATOR)
    md5.update(password.toReadBuffer(Charset.UTF8))
    md5.finish()

    val key = factory.allocate(Md5Core.MD5_DIGEST_BYTES)
    for (i in 0 until Md5Core.MD5_DIGEST_BYTES) key.writeByte(md5.digestByte(i))
    key.resetForRead()
    return key
}
