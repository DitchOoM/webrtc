package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.PlatformBuffer
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.KeyAgreementBlockingOps
import com.ditchoom.buffer.crypto.KeyAgreementCurve
import com.ditchoom.buffer.crypto.KeyAgreementKeyPair
import com.ditchoom.buffer.crypto.KeyAgreementPrivateKey
import com.ditchoom.buffer.crypto.KeyAgreementPublicKey
import com.ditchoom.buffer.crypto.KeyAgreementSupport
import com.ditchoom.buffer.crypto.keyAgreement
import com.ditchoom.buffer.freeIfNeeded

/**
 * The ephemeral (EC)DHE half of the DTLS handshake over one [curve] (RFC 8422 / RFC 7748). Wraps one
 * fresh keypair: [localPublicPoint] is our raw public point (65-byte uncompressed `04 ‖ X ‖ Y` for
 * P-256, 32-byte u-coordinate for X25519) for the ServerKeyExchange / ClientKeyExchange (1.2) or the
 * `key_share` (1.3), and [premasterSecret] computes the raw (EC)DH shared secret from the peer's point —
 * the TLS 1.2 pre-master secret / the TLS 1.3 (EC)DHE input directly.
 *
 * DTLS 1.2 always uses `secp256r1` ([KeyAgreementCurve.P256], the `generate()` default); only the DTLS
 * 1.3 path picks the group from [com.ditchoom.webrtc.dtls.DtlsConfig.keyExchangeGroup] (X25519 by default,
 * browser-matching). The buffer-crypto raw-secret path is curve-agnostic and enforces the RFC 7748 §6.1
 * all-zero rejection internally for X25519, so both curves drop through unchanged.
 *
 * Keypair generation is synchronous ([KeyAgreementBlockingOps.generateKeyPairBlocking]); the raw (EC)DH
 * multiply is the **one** buffer-crypto primitive with no blocking variant ([deriveTlsPremasterSecret]
 * is `suspend`, to cover WebCrypto), so it is bridged to synchronous through [rawEcdhPremaster] — the
 * sole per-platform seam in the otherwise-`commonMain` engine (see `crypto/RawEcdh.*`).
 */
internal class EcdheKeyExchange private constructor(
    private val curve: KeyAgreementCurve,
    private val ops: KeyAgreementBlockingOps,
    private val keyPair: KeyAgreementKeyPair,
) : AutoCloseable {
    /** Our ephemeral public point, raw SEC1/RFC 7748 form (65 B P-256 `04‖X‖Y`, 32 B X25519), read-ready. */
    val localPublicPoint: ReadBuffer get() = keyPair.publicKey.encoded

    /**
     * The raw (EC)DH shared secret from the peer's [peerPoint] (curve-sized: 65 B P-256, 32 B X25519) —
     * the TLS 1.2 pre-master secret / TLS 1.3 (EC)DHE input. The returned [PlatformBuffer] is
     * caller-owned; free it after deriving the master secret. Throws if [peerPoint] is invalid/rejected
     * (including the RFC 7748 §6.1 all-zero X25519 secret).
     */
    fun premasterSecret(peerPoint: ReadBuffer): PlatformBuffer {
        // `KeyAgreementPublicKey.of` SLICES [peerPoint] ("the buffer is sliced so the caller may reuse
        // theirs") and the type it returns is not `AutoCloseable`, so nothing downstream can give that
        // reference back. On a pooled buffer a slice is an `addRef`, so the peer's key-share point stayed
        // out of the pool for the life of the process — one chunk per peer, per session, invisible to
        // `assertNoLeaks` because the buffer itself is freed exactly once. The key is dead the moment the
        // agreement returns, so the borrow is handed back here.
        val peer = KeyAgreementPublicKey.of(curve, peerPoint)
        return try {
            rawEcdhPremaster(ops, keyPair.privateKey, peer)
        } finally {
            peer.encoded.freeIfNeeded()
        }
    }

    override fun close() {
        keyPair.close()
    }

    companion object {
        /**
         * Whether [curve] has a **blocking** key agreement on this runtime — i.e. whether [generateOrNull]
         * can succeed for it.
         *
         * Exists because curve support is a **runtime** property, not a platform one, and this stack used
         * to assume otherwise. Android is the case that proved it: Conscrypt registers `XDH` but its
         * `KeyPairGenerator` rejects every `AlgorithmParameterSpec`, so buffer-crypto's probe
         * (`KeyPairGenerator.getInstance("XDH").initialize(NamedParameterSpec.X25519)`) reports X25519
         * `Unavailable` on **every** Android API level — including those whose release notes say it is
         * present. P-256 is available there and always has been. A client that hard-assumes X25519
         * therefore cannot open a data channel on any Android device, which is exactly what shipped until
         * the ART lane ran.
         *
         * Ask this before *advertising* a group, not only before using one: offering a group we cannot do
         * invites a HelloRetryRequest we would then have to fail.
         */
        fun isAvailable(curve: KeyAgreementCurve): Boolean = CryptoCapabilities.keyAgreement(curve) is KeyAgreementSupport.Blocking

        /**
         * A fresh ephemeral keypair on [curve] (buffer-crypto's CSPRNG — the Tier-B unseeded residue), or
         * `null` when this runtime has no blocking agreement for it.
         *
         * Null rather than a throw so the caller maps the miss onto its own typed terminal
         * ([DtlsFailureReason.BackendUnavailable][com.ditchoom.webrtc.dtls.DtlsFailureReason.BackendUnavailable])
         * — per standing directive 3, an unsupported curve is a typed reason, never an exception escaping
         * the sans-io core. The predecessor of this function `check()`ed instead, and that
         * `IllegalStateException` unwound through `DtlsEngine.start` into the session's pump loop, where it
         * surfaced to the consumer as an unexplained `Dtls(HandshakeTimeout)`.
         */
        fun generateOrNull(curve: KeyAgreementCurve): EcdheKeyExchange? {
            val support = CryptoCapabilities.keyAgreement(curve)
            if (support !is KeyAgreementSupport.Blocking) return null
            return EcdheKeyExchange(curve, support.ops, support.ops.generateKeyPairBlocking())
        }

        /**
         * Generates a fresh ephemeral keypair on [curve], defaulting to P-256 — the DTLS **1.2** entry
         * point, whose cipher suite (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`) fixes the curve at
         * `secp256r1` with nothing to negotiate. The 1.3 caller has a choice of group and must use
         * [generateOrNull] so it can fall back.
         *
         * Still a `check()`, and deliberately: P-256 ECDH is available on every target that runs this
         * engine, so a miss here is not a negotiable condition but a broken crypto provider.
         */
        fun generate(curve: KeyAgreementCurve = KeyAgreementCurve.P256): EcdheKeyExchange =
            checkNotNull(generateOrNull(curve)) {
                "${curve.curveName} blocking key agreement unavailable on this runtime"
            }
    }
}

/**
 * The one suspend→blocking bridge: buffer-crypto exposes the raw ECDH secret only through the `suspend`
 * [deriveTlsPremasterSecret][KeyAgreementBlockingOps] (there is no `*Blocking` raw variant), but the
 * sans-io [com.ditchoom.webrtc.dtls.DtlsEngine] is synchronous by contract. On the four targets that
 * actually run the engine (JVM/Android/Apple/Linux) this `runBlocking`s the call, which completes
 * synchronously underneath; on JS/WASM — where browsers delegate to `RTCPeerConnection` and the engine
 * is never driven — it fails fast with a typed [DtlsFailureReason.BackendUnavailable].
 */
internal expect fun rawEcdhPremaster(
    ops: KeyAgreementBlockingOps,
    privateKey: KeyAgreementPrivateKey,
    peerPublicKey: KeyAgreementPublicKey,
): PlatformBuffer
