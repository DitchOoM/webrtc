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
        val peer = KeyAgreementPublicKey.of(curve, peerPoint)
        return rawEcdhPremaster(ops, keyPair.privateKey, peer)
    }

    override fun close() {
        keyPair.close()
    }

    companion object {
        /**
         * Generates a fresh ephemeral keypair on [curve] (buffer-crypto's CSPRNG — the Tier-B unseeded
         * residue). Defaults to P-256 for the DTLS 1.2 caller; the 1.3 caller passes its negotiated group.
         */
        fun generate(curve: KeyAgreementCurve = KeyAgreementCurve.P256): EcdheKeyExchange {
            val support = CryptoCapabilities.keyAgreement(curve)
            check(support is KeyAgreementSupport.Blocking) {
                "${curve.curveName} blocking key agreement unavailable on this target (browsers delegate; the engine never runs here)"
            }
            return EcdheKeyExchange(curve, support.ops, support.ops.generateKeyPairBlocking())
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
