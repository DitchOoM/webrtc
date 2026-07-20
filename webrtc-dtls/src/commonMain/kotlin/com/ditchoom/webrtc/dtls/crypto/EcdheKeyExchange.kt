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
 * The ephemeral ECDHE half of the DTLS 1.2 handshake over `secp256r1` (RFC 8422). Wraps one fresh
 * P-256 keypair: [localPublicPoint] is our 65-byte uncompressed point (`04 ‖ X ‖ Y`) for the
 * ServerKeyExchange / ClientKeyExchange, and [premasterSecret] computes the raw ECDH shared secret from
 * the peer's point — which becomes the TLS 1.2 pre-master secret directly.
 *
 * Keypair generation is synchronous ([KeyAgreementBlockingOps.generateKeyPairBlocking]); the raw ECDH
 * multiply is the **one** buffer-crypto primitive with no blocking variant ([deriveTlsPremasterSecret]
 * is `suspend`, to cover WebCrypto), so it is bridged to synchronous through [rawEcdhPremaster] — the
 * sole per-platform seam in the otherwise-`commonMain` engine (see `crypto/RawEcdh.*`).
 */
internal class EcdheKeyExchange private constructor(
    private val ops: KeyAgreementBlockingOps,
    private val keyPair: KeyAgreementKeyPair,
) : AutoCloseable {
    /** Our ephemeral public point, 65-byte uncompressed SEC1 (`04 ‖ X ‖ Y`), read-ready. */
    val localPublicPoint: ReadBuffer get() = keyPair.publicKey.encoded

    /**
     * The raw ECDH shared secret from the peer's 65-byte uncompressed [peerPoint] — the TLS 1.2
     * pre-master secret. The returned [PlatformBuffer] is caller-owned; free it after deriving the
     * master secret. Throws if [peerPoint] is an invalid/rejected point.
     */
    fun premasterSecret(peerPoint: ReadBuffer): PlatformBuffer {
        val peer = KeyAgreementPublicKey.of(KeyAgreementCurve.P256, peerPoint)
        return rawEcdhPremaster(ops, keyPair.privateKey, peer)
    }

    override fun close() {
        keyPair.close()
    }

    companion object {
        /** Generates a fresh ephemeral P-256 keypair (buffer-crypto's CSPRNG — the Tier-B unseeded residue). */
        fun generate(): EcdheKeyExchange {
            val support = CryptoCapabilities.keyAgreement(KeyAgreementCurve.P256)
            check(support is KeyAgreementSupport.Blocking) {
                "P-256 blocking key agreement unavailable on this target (browsers delegate; the engine never runs here)"
            }
            return EcdheKeyExchange(support.ops, support.ops.generateKeyPairBlocking())
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
