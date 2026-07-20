package com.ditchoom.webrtc.dtls.crypto

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ByteOrder
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.EcdsaSignatureEncoding
import com.ditchoom.buffer.crypto.Sha256Digest
import com.ditchoom.buffer.crypto.SignatureScheme
import com.ditchoom.buffer.crypto.SignatureSupport
import com.ditchoom.buffer.crypto.SyncCapableSigningKey
import com.ditchoom.buffer.crypto.ecdsaSignatureEncoding
import com.ditchoom.buffer.crypto.ecdsaSignatureToDer
import com.ditchoom.buffer.crypto.signatures
import com.ditchoom.webrtc.dtls.CertificateFingerprint
import kotlin.random.Random

/**
 * A self-signed ECDSA-P256 certificate + its identity key — the WebRTC DTLS credential (RFC 8827: no
 * PKI, no chain; peers are bound only by the SDP `a=fingerprint`). The spike proved this minimal cert
 * openssl-parses, self-signature-verifies, and fingerprints byte-identically to openssl.
 *
 * [derEncoded] is the full `Certificate` DER (the bytes that go in the DTLS Certificate message);
 * [fingerprint] is its SHA-256; [signingKey] signs the CertificateVerify / ServerKeyExchange. The only
 * webrtc-local ASN.1 is the TBSCertificate template — everything cryptographic (keygen, SPKI export,
 * ECDSA signing) is buffer-crypto's.
 */
internal class SelfSignedCertificate private constructor(
    val signingKey: SyncCapableSigningKey,
    val derEncoded: ReadBuffer,
    val fingerprint: CertificateFingerprint,
) : AutoCloseable {
    override fun close() {
        signingKey.close()
    }

    companion object {
        // AlgorithmIdentifier ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2), no parameters — the full
        // SEQUENCE, spliced verbatim wherever the cert needs the signature algorithm.
        private val ECDSA_WITH_SHA256 =
            intArrayOf(0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02)

        // AttributeType id-at-commonName (OID 2.5.4.3).
        private val COMMON_NAME_OID = intArrayOf(0x06, 0x03, 0x55, 0x04, 0x03)

        private const val COMMON_NAME = "WebRTC"

        // A fixed, deterministic validity window (directive #2: no Clock.System). WebRTC trusts the
        // fingerprint, not the dates — the window only has to be well-formed and generous.
        private const val NOT_BEFORE = "230101000000Z"
        private const val NOT_AFTER = "330101000000Z"

        private const val SERIAL_BYTES = 16

        /**
         * Generates a fresh identity: an ECDSA-P256 keypair (buffer-crypto's CSPRNG — the Tier-B
         * unseeded residue, same as the BoringSSL path), a self-signed cert over a template TBS, and the
         * SHA-256 fingerprint. [random] seeds only the serial number (seedable for reproducible fixtures).
         */
        fun generate(
            factory: BufferFactory,
            random: Random,
        ): SelfSignedCertificate {
            val support = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256)
            check(support is SignatureSupport.Blocking) {
                "ECDSA-P256 blocking signatures unavailable on this target (browsers delegate; the engine never runs here)"
            }
            val ops = support.ops
            val signingKey = ops.generateSigningKeyBlocking()
            val spki = signingKey.verifyKey.exportSpki()

            val der = Der(factory)
            val name =
                der.sequence(
                    listOf(
                        der.set(
                            listOf(
                                der.sequence(
                                    listOf(
                                        der.literal(*COMMON_NAME_OID),
                                        der.printableString(COMMON_NAME),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
            val tbs =
                der.sequence(
                    listOf(
                        der.explicit(0, der.integer(der.literal(0x02))), // version v3 (INTEGER 2)
                        der.integer(serialMagnitude(factory, random)),
                        der.literal(*ECDSA_WITH_SHA256),
                        name, // issuer
                        der.sequence(listOf(der.utcTime(NOT_BEFORE), der.utcTime(NOT_AFTER))),
                        name, // subject == issuer (reused; writeView restores position)
                        spki,
                    ),
                )

            val rawSig = ops.signBlocking(signingKey, tbs)
            val derSig =
                if (ecdsaSignatureEncoding == EcdsaSignatureEncoding.Der) {
                    rawSig
                } else {
                    ecdsaSignatureToDer(SignatureScheme.EcdsaP256, rawSig)
                }

            val certificate =
                der.sequence(
                    listOf(
                        tbs,
                        der.literal(*ECDSA_WITH_SHA256),
                        der.bitString(derSig),
                    ),
                )
            certificate.position(0)
            return SelfSignedCertificate(signingKey, certificate, fingerprintOf(certificate, factory))
        }

        /** The SHA-256 `a=fingerprint` of any certificate DER (used to verify the peer's cert). */
        fun fingerprintOf(
            certificateDer: ReadBuffer,
            factory: BufferFactory,
        ): CertificateFingerprint {
            val p = certificateDer.position()
            val digest = factory.allocate(32, ByteOrder.BIG_ENDIAN)
            Sha256Digest().use { it.update(certificateDer).digestInto(digest) }
            certificateDer.position(p)
            digest.resetForRead()
            val sb = StringBuilder(64)
            while (digest.remaining() > 0) {
                val v = digest.readByte().toInt() and 0xFF
                sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 0xF])
            }
            return CertificateFingerprint.ofHex(sb.toString())
        }

        private fun serialMagnitude(
            factory: BufferFactory,
            random: Random,
        ): ReadBuffer {
            val mag = factory.allocate(SERIAL_BYTES, ByteOrder.BIG_ENDIAN)
            // First octet in [1, 0x7F]: positive (high bit clear) and non-zero (no leading-zero DER issue).
            mag.writeByte(((random.nextInt() and 0x7F) or 0x01).toByte())
            var i = 1
            while (i < SERIAL_BYTES) {
                val r = random.nextInt()
                var shift = 24
                while (i < SERIAL_BYTES && shift >= 0) {
                    mag.writeByte(((r ushr shift) and 0xFF).toByte())
                    i++
                    shift -= 8
                }
            }
            mag.resetForRead()
            return mag
        }
    }
}
