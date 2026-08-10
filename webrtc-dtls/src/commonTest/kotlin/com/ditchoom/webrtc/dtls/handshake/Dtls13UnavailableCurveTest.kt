package com.ditchoom.webrtc.dtls.handshake

import com.ditchoom.buffer.crypto.KeyAgreementCurve
import com.ditchoom.webrtc.dtls.KeyExchangeGroup
import com.ditchoom.webrtc.dtls.crypto.EcdheKeyExchange
import com.ditchoom.webrtc.dtls.engineCryptoAvailable
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The regression fixture for the defect the Android emulator lane found: **a DTLS 1.3 client assumed its
 * configured (EC)DHE group was available and hard-`check()`ed it.**
 *
 * On Android that assumption is false at every API level. Conscrypt registers `XDH` — `KeyAgreement`
 * resolves fine — but its `KeyPairGenerator` rejects every `AlgorithmParameterSpec`
 * (`InvalidAlgorithmParameterException: No AlgorithmParameterSpec classes are supported`), so
 * buffer-crypto's capability probe reports X25519 `Unavailable`. `DtlsConfig.keyExchangeGroup` defaults to
 * X25519 and `enableDtls13` defaults to true, so **every** Android peer threw `IllegalStateException`
 * inside `DtlsEngine.start`, which unwound into the session pump and reached the consumer as an
 * unexplained `Dtls(HandshakeTimeout)`. P-256 was available the whole time and was already being
 * advertised in `supported_groups` — it was simply never selected.
 *
 * What this pins is the invariant that makes that unrepresentable, and it is deliberately expressed
 * against the **runtime's own** capabilities rather than a hardcoded curve: on a host with X25519 it
 * asserts the X25519 path, and on one without it asserts the fallback. A fixture naming a specific curve
 * would pass everywhere and prove nothing on the platform that had the bug.
 *
 * The end-to-end half — that a session actually establishes with the fallback — is the whole existing
 * `Dtls13HandshakeTest` / `PeerConnectionLossRoundTripTest` corpus, which now runs on ART.
 */
class Dtls13UnavailableCurveTest {
    @Test
    fun at_least_one_key_exchange_group_is_usable_wherever_the_engine_runs() {
        if (!engineCryptoAvailable()) return // browsers delegate; the engine's blocking crypto isn't here
        val usable = KeyExchangeGroup.entries.filter { EcdheKeyExchange.isAvailable(it.agreementCurveForTest()) }
        assertTrue(
            usable.isNotEmpty(),
            "every target that runs the engine must have at least one usable (EC)DHE group; " +
                "with none, a 1.3 handshake can only fail",
        )
    }

    @Test
    fun p256_is_usable_wherever_the_engine_runs() {
        if (!engineCryptoAvailable()) return
        // The load-bearing guarantee behind the fallback: P-256 is the group every runtime can do, which
        // is why it is a sufficient backstop when the configured group is missing. Android is the case
        // that matters — X25519 unavailable, P-256 Blocking.
        assertTrue(
            EcdheKeyExchange.isAvailable(KeyAgreementCurve.P256),
            "P-256 ECDH underpins DTLS 1.2 and is the 1.3 fallback; without it neither version can run",
        )
    }

    @Test
    fun generateOrNull_reports_an_unusable_curve_instead_of_throwing() {
        if (!engineCryptoAvailable()) return
        // The behavioural contract that replaced the `check()`. For whichever curves this runtime lacks,
        // the miss must be a null the caller maps to BackendUnavailable — never an exception escaping the
        // sans-io core (standing directive 3).
        for (curve in listOf(KeyAgreementCurve.X25519, KeyAgreementCurve.P256)) {
            val available = EcdheKeyExchange.isAvailable(curve)
            val produced = EcdheKeyExchange.generateOrNull(curve)
            try {
                if (available) {
                    assertTrue(produced != null, "${curve.curveName} reports available, so generation must succeed")
                } else {
                    assertFalse(produced != null, "${curve.curveName} reports unavailable, so generation must return null")
                }
            } finally {
                produced?.close()
            }
        }
    }

    /** Mirrors the handshake's private group→curve mapping; kept here so the test needs no internal access. */
    private fun KeyExchangeGroup.agreementCurveForTest(): KeyAgreementCurve =
        when (this) {
            KeyExchangeGroup.X25519 -> KeyAgreementCurve.X25519
            KeyExchangeGroup.Secp256r1 -> KeyAgreementCurve.P256
        }
}
