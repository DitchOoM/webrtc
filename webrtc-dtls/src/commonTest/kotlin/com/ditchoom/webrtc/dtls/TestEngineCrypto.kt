package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.crypto.CryptoCapabilities
import com.ditchoom.buffer.crypto.SignatureScheme
import com.ditchoom.buffer.crypto.SignatureSupport
import com.ditchoom.buffer.crypto.signatures

/**
 * True only on the targets that actually run the pure-Kotlin DTLS engine — jvm/android/apple/linux,
 * where buffer-crypto exposes **synchronous** primitives. On js/wasmJs buffer-crypto is WebCrypto
 * (async only), and by design the engine is never constructed there: browsers delegate to the platform
 * `RTCPeerConnection`. So the commonTest fixtures that drive the blocking crypto engine gate on this and
 * no-op on the browser targets rather than throw. Uses ECDSA-P256 as the proxy for "sync crypto here"
 * (all of buffer-crypto's `*Blocking` ops are present together on a non-browser target, absent together
 * on a browser one).
 */
internal fun engineCryptoAvailable(): Boolean = CryptoCapabilities.signatures(SignatureScheme.EcdsaP256) is SignatureSupport.Blocking

/**
 * True when this runtime can perform **both** (EC)DHE groups, which is what any HelloRetryRequest fixture
 * structurally requires: an HRR is a request to retry with a group *other* than the one already
 * key-shared (RFC 8446 §4.1.4), so with a single usable group there is nothing legitimate to retry into.
 *
 * Android is the runtime that is not. Conscrypt's `XDH` `KeyPairGenerator` rejects every
 * `AlgorithmParameterSpec`, so X25519 probes `Unavailable` there and P-256 is the only group — see
 * [com.ditchoom.webrtc.dtls.crypto.EcdheKeyExchange.isAvailable].
 *
 * **Gate every HRR fixture on this**, and note that skipping is the *conservative* half of the problem.
 * The dangerous half is silent degeneration: `Dtls13HelloRetryRequestTest` drives a client preferring
 * P-256 against a server preferring X25519 and asserts both reach `Established`. On a runtime without
 * X25519 the server falls back to P-256, the client's key-share already matches, **no HRR is ever sent**,
 * both establish — and the test passes while proving nothing about the path it is named for. A green run
 * is not evidence a negotiation happened.
 */
internal fun bothKeyExchangeGroupsAvailable(): Boolean =
    KeyExchangeGroup.entries.all {
        val curve =
            when (it) {
                KeyExchangeGroup.X25519 -> com.ditchoom.buffer.crypto.KeyAgreementCurve.X25519
                KeyExchangeGroup.Secp256r1 -> com.ditchoom.buffer.crypto.KeyAgreementCurve.P256
            }
        com.ditchoom.webrtc.dtls.crypto.EcdheKeyExchange
            .isAvailable(curve)
    }
