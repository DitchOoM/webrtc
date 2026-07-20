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
