package com.ditchoom.webrtc.harness

/**
 * Read an environment variable on the JVM. The harness peer takes its whole config from `WEBRTC_*` env
 * vars ([HarnessConfig.fromEnv]); reading one is the ONLY platform difference between the JVM peer and the
 * native peer (the datapath — [NativePeerConnection] + [PureKotlinDtls] + socket-udp — is common Kotlin on
 * both). This is a plain per-source-set function, not `expect`/`actual`: the shared harness code
 * (`src/commonSharedMain`) is compiled per target (the KSP-codec layout), so each compilation resolves its
 * own `readEnv` (this one on JVM, the posix one in `nativeMain`) with no metadata source set involved.
 */
internal fun readEnv(name: String): String? = System.getenv(name)
