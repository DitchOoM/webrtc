package com.ditchoom.webrtc.dtls

// No BoringSSL libssl on Apple this wave. buffer-crypto is CommonCrypto here (it contributes no
// libcrypto to link against), and boringssl-kmp's Apple lane is unbuilt — see the EXECUTION_PLAN
// "W4 sequencing" row. Probe reports "absent" exactly as the JVM/JS lanes do.
internal actual fun dtlsBackendProbe(): Long = 0L
