pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

// The `webrtc.*` convention plugins (KMP targets, publishing, versioning) live in build-logic and
// are shared with the main build here — one place for all module build logic, no copy-paste.
includeBuild("build-logic")

rootProject.name = "webrtc"

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
    id("com.gradle.develocity") version ("4.4.2")
}
develocity {
    buildScan {
        uploadInBackground.set(System.getenv("CI") != null)
        termsOfUseUrl.set("https://gradle.com/help/legal-terms-of-use")
        termsOfUseAgree.set("yes")
    }
}

// ── Phase-1 module tree (RFC §3) ──
// Pure common-Kotlin codec + sans-io cores; each layer depends only downward.
// Platform code exists in exactly two places (arriving in later waves): webrtc-dtls
// backends (W4) and the UDP/mDNS gathering actuals in webrtc-ice (W3).
include(":webrtc")            // PeerConnection + JSEP + DataChannel — the consumer API (W6)
include(":webrtc-sdp")        // SDP parse/serialize — pure buffer-codec, no I/O (W6)
include(":webrtc-stun")       // STUN/TURN wire codec + sans-io transactions (W1)
include(":webrtc-ice")        // ICE agent (RFC 8445 + trickle) — sans-io core + gathering seams (W3)
include(":webrtc-dtls")       // DTLS 1.2/1.3 + SRTP exporter — BoringSSL backends (W4)
include(":webrtc-sctp")       // SCTP subset over DTLS + DCEP — pure Kotlin, sans-io (W5)
include(":webrtc-testsuite")  // published consumer harness: vnet, timeline engine, control plane (W7)

// L2/L3 interop harness endpoint (W7) — a NON-published native executable, not a library. It composes
// the real stack (:webrtc NativePeerConnection + real BoringSSL DTLS) over real UDP (socket-udp) and is
// driven as a container endpoint against coturn + real NAT kernels. Deliberately does NOT apply the
// webrtc.multiplatform-library convention (no publish/apiCheck/apple/js). See test-harness/README.md.
include(":webrtc-harness-endpoint")
