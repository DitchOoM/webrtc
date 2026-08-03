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

// ── Module tree (ARCHITECTURE §3) ──
// Pure common-Kotlin codecs + sans-io cores; each layer depends only downward. Platform code exists in
// exactly two places: the UDP/mDNS actuals in webrtc-ice, and the network-monitor halves beside them.
include(":webrtc")            // PeerConnection + JSEP + DataChannel — the consumer API
include(":webrtc-sdp")        // SDP parse/serialize — hand-written text codec, no I/O
include(":webrtc-stun")       // STUN/TURN wire codec + sans-io transactions
include(":webrtc-ice")        // ICE agent (RFC 8445 + trickle) — sans-io core + gathering seams
include(":webrtc-dtls")       // DTLS 1.2/1.3 + SRTP exporter — pure Kotlin
include(":webrtc-sctp")       // SCTP subset over DTLS + DCEP — pure Kotlin, sans-io
include(":webrtc-testsuite")  // published consumer harness: vnet, timeline engine, control plane

// L2/L3 interop harness endpoint — a NON-published executable, not a library. It composes the real
// stack (:webrtc NativePeerConnection + PureKotlinDtls) over real UDP (socket-udp) and is driven as a
// container endpoint against coturn + real NAT kernels. Deliberately does NOT apply the
// webrtc.multiplatform-library convention (no publish/apiCheck/apple/js). See test-harness/README.md.
include(":webrtc-harness-endpoint")
