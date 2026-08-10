plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // The consumer API (ARCHITECTURE §3.1): PeerConnection as a Layer-2 session, DataChannel as StreamMux.
            // Browser/wasmJs peerConnectionSupport() delegates to RTCPeerConnection (added in W6).
            api(project(":webrtc-ice"))
            api(project(":webrtc-sctp"))
            api(project(":webrtc-sdp"))
            // The DTLS transport `PureKotlinDtls` drives. Pure Kotlin in commonMain on EVERY non-browser
            // target — there is no platform whose actual reports a missing backend. (This comment used to
            // say Native-Linux had BoringSSL and everyone else got a typed BackendUnavailable; that stopped
            // being true when the engine moved to commonMain, and BoringSSL survives only as a linuxTest
            // differential oracle.)
            api(project(":webrtc-dtls"))
            api(libs.buffer.flow)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            // runTest virtual time drives the whole session round-trip (offer/answer → ICE → SCTP → data)
            // at zero wall-clock on every platform. kotlin("test") comes from the convention.
            implementation(libs.kotlinx.coroutines.test)
        }

        // ── The native entry point: nativePeerConnection() (issue #136 / #135) ───────────────────
        // It composes things that exist only where real UDP does — webrtc-ice's `systemIceGathering()`
        // and `MulticastMdnsEndpoint`, both in THAT module's `socketMain` — so it compiles into exactly
        // the same leaves, and the source set is named to match.
        //
        // It does NOT depend on socket-udp: ARCHITECTURE §11.6 keeps that dependency to webrtc-ice's
        // socketMain alone, and this factory needs none of it directly. The binder is a REQUIRED
        // parameter, so the entry point structurally cannot bind a socket of its own — which is the
        // property that lets a WebRTC session and a QUIC-P2P connection share one demuxed socket, and
        // the reason a native factory was deferred twice before this one.
        //
        // Same shared-source-set shape (and the same Dokka constraint — one file, one owning source set)
        // as webrtc-ice's socketMain, and the same leaves for the same reason: js/wasm delegate to
        // RTCPeerConnection. tvOS/watchOS were excluded here too until socket 4.1.6 (socket#297)
        // published their socket-udp targets and closed webrtc#127; the leaf list tracks webrtc-ice's,
        // which is where the full note lives.
        val socketMain by creating { dependsOn(commonMain.get()) }
        val socketLeaves = mutableListOf("jvmMain", "androidMain", "linuxMain")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            socketLeaves += listOf("macosMain", "iosMain", "tvosMain", "watchosMain")
        }
        for (leaf in socketLeaves) {
            named(leaf) { dependsOn(socketMain) }
        }

        // ── The test mirror: one real-socket suite, every platform that has a socket ──────────────
        // Until this existed, **no real-socket test source set existed anywhere in the repo**. Linux's
        // real-wire coverage came entirely from the Docker L2 harness and the harness module's own
        // `JvmRealUdpLoopbackTest` — and `webrtc-harness-endpoint` is jvm + linuxX64 + linuxArm64 only, so
        // it structurally cannot reach Apple. The result was that `macosArm64Test`/`iosSimulatorArm64Test`
        // ran the vnet suite and nothing else: `udpDatagramBinder()`, the Apple send path (which reads
        // `position()`/`remaining()` directly), and the `requiresNativeMemoryBuffers` bind check were
        // compiled on Apple and never executed anywhere. That is the blind spot the buffer-crypto Apple
        // AEAD leak sat in.
        //
        // Paired with `socketMain` and named to match, because it tests exactly what that source set adds.
        // The leaves are the same minus Android: an Android *unit* test runs on a host JVM with no device,
        // so a real bind there proves the JVM path a second time rather than the Android one — instrumented
        // coverage is a different (and separately worthwhile) exercise. The `hostIsMac` guard is the same
        // one above, for the same reason: those leaves do not exist when the host cannot build them.
        val socketTest by creating { dependsOn(commonTest.get()) }
        val socketTestLeaves = mutableListOf("jvmTest", "linuxTest")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            socketTestLeaves += listOf("macosTest", "iosTest", "tvosTest", "watchosTest")
        }
        for (leaf in socketTestLeaves) {
            named(leaf) { dependsOn(socketTest) }
        }
    }
}

// ReadmeQuickstartTest reads README.md and fails if the documented wiring has drifted from the code it
// runs. Declaring the file as a task input is what makes that guard honest: without it, editing only the
// README leaves `jvmTest` UP-TO-DATE and the check silently does not run — which is precisely the failure
// mode (an unnoticed edit to a snippet nothing compiles) the test exists to close.
tasks.named<Test>("jvmTest") {
    inputs
        .file(rootProject.file("README.md"))
        .withPropertyName("readme")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}
