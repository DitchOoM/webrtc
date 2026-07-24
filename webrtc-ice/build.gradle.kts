plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Sans-io agent core (RFC §5.1): handle(event, now) + nextDeadline. Gathering drivers ride
            // the DatagramChannel/NetworkMonitor seams; UDP/mDNS actuals arrive in W3.
            // buffer-flow carries the @ExperimentalDatagramApi DatagramChannel seam (buffer 6.11.0); the
            // core targets it, NOT socket-udp — socket-udp is real-socket only (no wasm/browser, RFC §1.1)
            // and is consumed at the platform-edge gathering driver, keeping the core all-platform.
            api(project(":webrtc-stun"))
            api(libs.buffer.flow)
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            // runTest virtual time — the whole seam gate (VnetDatagramSeamTest) runs on it. kotlin("test")
            // comes from the convention; coroutines-test is per-module.
            implementation(libs.kotlinx.coroutines.test)
            // W5 composition proof (test-only, acyclic — webrtc-sctp does NOT depend on webrtc-ice): the
            // real sans-io SctpAssociation + DataChannel run over the actual W3 ICE selected pair via the
            // vnet here, where the tested vnet + IceDriver already live. The full ICE+DTLS+SCTP stack is
            // W6's job; this is the ICE⇄SCTP seam check (HANDOFF W5). Drop when W6 owns the composition.
            implementation(project(":webrtc-sctp"))
        }
        // The real-socket resolution smoke test (RealUdpSocketSeamTest) binds two `socket-udp` UdpSockets
        // on loopback and echoes over the SAME buffer-flow DatagramChannel the vnet implements — proving
        // socket-udp resolves (from Central) and its actual honors the seam. JVM-only: socket-udp has no
        // wasm/browser target, and real UDP is not virtual-time (real dispatcher).
        jvmTest.dependencies {
            implementation(libs.socket.udp)
        }

        // ── mDNS multicast resolver actual (MulticastMdnsResolver, RFC 6762 `.local` resolution) ──
        // It binds a socket-udp MulticastDatagramChannel, so it compiles ONLY into the non-browser targets
        // that ship a socket-udp actual: jvm, android, linux, and — on a macOS host — macOS + iOS. One
        // physical dir (src/socketMain) is added to each of those MAIN source sets (the per-source-set
        // pattern), with socket-udp as their dependency. The sans-io core in commonMain stays socket-free
        // and all-platform. EXCLUDED on purpose: js/wasm (both are also `browser()`, which has no raw UDP —
        // a browser resolves `.local` inside its own RTCPeerConnection) and watchOS/tvOS (socket-udp
        // publishes no artifact for them, matching its Apple matrix — so `appleMain`/`nativeMain` are too
        // broad to hang the dependency on).
        val mdnsSocketSourceSets = mutableListOf("jvmMain", "androidMain", "linuxMain")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            mdnsSocketSourceSets += listOf("macosMain", "iosMain")
        }
        for (sourceSetName in mdnsSocketSourceSets) {
            named(sourceSetName) {
                kotlin.srcDir("src/socketMain/kotlin")
                dependencies {
                    implementation(libs.socket.udp)
                }
            }
        }
    }
}
