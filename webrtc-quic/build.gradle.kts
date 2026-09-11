plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // The adapter from ICE's app-data seam to buffer-flow's AddressedDatagramChannel and the
            // sealed outcome vocabulary need only webrtc-ice — no socket artifact, so every target
            // (browsers included) can name the types.
            api(project(":webrtc-ice"))
        }

        // ── The composition: open QUIC on the nominated pair ────────────────────────────────────
        // socket-quic-default resolves to quiche on jvm/android/linux/macOS/iOS and to an
        // UnsupportedQuicEngine on tvOS/watchOS/js/wasm; socket-udp (whose resolver spells addresses
        // the way quiche's sockaddr codec and peer comparison require) ships no browser artifact at
        // all. So the opening lives in the same shared `socketMain` shape webrtc-ice uses, hung on the
        // same leaves: a call site that reaches for QUIC-over-ICE in a browser should not compile.
        val socketMain by creating {
            dependsOn(commonMain.get())
            dependencies {
                api(libs.socket.quic.default)
                implementation(libs.socket.udp)
            }
        }
        val socketLeaves = mutableListOf("jvmMain", "androidMain", "linuxMain")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            socketLeaves += listOf("macosMain", "iosMain", "tvosMain", "watchosMain")
        }
        for (leaf in socketLeaves) {
            named(leaf) { dependsOn(socketMain) }
        }
    }
}
