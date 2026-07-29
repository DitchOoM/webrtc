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
        // that ship a socket-udp actual: jvm, android, linux, and — on a macOS host — macOS + iOS.
        //
        // Modeled as a REAL shared `socketMain` source set (its files live once in src/socketMain/kotlin,
        // the default root for a source set of that name) that those leaves `dependsOn` — NOT a srcDir
        // replicated across each leaf. Both keep the sans-io commonMain core socket-free, but replicating
        // one physical file across several leaf source sets makes Dokka reject it: its pre-generation check
        // ("every Kotlin source file belongs to only one source set") fails with `Source sets 'android' and
        // 'jvm' … have the common source roots: …/MulticastMdnsResolver.kt`, breaking
        // :webrtc-ice:dokkaGeneratePublicationHtml (build-linux). A shared source set is one module → one
        // owner. EXCLUDED on purpose: js/wasm (both `browser()`, no raw UDP — a browser resolves `.local`
        // inside its own RTCPeerConnection) and watchOS/tvOS (socket-udp publishes no artifact for them, so
        // `appleMain`/`nativeMain` are too broad to hang the dependency on).
        val socketMain by creating {
            dependsOn(commonMain.get())
            dependencies {
                implementation(libs.socket.udp)
            }
        }
        val mdnsSocketLeaves = mutableListOf("jvmMain", "androidMain", "linuxMain")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            mdnsSocketLeaves += listOf("macosMain", "iosMain")
        }
        for (leaf in mdnsSocketLeaves) {
            named(leaf) { dependsOn(socketMain) }
        }

        // ── The production NetworkMonitor (#69) ──────────────────────────────────────────────────
        // It has two halves, and they come from different places on purpose.
        //
        //  ENUMERATION (which local ADDRESSES exist) is ours: `systemInterfaceEnumerator()`. It has to
        //  be — `com.ditchoom:network-monitor` answers "is the network up, and what link am I on"
        //  (availability + a sealed NetworkId of Link(kind, handle)), and carries no addresses at all,
        //  while IceAgentDriver.pathRidesOneOf compares the selected pair's local IP against the set.
        //  jvm and android read the SAME API for it (`java.net.NetworkInterface`), so that actual is one
        //  physical file in a REAL shared source set both leaves `dependsOn`, exactly as `socketMain`
        //  above and for the same Dokka reason (one source file, one owning source set, or
        //  dokkaGeneratePublicationHtml rejects it).
        //
        //  REACTIVITY (WHEN did it change) is socket's, so we do not hand-roll a second one:
        //   · jvm + android → com.ditchoom:network-monitor — cinterop-free, and its only commonMain
        //     dependency is kotlinx-coroutines-core. Hung on the two leaves rather than commonMain: the
        //     sans-io core stays dependency-free and all-platform (browsers included).
        //   · nativeMain    → com.ditchoom:socket core, the ONLY place we depend on it. socket's netlink
        //     and NWPathMonitor monitors reuse its LinuxSockets / NWHelpers cinterop, which
        //     :network-monitor deliberately stays free of, so on native that artifact ships the contract
        //     with no implementation behind it. Known interim — DitchOoM/socket#269.
        //
        //     The old "socket core vendors a SECOND BoringSSL → duplicate-symbol link break" objection is
        //     OBSOLETE, verified not assumed: socket 3.15.1's LinuxSockets klib embeds only liburing.a
        //     (the libssl.a/libcrypto.a in 3.9.5 are gone), and socket:3.15.1 + buffer-crypto:6.22.0 both
        //     resolve to the SAME com.ditchoom.boringssl:boringssl-canonical:0.0.6, which Gradle dedupes.
        //     Proven by linking the production webrtc-harness-endpoint executable on linuxX64 AND
        //     linuxArm64 with this dependency present, and by running socket's netlink monitor under
        //     linuxX64Test. js/wasmJs need neither dependency — they report NoPlatformApi and are moot.
        val javaMain by creating {
            dependsOn(commonMain.get())
        }
        for (leaf in listOf("jvmMain", "androidMain")) {
            named(leaf) {
                dependsOn(javaMain)
                dependencies { implementation(libs.network.monitor) }
            }
        }
        named("nativeMain") {
            dependencies { implementation(libs.socket.core) }
        }

        // ── Android reactivity proof (#104) ──────────────────────────────────────────────────────
        // Android was the ONLY target whose trigger had no runtime proof: Linux asserts against real
        // AF_NETLINK, Apple against a real NWPathMonitor on the macOS runner, the JVM against the
        // JDK-21 FFM routing socket — and `androidHostTest` exercised the code path with no
        // ConnectivityManager behind it. That inversion is the whole of #104: Wi-Fi→cellular is the
        // canonical IceRestartPolicy.OnNetworkChange case and it is a *mobile* phenomenon.
        //
        // Robolectric runs the real framework classes on the host JVM, so this is an ordinary
        // `testAndroidHostTest` in the existing build-linux lane — no emulator, no new CI lane. It
        // proves the ADAPTER (a ConnectivityManager callback reaches our seam); it deliberately does
        // not claim to prove the RADIO (that a real handoff fires onLost), which is #102's job.
        named("androidHostTest") {
            dependencies {
                implementation(libs.robolectric)
                implementation(libs.androidx.test.core.ktx)
            }
        }
    }
}
