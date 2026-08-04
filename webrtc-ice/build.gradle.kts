plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Sans-io agent core (ARCHITECTURE §5.1): handle(event, now) + nextDeadline. Gathering drivers ride
            // the DatagramChannel/NetworkMonitor seams; UDP/mDNS actuals arrive in W3.
            // buffer-flow carries the @ExperimentalDatagramApi DatagramChannel seam (buffer 6.11.0); the
            // core targets it, NOT socket-udp — socket-udp is real-socket only (no wasm/browser, ARCHITECTURE §1.1)
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

        // ── Real-socket tests that must run on MORE THAN ONE platform (`socketTest`) ──────────────
        // `UdpDatagramBinderTest` establishes ICE between two agents over sockets the shipped
        // `udpDatagramBinder()` bound. It has to compile into both the JVM and a Kotlin/Native leaf, and
        // that is not a nicety: the two receive paths are *different implementations* — NIO on the JVM,
        // io_uring on Linux, `NWConnection` on Apple — with different allocation requirements, and a
        // JVM-only version of this test passes while the native one is broken. It did exactly that, once.
        //
        // Same shared-source-set shape as `monitorReplayTest` below, and for the same Dokka-adjacent
        // reason: one physical file, one owning source set, compiled per leaf.
        //
        // linuxTest, not nativeTest: `nativeTest` also covers watchOS/tvOS, for which socket-udp publishes
        // no artifact at all (which is the same reason `socketMain` names its leaves explicitly).
        val socketTest by creating {
            dependsOn(commonTest.get())
            dependencies { implementation(libs.socket.udp) }
        }
        val socketTestLeaves = mutableListOf("jvmTest", "linuxTest")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            socketTestLeaves += listOf("macosTest", "iosTest")
        }
        for (leaf in socketTestLeaves) {
            named(leaf) { dependsOn(socketTest) }
        }

        // ── The real-socket edge: udpDatagramBinder() + the mDNS multicast resolver ──────────────
        // Two things that bind a socket-udp channel, so they compile ONLY into the non-browser targets
        // that ship a socket-udp actual: jvm, android, linux, and — on a macOS host — macOS + iOS.
        //
        //  · `udpDatagramBinder()` — the production DatagramBinder every real session passes to
        //    NativePeerConnection. It is the ONE substitution between a vnet run and a real-kernel run,
        //    which is exactly why it belongs beside the seam it implements rather than in each consumer.
        //  · `MulticastMdnsResolver` — RFC 6762 `.local` resolution over a MulticastDatagramChannel.
        //
        // Their absence on the remaining targets is the design, not a gap to paper over: a browser has no
        // raw UDP and delegates to its own RTCPeerConnection, so a call site that reaches for a binder
        // there should not compile.
        //
        // Modeled as a REAL shared `socketMain` source set (its files live once in src/socketMain/kotlin,
        // the default root for a source set of that name) that those leaves `dependsOn` — NOT a srcDir
        // replicated across each leaf. Both keep the sans-io commonMain core socket-free, but replicating
        // one physical file across several leaf source sets makes Dokka reject it: its pre-generation check
        // ("every Kotlin source file belongs to only one source set") fails with `Source sets 'android' and
        // 'jvm' … have the common source roots: …/MulticastMdnsResolver.kt`, breaking
        // :webrtc-ice:dokkaGeneratePublicationHtml (build-linux). A shared source set is one module → one
        // owner. EXCLUDED on purpose: js/wasm (both `browser()`, no raw UDP) and watchOS/tvOS (socket-udp
        // publishes no artifact for them, so `appleMain`/`nativeMain` are too broad to hang the dependency
        // on — which is also why those five targets publish yet cannot establish a session).
        val socketMain by creating {
            dependsOn(commonMain.get())
            dependencies {
                implementation(libs.socket.udp)
            }
        }
        val socketLeaves = mutableListOf("jvmMain", "androidMain", "linuxMain")
        if (org.jetbrains.kotlin.konan.target.HostManager.hostIsMac) {
            socketLeaves += listOf("macosMain", "iosMain")
        }
        for (leaf in socketLeaves) {
            named(leaf) { dependsOn(socketMain) }
        }

        // ── The production NetworkMonitor (#69) ──────────────────────────────────────────────────
        // It has two halves, and they come from different places on purpose.
        //
        //  ENUMERATION (which local ADDRESSES exist) is ours: `systemInterfaceEnumerator()`. It has to
        //  be — `com.ditchoom:network-monitor` answers "is the network up, and what link am I on"
        //  (one sealed NetworkState carrying a NetworkId of Link(kind, handle)), and carries no addresses,
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
        //   · nativeMain    → com.ditchoom:network-monitor, the same artifact as the two leaves above.
        //
        //     This used to be `com.ditchoom:socket` core, "the ONLY place we depend on it", because
        //     socket's netlink and NWPathMonitor monitors reused its LinuxSockets / NWHelpers cinterop
        //     while :network-monitor deliberately stayed free of cinterops — so on native that artifact
        //     shipped the contract with no implementation behind it. It was written down as a known
        //     interim against DitchOoM/socket#269, and socket#275 CLOSED it: :network-monitor now owns
        //     every monitor, `default()` and `enumerateNetworkInterfaces()`, with its own netlink and
        //     Apple cinterops.
        //
        //     Verified as a differential rather than assumed. Against socket 4.0.0 this same swap does
        //     not compile — `InterfaceChangeTrigger.nativeMain.kt` fails with `Unresolved reference
        //     'default'` / `'state'` / `'close'`, which is precisely "the contract with no implementation
        //     behind it". Against 4.0.1 it compiles and all 9 SystemNetworkMonitorTest cases pass on
        //     linuxX64. js/wasmJs need neither dependency — they report NoPlatformApi and are moot.
        //
        //     With this, `com.ditchoom:socket` core is no longer a dependency of this repo at all; the
        //     only socket artifact left is socket-udp, in `socketMain` (ARCHITECTURE §11.6). The old
        //     "socket core vendors a SECOND BoringSSL → duplicate-symbol link break" objection is
        //     therefore doubly moot, and was already obsolete before that.
        // network-monitor is declared on the SHARED set rather than per-leaf, so `linkTopology()` — the
        // projection that decides what counts as "the network moved" — can be written once for jvm and
        // android instead of once each. It has to be repeated in nativeMain regardless (different
        // artifact, same type), which is exactly the getifaddrs situation above.
        val javaMain by creating {
            dependsOn(commonMain.get())
            dependencies { implementation(libs.network.monitor) }
        }
        for (leaf in listOf("jvmMain", "androidMain")) {
            named(leaf) { dependsOn(javaMain) }
        }
        named("nativeMain") {
            dependencies { implementation(libs.network.monitor) }
        }

        // ── The real-device flap replay (#113) ───────────────────────────────────────────────────
        // `linkTopology()` exists twice — once in javaMain, once in nativeMain — because the two read
        // the same NetworkState out of different artifacts (socket#269). Two copies of a decision want
        // ONE test, or the duplication is unguarded: edit one and nothing notices. So the replay lives
        // in a shared TEST source set that both jvmTest and nativeTest `dependsOn`, and each leaf
        // compiles it against its own copy.
        //
        // socket-testkit is test-only and stays that way: it pulls socket CORE transitively, which
        // jvmMain deliberately does not depend on, so it must never reach a published POM.
        val monitorReplayTest by creating {
            dependsOn(commonTest.get())
            dependencies { implementation(libs.socket.testkit) }
        }
        for (leaf in listOf("jvmTest", "nativeTest")) {
            named(leaf) { dependsOn(monitorReplayTest) }
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
