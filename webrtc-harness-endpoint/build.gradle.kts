import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

// ── W7 · L2/L3 interop harness endpoint (NON-published native executable) ────────────────────────
//
// This is NOT a library and deliberately does NOT apply the `webrtc.multiplatform-library` convention
// (no publishing, no apiCheck, no jvm/js/wasm/android/apple targets). It is a Kotlin/Native executable —
// the "our side" peer the L2 container harness runs behind real NAT kernels. JVM has no DTLS backend
// (W4 is native-Linux-only), so the interop endpoint MUST be the native linuxX64/linuxArm64 binary — the
// only backend with a real BoringSSL DTLS handshake (see webrtc HANDOFF "the one correction that
// reshapes the plan"). It composes the real stack over REAL UDP:
//   :webrtc  NativePeerConnection + BoringSslDtls   (the actual production session machine)
//   socket-udp  UdpSocket → buffer-flow DatagramChannel   (the real-UDP DatagramBinder + signaling)
//
// Linkage: depending on :webrtc pulls :webrtc-dtls transitively, whose cinterop klib embeds libssl.a and
// whose buffer-crypto dep contributes the ONE libcrypto.a — so BoringSSL links here exactly as it does in
// webrtc-dtls's own linuxTest. The only thing NOT propagated from webrtc-dtls's binaries is the system
// linkerOpts its C++ TUs need (pthread + libstdc++), re-added below. We intentionally depend ONLY on
// socket-udp (crypto-free), never socket core / socket-quic (they vendor a SECOND BoringSSL → the
// duplicate-symbol link break; see ~/git/cinterop-issues). That constraint is why signaling rides UDP.
//
// Source layout: KSP 2.3.10 has no common-metadata processing for a native-only module, so it runs
// per Kotlin/Native target. Per-target generated codecs land in `<target>Main`, invisible to a shared
// `linuxMain` metadata source set — so all sources live in ONE physical dir (`src/linuxSharedMain`) added
// to BOTH targets' *main* source sets. That compiles them per-target (not as shared metadata), so the
// code sees its target's generated codec, with zero file duplication. (The `…Main` dir name keeps the
// code under the standing-directives CI grep, which scans `*/src/*Main/*`.)

plugins {
    // Applies KGP + KSP from build-logic's classpath (NOT a module-level alias — that double-loads KGP).
    // KSP generates the buffer-codec signaling wire codecs (SignalingWire.kt) — same as STUN/SDP/SCTP.
    id("webrtc.native-executable")
}

kotlin {
    fun KotlinNativeTarget.configurePeerBinary() {
        binaries {
            executable("peer") {
                entryPoint = "com.ditchoom.webrtc.harness.main"
                // libssl.a (bundled in :webrtc-dtls's klib) drags in C++ TUs + pthread at the final link;
                // those system libs are set on webrtc-dtls's OWN binaries and are not propagated to a
                // downstream executable, so re-declare them here.
                linkerOpts("-lpthread", "-lstdc++")
            }
        }
        compilations.getByName("main").defaultSourceSet.kotlin.srcDir("src/linuxSharedMain/kotlin")
    }

    linuxX64 { configurePeerBinary() }
    linuxArm64 { configurePeerBinary() }

    sourceSets {
        // Deps live in commonMain (they propagate to both target compilations); the CODE lives in the
        // per-target-compiled shared srcDir above, so it can reference the per-target generated codecs.
        commonMain.dependencies {
            implementation(project(":webrtc"))
            implementation(project(":webrtc-dtls"))
            implementation(project(":webrtc-ice"))
            implementation(project(":webrtc-sctp"))
            implementation(project(":webrtc-sdp"))
            implementation(libs.socket.udp)
            implementation(libs.buffer)
            implementation(libs.buffer.flow)
            // buffer-codec: the signaling rendezvous wire schema (SignalingWire.kt) is KSP-generated.
            implementation(libs.buffer.codec)
            implementation(libs.kotlinx.coroutines.core)
        }
    }
}

// ── KSP (buffer-codec schema generation) ──
// Per-target processing (see the source-layout note above). Each `kspLinux*` run sees the shared
// `@ProtocolMessage` sources (part of its target's compilation) and generates the codecs into that
// target's own srcDir, which the KSP plugin adds to the compilation automatically — so the shared
// signaling code that references them resolves per target. Identical codec on both targets (generated,
// not hand-duplicated → no divergence risk).
dependencies {
    add("kspLinuxX64", libs.buffer.codec.processor)
    add("kspLinuxArm64", libs.buffer.codec.processor)
}
