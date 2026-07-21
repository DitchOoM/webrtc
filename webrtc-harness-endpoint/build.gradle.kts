import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

// ── W7 · L2/L3 interop harness endpoint (NON-published) ──────────────────────────────────────────
//
// The "our side" peer the L2 container harness runs behind real NAT kernels. It composes the PRODUCTION
// stack over REAL UDP and establishes a full WebRTC data channel against real independent engines
// (another of our peers, Pion, Chrome, Firefox):
//   :webrtc  NativePeerConnection + PureKotlinDtls   (the actual production session machine)
//   socket-udp  UdpSocket → buffer-flow DatagramChannel   (the real-UDP DatagramBinder + signaling)
//
// It targets BOTH Kotlin/Native (linuxX64 + linuxArm64) AND the JVM. Since the W4b flip, DTLS is
// pure-Kotlin `commonMain` on every target (BoringSSL demoted to a linuxTest oracle) — so the JVM now
// has a real DTLS handshake too, and a JVM peer (JRE + the pure engine + socket-udp's NIO datapath) is a
// first-class interop endpoint. The native binary and the JVM jar run the SAME common datapath; the ONLY
// per-platform code is `readEnv` (posix vs System.getenv). The JVM lane proves the pure engine on the real
// wire from a managed runtime, and its jar is arch-independent (one build runs on x64 AND arm64 runners),
// unlike the native peer which K/N must cross-build per arch. This is NOT a published library — it
// deliberately does NOT apply `webrtc.multiplatform-library` (no publishing/apiCheck/js/wasm/apple).
//
// Linkage (native): depending on :webrtc pulls :webrtc-dtls transitively, whose cinterop klib embeds
// libssl.a (linuxTest oracle) and whose buffer-crypto dep contributes libcrypto.a — but the PRODUCTION
// engine is pure Kotlin, so the native binary needs only the system libs the C TUs drag in (pthread +
// libstdc++), re-added on the executable below. We depend ONLY on socket-udp (crypto-free), never socket
// core / socket-quic (they vendor a SECOND BoringSSL → the duplicate-symbol link break; see
// ~/git/cinterop-issues). That constraint is why signaling rides UDP.
//
// Source layout: KSP 2.3.10 has no common-metadata processing here, so it runs per compilation. Per-target
// generated codecs land in `<target>Main`, invisible to a shared metadata source set — so all shared
// sources live in ONE physical dir (`src/commonSharedMain`) added to EVERY target's *main* source set
// (jvm + both linux). That compiles them per-target (not as shared metadata), so the code sees its own
// target's generated codec, with zero file duplication. The one true per-platform seam (`readEnv`) lives
// in the real `jvmMain` / `nativeMain` source sets instead. (`…Main` / `…Test` dir names keep the code
// under the standing-directive CI grep, which scans `*/src/*Main/*` and `*/src/*Test/*`.)

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
        compilations.getByName("main").defaultSourceSet.kotlin.srcDir("src/commonSharedMain/kotlin")
        compilations.getByName("test").defaultSourceSet.kotlin.srcDir("src/commonSharedTest/kotlin")
    }

    jvm {
        // The shared harness code is compiled into the jvm main/test compilations too (per-target KSP, as
        // for the native targets), so the JVM peer sees its own kspJvm-generated codecs.
        compilations.getByName("main").defaultSourceSet.kotlin.srcDir("src/commonSharedMain/kotlin")
        compilations.getByName("test").defaultSourceSet.kotlin.srcDir("src/commonSharedTest/kotlin")
    }
    linuxX64 { configurePeerBinary() }
    linuxArm64 { configurePeerBinary() }

    sourceSets {
        // Deps live in commonMain (they propagate to every target compilation); the CODE lives in the
        // per-target-compiled shared srcDirs above, so it can reference the per-target generated codecs.
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
        // Unit tests for the harness's own logic (e.g. the signaling request/response correlation). Native
        // test compilations run on the matching host (linuxX64Test on an x64 runner); the same shared test
        // runs on the JVM under `jvmTest` — both under `./gradlew build`.
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

// ── KSP (buffer-codec schema generation) ──
// Per-compilation processing (see the source-layout note above). Each `ksp<Target>` run sees the shared
// `@ProtocolMessage` sources (part of that compilation) and generates the codecs into that compilation's
// own srcDir, which the KSP plugin adds automatically — so the shared signaling code that references them
// resolves per target. Identical codec on every target (generated, not hand-duplicated → no divergence).
dependencies {
    add("kspJvm", libs.buffer.codec.processor)
    add("kspLinuxX64", libs.buffer.codec.processor)
    add("kspLinuxArm64", libs.buffer.codec.processor)
}

// ── JVM peer fat jar ──
// A self-contained, arch-independent runnable jar (compiled classes + every runtime dependency + a
// Main-Class manifest) so the JVM peer Docker image is just `FROM eclipse-temurin:21-jre` + this jar +
// `java -jar`. `fun main()` in the shared code compiles to `com.ditchoom.webrtc.harness.MainKt` on the JVM.
val peerJvmMain = kotlin.jvm().compilations.getByName("main")
val peerJar =
    tasks.register<Jar>("peerJar") {
        archiveBaseName.set("webrtc-harness-peer")
        archiveClassifier.set("all")
        manifest { attributes["Main-Class"] = "com.ditchoom.webrtc.harness.MainKt" }
        from(peerJvmMain.output.allOutputs)
        dependsOn(peerJvmMain.runtimeDependencyFiles)
        from({
            peerJvmMain.runtimeDependencyFiles.filter { it.name.endsWith(".jar") }.map { zipTree(it) }
        })
        // Drop signing metadata from dependency jars (a signed entry breaks under repackaging) and dedup
        // any coincident resource paths across dependencies.
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.kotlin_module")
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

// Build the peer jar as part of the module's `assemble`/`build` so CI produces it without a bespoke task.
tasks.named("assemble") { dependsOn(peerJar) }
