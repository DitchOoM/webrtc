plugins {
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Pure text codec (RFC §3): a hand-written line parser/writer, zero platform code, zero
            // I/O — runs everywhere including browsers. SDP is text, so unlike webrtc-stun there is no
            // buffer-codec KSP schema; the only dependency is buffer core (ReadBuffer/WriteBuffer,
            // the single UTF-8 decode of the datagram, and the size-class allocator for encode).
            api(libs.buffer)
        }
    }
}

// ── Coverage-guided fuzzing (Jazzer) — T0′ (RFC §7) ──
// `sdpCodecFuzz` drives SdpCodecFuzzer (src/jvmTest) — the pure-Kotlin SDP parser — under
// Jazzer/libFuzzer. Because the parser is JVM bytecode (not opaque native), Jazzer gets REAL edge
// coverage of the line walk, the session/media split, and every typed field interpreter (RFC §7 T0′).
// Jazzer is runtime-only: the target uses the `byte[]` entry point, so nothing in jvmTest compiles
// against Jazzer — the driver comes from the dedicated `jazzer` configuration. The committed seed
// corpus (fuzz/corpus/sdp-codec) starts every run warm. Time-box with -PsdpFuzzSeconds=<n>.
val sdpJazzer =
    configurations.create("jazzer") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }
dependencies { add("jazzer", libs.jazzer) }

val sdpFuzzCorpusDir = projectDir.resolve("fuzz/corpus/sdp-codec")
val sdpFuzzWorkDir = layout.buildDirectory.dir("fuzz/sdp-codec")

tasks.register<JavaExec>("sdpCodecFuzz") {
    group = "verification"
    description = "Coverage-guided Jazzer fuzzing of the SDP parser (SdpCodecFuzzer). " +
        "Configure runtime with -PsdpFuzzSeconds=<n> (default 60)."
    dependsOn("jvmTestClasses")

    // Classpath from the jvm test compilation (main+test output + runtime deps) WITHOUT referencing
    // the jvmTest *task*, so launching the fuzzer doesn't first run the whole suite.
    val jvmTestCompilation = kotlin.jvm().compilations["test"]
    classpath =
        files(
            jvmTestCompilation.output.allOutputs,
            jvmTestCompilation.runtimeDependencyFiles,
        ) + sdpJazzer

    mainClass.set("com.code_intelligence.jazzer.Jazzer")

    val maxSeconds = providers.gradleProperty("sdpFuzzSeconds").orElse("60")
    val corpusDir = sdpFuzzCorpusDir
    val workDir = sdpFuzzWorkDir

    doFirst {
        corpusDir.mkdirs()
        workDir
            .get()
            .asFile
            .resolve("corpus")
            .mkdirs()
    }

    // libFuzzer writes crash-*/oom-*/timeout-* repros to artifact_prefix and new interesting inputs
    // only to the FIRST positional corpus dir — a gitignored build/ dir, so the committed seed corpus
    // (passed second) stays pristine across local runs.
    argumentProviders.add {
        val work = workDir.get().asFile
        listOf(
            "--target_class=com.ditchoom.webrtc.sdp.fuzz.SdpCodecFuzzer",
            "--instrumentation_includes=com.ditchoom.webrtc.sdp.**",
            "-print_final_stats=1",
            "-artifact_prefix=${work.absolutePath}/",
            "-max_total_time=${maxSeconds.get()}",
            work.resolve("corpus").absolutePath,
            corpusDir.absolutePath,
        )
    }
}
