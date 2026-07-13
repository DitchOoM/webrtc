plugins {
    // The convention applies KSP (shared classloader with KGP); this module supplies the
    // buffer-codec processor + generated srcDir wiring below to generate its @ProtocolMessage codecs.
    id("webrtc.multiplatform-library")
}

// Only this module's dependencies live here — targets, publishing, versioning, lint, and ABI
// validation all come from the webrtc.multiplatform-library convention (build-logic/).
kotlin {
    sourceSets {
        commonMain.dependencies {
            // Pure-Kotlin sans-io SCTP subset (RFC §3, §5.1): the chunk/DCEP wire codec is
            // commonMain-only, zero platform code, zero I/O — it runs everywhere including browsers,
            // exactly as webrtc-stun/webrtc-sdp do. Chunk values are zero-copy slice views over the
            // datagram (RFC §6), never extracted to arrays. The SCTP CRC32c checksum is self-contained
            // (Crc32c.kt) — a managed-ReadBuffer table (no primitive array, directive #1), so no
            // buffer-crypto dependency. The DTLS transport, the SCTP association state machine, and the
            // DataChannel StreamMux (the rest of W5) sit above this floor on the deferred UDP/DTLS
            // track — this deliverable is the wire codec + DCEP messages only.
            api(libs.buffer)
            api(libs.buffer.codec)
        }
    }
}

// ── KSP (buffer-codec schema generation) ──
// KSP2 multiplatform shape: run the processor once on the common metadata compilation. Per-target
// runs would scatter generated sources across jvmMain/jsMain/… and break commonMain/commonTest
// references to the generated codecs. Mirrors webrtc-stun's wiring.
dependencies {
    add("kspCommonMainMetadata", libs.buffer.codec.processor)
    add("kspCommonMainMetadata", libs.buffer.codec)
}

kotlin.sourceSets.named("commonMain") {
    kotlin.srcDir("build/generated/ksp/metadata/commonMain/kotlin")
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask<*>>().configureEach {
    if (name != "kspCommonMainKotlinMetadata") {
        dependsOn("kspCommonMainKotlinMetadata")
    }
}

// commonMain pulls in the KSP-generated srcDir above; the convention's ktlint filter excludes
// generated code, but Gradle still sees the ktlint task reading a directory written by
// kspCommonMainKotlinMetadata and flags an implicit dependency. Declare it explicitly.
tasks
    .matching {
        it.name == "runKtlintCheckOverCommonMainSourceSet" ||
            it.name == "runKtlintFormatOverCommonMainSourceSet"
    }.configureEach {
        dependsOn("kspCommonMainKotlinMetadata")
    }

// Publishing tasks (`sourcesJar`, per-target `<target>SourcesJar`, the Dokka-backed `javadocJar`)
// package commonMain sources, which now include the KSP-generated srcDir — so they read
// kspCommonMainKotlinMetadata's output and Gradle reports the same implicit-dependency validation
// error at publish time (build/test/apiCheck don't hit it, only `publishToMavenLocal` does). Match by
// name — the KMP source Jars are the base Jar type that `withType<Jar>` misses. (Mirrors webrtc-stun.)
tasks
    .matching {
        it.name == "sourcesJar" ||
            it.name.endsWith("SourcesJar") ||
            it.name == "javadocJar" ||
            it.name.endsWith("JavadocJar")
    }.configureEach {
        dependsOn("kspCommonMainKotlinMetadata")
    }

// ── Coverage-guided fuzzing (Jazzer) — T0′ (RFC §7) ──
// `sctpCodecFuzz` drives SctpCodecFuzzer (src/jvmTest) — the pure-Kotlin SCTP packet + DCEP decoders —
// under Jazzer/libFuzzer. Because the parser is JVM bytecode (not opaque native), Jazzer gets REAL
// edge coverage of the common-header decode, the chunk TLV walk, the parameter/error-cause sub-TLV
// walks, the in-place CRC32c, and the DCEP field parse (RFC §7 T0′). Jazzer is runtime-only: the
// target uses the `byte[]` entry point, so nothing in jvmTest compiles against Jazzer — the driver
// comes from the dedicated `jazzer` configuration. The committed seed corpus (fuzz/corpus/sctp-codec)
// starts every run warm. Time-box with -PsctpFuzzSeconds=<n>.
val sctpJazzer =
    configurations.create("jazzer") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }
dependencies { add("jazzer", libs.jazzer) }

val sctpFuzzCorpusDir = projectDir.resolve("fuzz/corpus/sctp-codec")
val sctpFuzzWorkDir = layout.buildDirectory.dir("fuzz/sctp-codec")

tasks.register<JavaExec>("sctpCodecFuzz") {
    group = "verification"
    description = "Coverage-guided Jazzer fuzzing of the SCTP + DCEP decoders (SctpCodecFuzzer). " +
        "Configure runtime with -PsctpFuzzSeconds=<n> (default 60)."
    dependsOn("jvmTestClasses")

    // Classpath from the jvm test compilation (main+test output + runtime deps) WITHOUT referencing
    // the jvmTest *task*, so launching the fuzzer doesn't first run the whole suite.
    val jvmTestCompilation = kotlin.jvm().compilations["test"]
    classpath =
        files(
            jvmTestCompilation.output.allOutputs,
            jvmTestCompilation.runtimeDependencyFiles,
        ) + sctpJazzer

    mainClass.set("com.code_intelligence.jazzer.Jazzer")

    val maxSeconds = providers.gradleProperty("sctpFuzzSeconds").orElse("60")
    val corpusDir = sctpFuzzCorpusDir
    val workDir = sctpFuzzWorkDir

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
            "--target_class=com.ditchoom.webrtc.sctp.fuzz.SctpCodecFuzzer",
            "--instrumentation_includes=com.ditchoom.webrtc.sctp.**",
            "-print_final_stats=1",
            "-artifact_prefix=${work.absolutePath}/",
            "-max_total_time=${maxSeconds.get()}",
            work.resolve("corpus").absolutePath,
            corpusDir.absolutePath,
        )
    }
}
