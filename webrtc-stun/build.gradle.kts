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
            // Pure codec module (RFC §3): zero platform code, zero I/O — runs everywhere including
            // browsers. STUN/TURN schemas are buffer-codec KSP-generated, decoded as views over the
            // datagram buffer (RFC §6), never extracted to arrays.
            api(libs.buffer)
            api(libs.buffer.codec)
            // MESSAGE-INTEGRITY (HMAC-SHA1) + FINGERPRINT (CRC-32) are verified in place over slices
            // (RFC §6). CRC-32 is ReadBuffer.crc32 in buffer core; HMAC-SHA1 is buffer-crypto.
            implementation(libs.buffer.crypto)
        }
    }
}

// ── KSP (buffer-codec schema generation) ──
// KSP2 multiplatform shape: run the processor once on the common metadata compilation. Per-target
// runs would scatter generated sources across jvmMain/jsMain/… and break commonMain/commonTest
// references to the generated codecs. Mirrors buffer's :buffer-codec-test wiring.
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
// name — the KMP source Jars are the base Jar type that `withType<Jar>` misses. (Mirrors socket-http3.)
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
// `stunCodecFuzz` drives StunCodecFuzzer (src/jvmTest) — the pure-Kotlin STUN decoder — under
// Jazzer/libFuzzer. Because the parser is JVM bytecode (not opaque native), Jazzer gets REAL edge
// coverage, so the JVM fuzzer finally earns the coverage feedback the quiche lanes never had (RFC §7
// T0′). Jazzer is runtime-only: the target uses the `byte[]` entry point, so nothing in jvmTest
// compiles against Jazzer — the driver comes from the dedicated `jazzer` configuration. The committed
// seed corpus (fuzz/corpus/stun-codec) starts every run warm. Time-box with -PstunFuzzSeconds=<n>.
val stunJazzer =
    configurations.create("jazzer") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }
dependencies { add("jazzer", libs.jazzer) }

val stunFuzzCorpusDir = projectDir.resolve("fuzz/corpus/stun-codec")
val stunFuzzWorkDir = layout.buildDirectory.dir("fuzz/stun-codec")

tasks.register<JavaExec>("stunCodecFuzz") {
    group = "verification"
    description = "Coverage-guided Jazzer fuzzing of the STUN decoder (StunCodecFuzzer). " +
        "Configure runtime with -PstunFuzzSeconds=<n> (default 60)."
    dependsOn("jvmTestClasses")

    // Classpath from the jvm test compilation (main+test output + runtime deps) WITHOUT referencing
    // the jvmTest *task*, so launching the fuzzer doesn't first run the whole suite.
    val jvmTestCompilation = kotlin.jvm().compilations["test"]
    classpath =
        files(
            jvmTestCompilation.output.allOutputs,
            jvmTestCompilation.runtimeDependencyFiles,
        ) + stunJazzer

    mainClass.set("com.code_intelligence.jazzer.Jazzer")

    val maxSeconds = providers.gradleProperty("stunFuzzSeconds").orElse("60")
    val corpusDir = stunFuzzCorpusDir
    val workDir = stunFuzzWorkDir

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
            "--target_class=com.ditchoom.webrtc.stun.fuzz.StunCodecFuzzer",
            "--instrumentation_includes=com.ditchoom.webrtc.stun.**",
            "-print_final_stats=1",
            "-artifact_prefix=${work.absolutePath}/",
            "-max_total_time=${maxSeconds.get()}",
            work.resolve("corpus").absolutePath,
            corpusDir.absolutePath,
        )
    }
}
