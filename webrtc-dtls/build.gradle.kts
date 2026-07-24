import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    id("webrtc.multiplatform-library")
}

// ── W4b · webrtc-dtls dependencies + the Kotlin/Native BoringSSL differential-oracle provisioning ─
//
// Targets, publishing, versioning, lint, and ABI validation all come from the
// webrtc.multiplatform-library convention (build-logic/). This file adds only:
//   1. module dependencies (buffer + buffer-crypto — production DTLS crypto primitives),
//   2. the `buildBoringsslOracle<Arch>` task that provisions a self-contained, symbol-PREFIXED
//      `libssl.a` + `libcrypto.a` (BoringSSL @ 63893acb, API 42 / DTLS 1.3) for K/N Linux, and
//   3. the `boringsslssl` cinterop wiring scoped to the **linuxX64/linuxArm64 TEST compilation**.
//
// W4b flipped production DTLS to a pure-Kotlin `commonMain` [DtlsEngine] over buffer-crypto — it runs
// on every non-browser target with NO native dependency, so BoringSSL is no longer in the published
// klib on any target. It survives here purely as the `linuxTest` **differential-testing oracle**
// (BoringSslDtlsEngine): our engine ⇄ BoringSSL, proving interop against an independent stack. That is
// why the cinterop attaches to the `test` compilation only — it must not leak into the shipped artifact.
//
// SYMBOL PREFIXING (the decoupling — see boringsslssl.def for the full rationale): the oracle builds
// BOTH `libssl.a` and `libcrypto.a` from commit 63893acb with `-DBORINGSSL_PREFIX=webrtc_dtls_oracle`,
// so every exported symbol becomes `webrtc_dtls_oracle_*`. The oracle links its OWN complete, prefixed
// BoringSSL and NEVER resolves against buffer-crypto's libcrypto. That permanently breaks the coupling
// that made a buffer bump (6.17.1+ moved buffer-crypto onto the canonical DTLS-1.2 bundle, which also
// carries an unprefixed libssl) collide with our oracle's libssl at the linuxTest link (duplicate ECH
// symbols). With prefixing, buffer/socket can bump freely forever while the full DTLS-1.3 oracle stays.

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(libs.buffer)
            // buffer-crypto supplies the PRODUCTION pure-Kotlin DTLS engine's crypto primitives (AES,
            // ECDHE, HMAC, …) on every target. On K/N Linux it vendors a canonical (unprefixed)
            // libcrypto for those primitives; the oracle below no longer depends on that libcrypto — it
            // brings its own prefixed copy — so the two never share a symbol namespace.
            api(libs.buffer.crypto)
            // Used ONLY by the rawEcdhPremaster expect/actual bridge (jvm/android/linux/apple actuals
            // `runBlocking` the one suspend-only primitive — deriveTlsPremasterSecret — so the sans-io
            // engine stays synchronous). The engine itself is coroutine-free.
            api(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

// ── Symbol-PREFIXED BoringSSL oracle provisioning (K/N Linux, test-only) ──────────────────────────
//
// Builds libssl.a + libcrypto.a from the SAME commit (63893acb = BoringSSL API 42, DTLS 1.3) with
// `-DBORINGSSL_PREFIX=webrtc_dtls_oracle`. This commit ships a PREGENERATED
// `include/openssl/prefix_symbols.h` (`#pragma redefine_extname NAME webrtc_dtls_oracle_NAME`, auto-
// included by `openssl/base.h` when BORINGSSL_PREFIX is defined), so a SINGLE cmake pass suffices — no
// two-pass read_symbols.go dance. libs/boringssl-oracle/** is gitignored and either built here in CI
// or dropped in from a prebuilt sibling tree on a dev box (marker-file skip).
val boringSslCommit = "63893acb3684fc756ddfa1ca4c6bab9e7b924e53"
val boringSslRepo = "https://github.com/google/boringssl.git"
val boringSslBuildScratch = layout.buildDirectory.dir("boringssl")

// The C-identifier prefix stamped onto every exported BoringSSL symbol. Must match the value the
// cinterop compiles against (boringsslssl.def's `-DBORINGSSL_PREFIX`).
val oraclePrefix = "webrtc_dtls_oracle"

// glibc >= 2.38 rewrites strtol/strtoul/strtoll/strtoull to __isoc23_* via a <stdlib.h> redirect, so a
// BoringSSL built on a modern host emits references to __isoc23_strtoull etc. Kotlin/Native's Linux
// sysroots ship an OLDER glibc without those symbols → K/N link fails. We ar-merge a tiny compat TU
// that forwards them to the real (pre-C23) entry points. Declaring the targets via __asm__ (and NOT
// including <stdlib.h>) sidesteps the redirect, so no self-recursion. Mirrors boringssl-kmp's
// :boringssl-build shim — previously this came in transitively via buffer-crypto's libcrypto; now the
// oracle owns its libcrypto, so it must carry the shim itself.
val isoC23CompatSource =
    """
    /* webrtc-dtls oracle — glibc>=2.38 __isoc23_* compat shim for Kotlin/Native linking. */
    extern unsigned long long strtoull(const char *, char **, int) __asm__("strtoull");
    extern long long          strtoll (const char *, char **, int) __asm__("strtoll");
    extern unsigned long      strtoul (const char *, char **, int) __asm__("strtoul");
    extern long               strtol  (const char *, char **, int) __asm__("strtol");
    unsigned long long __isoc23_strtoull(const char *n, char **e, int b){ return strtoull(n, e, b); }
    long long          __isoc23_strtoll (const char *n, char **e, int b){ return strtoll (n, e, b); }
    unsigned long      __isoc23_strtoul (const char *n, char **e, int b){ return strtoul (n, e, b); }
    long               __isoc23_strtol  (const char *n, char **e, int b){ return strtol  (n, e, b); }
    """.trimIndent()

fun createBuildBoringSslOracleTask(arch: String): TaskProvider<Task> {
    val taskName = "buildBoringsslOracle${arch.replaceFirstChar { it.uppercase() }}"
    val outputDir = project.projectDir.resolve("libs/boringssl-oracle/linux-$arch")
    // Marker keys on both the commit AND the prefix so a prefix change (or a stale unprefixed tree)
    // forces a rebuild.
    val markerFile = outputDir.resolve("lib/.built-$oraclePrefix-$boringSslCommit")

    return tasks.register(taskName) {
        group = "build"
        description = "Build symbol-prefixed BoringSSL libssl+libcrypto oracle for Linux $arch"
        inputs.property("boringSslCommit", boringSslCommit)
        inputs.property("oraclePrefix", oraclePrefix)
        outputs.file(markerFile)
        onlyIf { !markerFile.exists() }

        doLast {
            val scratch = boringSslBuildScratch.get().asFile
            val srcDir = File(scratch, "boringssl")

            fun run(
                vararg cmd: String,
                dir: File,
            ) {
                val rc =
                    ProcessBuilder(*cmd)
                        .directory(dir)
                        .redirectErrorStream(true)
                        .start()
                        .also { it.inputStream.bufferedReader().forEachLine { l -> logger.lifecycle(l) } }
                        .waitFor()
                if (rc != 0) throw GradleException("command failed (${cmd.joinToString(" ")}): exit $rc")
            }

            if (!File(srcDir, "include").exists()) {
                scratch.mkdirs()
                srcDir.deleteRecursively()
                logger.lifecycle("Cloning BoringSSL @ $boringSslCommit ...")
                run("git", "init", "boringssl", dir = scratch)
                run("git", "remote", "add", "origin", boringSslRepo, dir = srcDir)
                run("git", "fetch", "--depth", "1", "origin", boringSslCommit, dir = srcDir)
                run("git", "checkout", "FETCH_HEAD", dir = srcDir)
            }

            val cmakeBuildDir = File(srcDir, "build-oracle-$arch")
            if (cmakeBuildDir.exists()) cmakeBuildDir.deleteRecursively()
            cmakeBuildDir.mkdirs()

            // Same glibc-compat flags as buffer-crypto so the archives reference only symbols present
            // in Kotlin/Native's bundled (older) glibc (no fortify/stack-protector). Any __isoc23_*
            // refs that still leak in are resolved by the compat shim ar-merged below.
            val compatCFlags = "-fPIC -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector"
            // Cross-compiler for the isoc23 compat TU (must match the archive's object format/ABI).
            var compatCc = "gcc"
            val cmakeArgs =
                mutableListOf(
                    "cmake",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DBUILD_SHARED_LIBS=OFF",
                    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                    "-DBORINGSSL_PREFIX=$oraclePrefix",
                    "-DCMAKE_C_FLAGS=$compatCFlags",
                    "-DCMAKE_CXX_FLAGS=$compatCFlags",
                    "-G",
                    "Unix Makefiles",
                )
            if (arch == "arm64" && System.getProperty("os.arch") != "aarch64") {
                compatCc = "aarch64-linux-gnu-gcc"
                cmakeArgs.addAll(
                    listOf(
                        "-DCMAKE_SYSTEM_NAME=Linux",
                        "-DCMAKE_SYSTEM_PROCESSOR=aarch64",
                        "-DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc",
                        "-DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++",
                        "-DCMAKE_C_FLAGS=$compatCFlags -mno-outline-atomics",
                        "-DCMAKE_CXX_FLAGS=$compatCFlags -mno-outline-atomics",
                    ),
                )
            }
            cmakeArgs.add("..")

            fun runIn(
                dir: File,
                vararg cmd: String,
            ) {
                val rc =
                    ProcessBuilder(*cmd)
                        .directory(dir)
                        .redirectErrorStream(true)
                        .start()
                        .also { it.inputStream.bufferedReader().forEachLine { l -> logger.lifecycle(l) } }
                        .waitFor()
                if (rc != 0) throw GradleException("command failed (${cmd.joinToString(" ")}): exit $rc")
            }

            logger.lifecycle("Configuring prefixed BoringSSL oracle for $arch ...")
            runIn(cmakeBuildDir, *cmakeArgs.toTypedArray())
            // Build ONLY the crypto+ssl library targets (not `all` — that would pull the Go-dependent
            // verify_boringssl_prefix custom target and the tools/tests we don't need).
            logger.lifecycle("Building prefixed libcrypto + libssl for $arch ...")
            val cpu = Runtime.getRuntime().availableProcessors()
            runIn(cmakeBuildDir, "make", "-j$cpu", "crypto", "ssl")

            val builtSsl =
                cmakeBuildDir.walk().firstOrNull { it.name == "libssl.a" }
                    ?: throw GradleException("libssl.a not found under ${cmakeBuildDir.absolutePath}")
            val builtCrypto =
                cmakeBuildDir.walk().firstOrNull { it.name == "libcrypto.a" }
                    ?: throw GradleException("libcrypto.a not found under ${cmakeBuildDir.absolutePath}")

            val libOut = outputDir.resolve("lib").apply { mkdirs() }
            builtSsl.copyTo(libOut.resolve("libssl.a"), overwrite = true)
            val cryptoOut = libOut.resolve("libcrypto.a")
            builtCrypto.copyTo(cryptoOut, overwrite = true)

            // ar-merge the __isoc23_* compat shim into libcrypto.a (the archive that actually references
            // strtoull etc). Compiled with the target's CC so the object matches the archive's ABI.
            val compatC = cmakeBuildDir.resolve("isoc23_compat.c").apply { writeText(isoC23CompatSource) }
            val compatO = cmakeBuildDir.resolve("isoc23_compat.o")
            runIn(cmakeBuildDir, compatCc, "-c", "-fPIC", "-O2", compatC.absolutePath, "-o", compatO.absolutePath)
            runIn(cmakeBuildDir, "ar", "r", cryptoOut.absolutePath, compatO.absolutePath)

            val includeOutput = outputDir.resolve("include")
            val srcInclude = srcDir.resolve("src/include")
            val topInclude = srcDir.resolve("include")
            // The include tree carries the pregenerated openssl/prefix_symbols.h that base.h pulls in
            // under -DBORINGSSL_PREFIX; copying it wholesale is what makes the cinterop's inline C
            // resolve to the prefixed symbols.
            (if (srcInclude.exists()) srcInclude else topInclude).copyRecursively(includeOutput, overwrite = true)

            markerFile.writeText("BoringSSL oracle $oraclePrefix @ $boringSslCommit built ${System.currentTimeMillis()}")
            logger.lifecycle("Prefixed BoringSSL oracle ($arch) provisioned at ${outputDir.absolutePath}")
        }
    }
}

fun KotlinNativeTarget.configureDtlsCinterop(
    arch: String,
    buildTask: TaskProvider<Task>,
) {
    val boringsslDir = project.projectDir.resolve("libs/boringssl-oracle/linux-$arch")
    val libDir = boringsslDir.resolve("lib")
    val incDir = boringsslDir.resolve("include")

    // Scope the cinterop to the TEST compilation — BoringSSL is a linuxTest-only differential oracle
    // (W4b), never part of the shipped klib. The test klib/binary embeds the prefixed archives; the
    // published main klib carries none of it.
    compilations.getByName("test").cinterops.create("boringsslssl") {
        defFile(project.file("src/nativeInterop/cinterop/boringsslssl.def"))
        includeDirs(incDir.absolutePath)
        // Embed BOTH prefixed archives — the oracle is fully self-contained and shares NO symbol with
        // buffer-crypto's (unprefixed) libcrypto, so there is no duplicate-symbol trap.
        extraOpts(
            "-libraryPath",
            libDir.absolutePath,
            "-staticLibrary",
            "libssl.a",
            "-staticLibrary",
            "libcrypto.a",
        )
        tasks.named(interopProcessingTaskName).configure { dependsOn(buildTask) }
    }
    binaries.all {
        // The only linked binary on a library target is the test executable. Link the oracle's own
        // prefixed libssl + libcrypto; its C++ TUs need pthread + the C++ runtime at the final link.
        linkerOpts("-L${libDir.absolutePath}", "-lssl", "-lcrypto", "-lpthread", "-lstdc++")
    }
}

// The oracle is a linuxX64/linuxArm64 TEST-only artifact — provision + wire it ONLY on a Linux host. The
// linuxX64/linuxArm64 targets still EXIST when the KMP build runs on a non-Linux host (e.g. the macOS
// runner cross-publishing the linux klibs via `publishToMavenLocal`); an unguarded
// `targets.matching { linux }` would then pull the cinterop's build task into that host's graph, and the
// prefixed BoringSSL cmake configure runs `require_go()` — which aborts on the macOS runner (no Go). The
// oracle is never published and linux tests never run off Linux, so gating the whole thing on the host is
// correct: the Apple `publishToMavenLocal` publishes the Apple + linux-main klibs untouched, while Linux
// CI still builds the oracle for `linuxTest`. (See CI: build-apple failed at buildBoringsslOracleArm64.)
if (org.jetbrains.kotlin.konan.target.HostManager.hostIsLinux) {
    val buildBoringsslOracleX64 = createBuildBoringSslOracleTask("x64")
    val buildBoringsslOracleArm64 = createBuildBoringSslOracleTask("arm64")
    kotlin {
        targets.matching { it.name == "linuxX64" }.configureEach {
            (this as KotlinNativeTarget).configureDtlsCinterop("x64", buildBoringsslOracleX64)
        }
        targets.matching { it.name == "linuxArm64" }.configureEach {
            (this as KotlinNativeTarget).configureDtlsCinterop("arm64", buildBoringsslOracleArm64)
        }
    }
}
