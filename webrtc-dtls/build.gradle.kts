import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    id("webrtc.multiplatform-library")
}

// ── W4 · webrtc-dtls dependencies + the Kotlin/Native BoringSSL(libssl) provisioning ─────────────
//
// Targets, publishing, versioning, lint, and ABI validation all come from the
// webrtc.multiplatform-library convention (build-logic/). This file adds only:
//   1. module dependencies (buffer + buffer-crypto — the latter contributes the ONE libcrypto),
//   2. the `buildBoringsslSsl<Arch>` task that provisions a same-commit `libssl.a` for K/N Linux, and
//   3. the `boringsslssl` cinterop wiring on the Linux targets.
//
// See the EXECUTION_PLAN "W4 sequencing" decision row and boringsslssl.def for the linkage rationale:
// we link ONLY libssl.a (SSL/DTLS) and let its undefined libcrypto symbols resolve against
// buffer-crypto's already-linked `libcrypto.a` (no second copy → no duplicate-symbol clash). Apple /
// JVM / Android / JS DTLS is deferred to the `com.ditchoom.boringssl:boringssl-kmp` binary factory
// (unpublished today); those targets get a typed `DtlsUnavailable` actual this wave.

kotlin {
    sourceSets {
        commonMain.dependencies {
            api(libs.buffer)
            // buffer-crypto is the module that vendors + links BoringSSL's libcrypto (commit 63893acb)
            // on K/N Linux; depending on it puts that one libcrypto on our final link line, which our
            // libssl.a resolves against. On JVM/Android it is pure JCA (no native lib), harmless here.
            api(libs.buffer.crypto)
        }
        commonTest.dependencies {
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

// ── BoringSSL libssl.a provisioning (K/N Linux) ──────────────────────────────────────────────────
//
// MUST match buffer-crypto's pinned commit exactly: libssl.a is linked against buffer-crypto's
// libcrypto.a at the final K/N link, so the two archives must be one ABI (one commit). Mirrors
// buffer-crypto/build.gradle.kts's createBuildBoringSslTask, but runs `make ssl` and harvests
// libssl.a (buffer-crypto harvests only libcrypto.a). libs/boringssl-ssl/** is gitignored and either
// built here in CI or dropped in from a prebuilt sibling tree on a dev box (marker-file skip).
val boringSslCommit = "63893acb3684fc756ddfa1ca4c6bab9e7b924e53"
val boringSslRepo = "https://github.com/google/boringssl.git"
val boringSslBuildScratch = layout.buildDirectory.dir("boringssl")

fun createBuildBoringSslSslTask(arch: String): TaskProvider<Task> {
    val taskName = "buildBoringsslSsl${arch.replaceFirstChar { it.uppercase() }}"
    val outputDir = project.projectDir.resolve("libs/boringssl-ssl/linux-$arch")
    val markerFile = outputDir.resolve("lib/.built-$boringSslCommit")

    return tasks.register(taskName) {
        group = "build"
        description = "Build BoringSSL static libssl for Linux $arch (same commit as buffer-crypto's libcrypto)"
        inputs.property("boringSslCommit", boringSslCommit)
        outputs.file(markerFile)
        onlyIf { !markerFile.exists() }

        doLast {
            val scratch = boringSslBuildScratch.get().asFile
            val srcDir = File(scratch, "boringssl")

            fun run(vararg cmd: String, dir: File) {
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

            val cmakeBuildDir = File(srcDir, "build-ssl-$arch")
            if (cmakeBuildDir.exists()) cmakeBuildDir.deleteRecursively()
            cmakeBuildDir.mkdirs()

            // Same glibc-compat flags as buffer-crypto so the archive references only symbols present
            // in Kotlin/Native's bundled (older) glibc (no fortify/stack-protector). libssl's
            // undefined libcrypto refs — and any __isoc23_strtoull — resolve against buffer-crypto's
            // libcrypto.a (which carries the compat shim) at the final link.
            val compatCFlags = "-fPIC -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector"
            val cmakeArgs =
                mutableListOf(
                    "cmake",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DBUILD_SHARED_LIBS=OFF",
                    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
                    "-DCMAKE_C_FLAGS=$compatCFlags",
                    "-DCMAKE_CXX_FLAGS=$compatCFlags",
                    "-G",
                    "Unix Makefiles",
                )
            if (arch == "arm64" && System.getProperty("os.arch") != "aarch64") {
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

            fun runIn(dir: File, vararg cmd: String) {
                val rc =
                    ProcessBuilder(*cmd)
                        .directory(dir)
                        .redirectErrorStream(true)
                        .start()
                        .also { it.inputStream.bufferedReader().forEachLine { l -> logger.lifecycle(l) } }
                        .waitFor()
                if (rc != 0) throw GradleException("command failed (${cmd.joinToString(" ")}): exit $rc")
            }

            logger.lifecycle("Configuring BoringSSL for $arch (ssl) ...")
            runIn(cmakeBuildDir, *cmakeArgs.toTypedArray())
            logger.lifecycle("Building BoringSSL ssl for $arch ...")
            val cpu = Runtime.getRuntime().availableProcessors()
            runIn(cmakeBuildDir, "make", "-j$cpu", "ssl")

            val builtSsl =
                cmakeBuildDir.walk().firstOrNull { it.name == "libssl.a" }
                    ?: throw GradleException("libssl.a not found under ${cmakeBuildDir.absolutePath}")

            outputDir.resolve("lib").mkdirs()
            builtSsl.copyTo(outputDir.resolve("lib/libssl.a"), overwrite = true)

            val includeOutput = outputDir.resolve("include")
            val srcInclude = srcDir.resolve("src/include")
            val topInclude = srcDir.resolve("include")
            (if (srcInclude.exists()) srcInclude else topInclude).copyRecursively(includeOutput, overwrite = true)

            markerFile.writeText("BoringSSL(ssl) $boringSslCommit built ${System.currentTimeMillis()}")
            logger.lifecycle("BoringSSL libssl ($arch) provisioned at ${outputDir.absolutePath}")
        }
    }
}

val buildBoringsslSslX64 = createBuildBoringSslSslTask("x64")
val buildBoringsslSslArm64 = createBuildBoringSslSslTask("arm64")

fun KotlinNativeTarget.configureDtlsCinterop(arch: String) {
    val boringsslDir = project.projectDir.resolve("libs/boringssl-ssl/linux-$arch")
    val libDir = boringsslDir.resolve("lib")
    val incDir = boringsslDir.resolve("include")
    val buildTask = if (arch == "x64") buildBoringsslSslX64 else buildBoringsslSslArm64

    compilations.getByName("main").cinterops.create("boringsslssl") {
        defFile(project.file("src/nativeInterop/cinterop/boringsslssl.def"))
        includeDirs(incDir.absolutePath)
        // Embed ONLY libssl.a into our klib. libcrypto is contributed once by buffer-crypto (do NOT
        // add -staticLibrary libcrypto.a here — that is the duplicate-symbol trap).
        extraOpts("-libraryPath", libDir.absolutePath, "-staticLibrary", "libssl.a")
        tasks.named(interopProcessingTaskName).configure { dependsOn(buildTask) }
    }
    binaries.all {
        // libssl's C++ TUs (ssl/*.cc) and libcrypto need pthread + the C++ runtime at final link.
        linkerOpts("-L${libDir.absolutePath}", "-lssl", "-lpthread", "-lstdc++")
    }
}

kotlin {
    targets.matching { it.name == "linuxX64" }.configureEach {
        (this as KotlinNativeTarget).configureDtlsCinterop("x64")
    }
    targets.matching { it.name == "linuxArm64" }.configureEach {
        (this as KotlinNativeTarget).configureDtlsCinterop("arm64")
    }
}
