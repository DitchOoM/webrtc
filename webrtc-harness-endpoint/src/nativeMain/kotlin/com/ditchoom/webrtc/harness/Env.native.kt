@file:OptIn(ExperimentalForeignApi::class)

package com.ditchoom.webrtc.harness

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv

/**
 * Read an environment variable on Kotlin/Native (linuxX64 + linuxArm64) via posix `getenv`. The JVM
 * counterpart is [Env.jvm.kt]'s `System.getenv`; see it for why this is a plain per-source-set function
 * rather than `expect`/`actual`. Lives in `nativeMain` so both linux targets share the one posix impl.
 */
internal fun readEnv(name: String): String? = getenv(name)?.toKString()
