package com.ditchoom.webrtc.gradle

import org.gradle.api.Project
import java.net.URI

/**
 * Next-version derivation, cloned from the socket/buffer convention: read the latest published
 * version of the umbrella artifact from Maven Central and bump it. `-PincrementMajor` /
 * `-PincrementMinor` (set from PR labels by merged.yaml) pick the segment; patch is the default.
 * Non-CI builds get a `-SNAPSHOT` suffix.
 *
 * Greenfield adaptation: until the first `com.ditchoom:webrtc` release exists, the metadata fetch
 * fails; we fall back to `0.0.0` so the default patch bump yields the RFC's target `0.0.1`. Once the
 * first real release lands the fetch succeeds and normal increment resumes with no code change.
 */
internal fun Project.computeNextVersion(
    umbrellaArtifact: String = "webrtc",
    snapshot: Boolean,
): String {
    val base =
        try {
            val xml =
                URI("https://repo1.maven.org/maven2/com/ditchoom/$umbrellaArtifact/maven-metadata.xml")
                    .toURL()
                    .readText()
            Regex("<latest>(.*?)</latest>").find(xml)?.groupValues?.get(1)
                ?: Regex("<release>(.*?)</release>").find(xml)?.groupValues?.get(1)
                ?: "0.0.0"
        } catch (_: Exception) {
            "0.0.0"
        }

    val parts = base.split('.').mapNotNull { it.toIntOrNull() }
    val (major, minor, patch) = if (parts.size == 3) parts else listOf(0, 0, 0)

    val incrementMajor = hasProperty("incrementMajor") && property("incrementMajor") == "true"
    val incrementMinor = hasProperty("incrementMinor") && property("incrementMinor") == "true"
    val next =
        when {
            incrementMajor -> "${major + 1}.0.0"
            incrementMinor -> "$major.${minor + 1}.0"
            else -> "$major.$minor.${patch + 1}"
        }
    return if (snapshot) "$next-SNAPSHOT" else next
}
