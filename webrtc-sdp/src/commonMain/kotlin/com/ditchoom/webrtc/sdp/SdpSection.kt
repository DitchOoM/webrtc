package com.ditchoom.webrtc.sdp

/**
 * A run of SDP lines that carries `a=` attributes — either the session block ([SessionDescription])
 * or one media block ([MediaDescription]). RFC 8866 §5.13 attributes appear in both, and the JSEP
 * ICE/DTLS parameters (`a=ice-ufrag`, `a=ice-pwd`, `a=fingerprint`, `a=setup`) may sit at session
 * level as a default or be overridden per media section (RFC 8829 §5.2.1) — so the typed interpreters
 * that read them are shared here rather than duplicated.
 *
 * Every interpreter is **null/empty on malformed** (never a throw) and reads from the retained
 * verbatim [lines]; nothing is precomputed, mirroring STUN's on-demand `asXxx` attribute readers.
 */
public sealed interface SdpSection {
    /** The verbatim lines of this section, in order (excluding the `m=` line for a media section). */
    public val lines: List<SdpLine>
}

/** Every `a=<name>:<value>` value for [name], in document order (property attributes are skipped). */
public fun SdpSection.attributeValues(name: String): List<String> =
    lines.mapNotNull { line ->
        line.attribute()?.takeIf { it.name == name }?.value
    }

/** The first `a=<name>:<value>` value for [name], or null if absent (or the attribute has no value). */
public fun SdpSection.firstAttributeValue(name: String): String? = attributeValues(name).firstOrNull()

/** True if a property (flag) attribute `a=<name>` (no value) is present — e.g. `a=end-of-candidates`. */
public fun SdpSection.hasFlag(name: String): Boolean =
    lines.any { line ->
        val attr = line.attribute()
        attr != null && attr.name == name && attr.value == null
    }

/** The ICE username fragment (`a=ice-ufrag`, RFC 8839 §5.4), or null. */
public fun SdpSection.iceUfrag(): String? = firstAttributeValue("ice-ufrag")

/** The ICE password (`a=ice-pwd`, RFC 8839 §5.4), or null. */
public fun SdpSection.icePwd(): String? = firstAttributeValue("ice-pwd")

/** The negotiated DTLS role (`a=setup`, RFC 8842), or null if absent/unrecognized. */
public fun SdpSection.setup(): SetupRole? = firstAttributeValue("setup")?.let(SetupRole::fromToken)

/**
 * Every `a=fingerprint` (RFC 8122 §5) in this section, each split into hash-function + value; an
 * entry that is not two space-separated fields is dropped (null-on-malformed, applied per line).
 */
public fun SdpSection.fingerprints(): List<Fingerprint> =
    attributeValues("fingerprint").mapNotNull { v ->
        val sp = v.indexOf(' ')
        if (sp <= 0 || sp == v.length - 1) null else Fingerprint(v.substring(0, sp), v.substring(sp + 1))
    }
