package com.ditchoom.webrtc.harness

import kotlin.jvm.JvmInline

// These are the harness's pure type wrappers — zero-cost `@JvmInline value class`es that make illegal
// states unrepresentable at the signaling/diagnostics boundaries. They live in the REAL `commonMain`
// (common-metadata) source set rather than the per-target `commonSharedMain` srcDir: `@JvmInline` is an
// `@OptionalExpectation` annotation and is only legal in COMMON module sources, whereas the shared srcDir is
// compiled per-target as a leaf source set (so it can see its own KSP-generated codecs — see build.gradle.kts).
// These wrappers reference no generated code, so they belong in commonMain, where value classes are valid on
// every target (they are `internal`, so the per-target shared code + tests still see them).

/**
 * A record's index within its `Slot` (monotonic per slot). Wraps the wire uint so a raw loop counter can
 * never be passed where a record id is meant, and vice-versa.
 */
@JvmInline
internal value class RecordId(
    val value: Int,
)

/**
 * A JSEP session description as its SDP text — wrapped so it can't be confused with a candidate line or a
 * raw log string at the diagnostics boundary (SDP is a serialized document, not an identifier).
 */
@JvmInline
internal value class Sdp(
    val text: String,
)

/** One trickled ICE candidate line (RFC 8839 §5.1), wrapped for the same reason. */
@JvmInline
internal value class CandidateLine(
    val text: String,
)
