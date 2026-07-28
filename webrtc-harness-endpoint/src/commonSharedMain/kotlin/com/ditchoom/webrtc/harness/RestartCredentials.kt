package com.ditchoom.webrtc.harness

import com.ditchoom.webrtc.sdp.Fingerprint
import com.ditchoom.webrtc.sdp.SdpParseResult
import com.ditchoom.webrtc.sdp.SdpSection
import com.ditchoom.webrtc.sdp.SessionDescription
import com.ditchoom.webrtc.sdp.fingerprints
import com.ditchoom.webrtc.sdp.icePwd
import com.ditchoom.webrtc.sdp.iceUfrag

/**
 * Reading an ICE restart off the peer's OWN answer (s8, issue #71).
 *
 * The s8 phase can already see that the session reconverged onto a new pair, but reconvergence alone does
 * not say the *peer* restarted ICE — a pair can move for other reasons, and against a third-party stack
 * "it kept working" is exactly the observation that hides a peer doing the wrong thing. What the peer's
 * re-answer says, and nothing else can, is whether it obeyed the two halves RFC 8842 §5.5 separates:
 *
 *  * the **ICE credentials** (`a=ice-ufrag` / `a=ice-pwd`, RFC 8839 §5.4) MUST both be replaced — that IS
 *    the restart (RFC 8445 §9). A peer that re-answers with the credentials it already had has answered a
 *    restart offer without restarting, and every check we send to it belongs to the generation it just
 *    superseded;
 *  * the **DTLS fingerprint** (RFC 8122 §5) MUST NOT change — an unchanged fingerprint is precisely what
 *    tells both sides to keep the existing DTLS association (and the SCTP association, and every open data
 *    channel) rather than build a new one. A peer whose fingerprint moves has performed a reconnect wearing
 *    a restart's clothes, and s8's "nothing closed" assertions on OUR side would not necessarily notice.
 *
 * This is the half of the proof only the answer can give, which is why it lives here rather than in the
 * connection state the phase otherwise reads.
 */

/**
 * What one round's SDP carries of the three values above. Sealed rather than three nullable fields: a
 * comparison is only meaningful between two [Present] rounds, and the type is what makes the other two
 * outcomes impossible to accidentally compare instead of report.
 */
internal sealed interface RoundCredentials {
    /** All three present — the only shape a restart can actually be judged from. */
    data class Present(
        val ufrag: String,
        val pwd: String,
        val fingerprint: Fingerprint,
    ) : RoundCredentials

    /** The SDP parsed but omitted [attribute]. There is nothing to compare, and the omission is the finding. */
    data class Missing(val attribute: String) : RoundCredentials

    /** The SDP did not parse at all. */
    data object Unparseable : RoundCredentials
}

/**
 * Read [sdp]'s ICE credentials and DTLS fingerprint.
 *
 * JSEP (RFC 8829 §5.2.1) lets all three sit at session level as a default or be overridden per media
 * section, so the media section wins and the session block is the fallback. Every peer this harness meets
 * — ours, Pion, werift, Chrome, Firefox, WebKit — writes them per-m-section, but a session-level-only peer
 * must read as [RoundCredentials.Present] rather than look like it omitted them.
 */
internal fun credentialsOf(sdp: String): RoundCredentials {
    val description =
        when (val parsed = SessionDescription.parseText(sdp)) {
            is SdpParseResult.Success -> parsed.description
            is SdpParseResult.Reject -> return RoundCredentials.Unparseable
        }
    val media = description.mediaDescriptions.firstOrNull()
    fun <T> read(from: SdpSection.() -> T?): T? = media?.from() ?: description.from()

    val ufrag = read { iceUfrag() } ?: return RoundCredentials.Missing("a=ice-ufrag")
    val pwd = read { icePwd() } ?: return RoundCredentials.Missing("a=ice-pwd")
    val fingerprint = read { fingerprints().firstOrNull() } ?: return RoundCredentials.Missing("a=fingerprint")
    return RoundCredentials.Present(ufrag, pwd, fingerprint)
}

/**
 * The ways a peer's ICE credential pair can FALL SHORT of RFC 8445 §9's "replace both". "Both replaced" is
 * deliberately absent: that outcome is [ReanswerVerdict.Restarted], so there is no way to build a
 * [ReanswerVerdict.NotRestarted] that describes a peer which did restart.
 */
internal enum class CredentialGap {
    Neither,
    UfragOnly,
    PwdOnly,
}

/**
 * What the peer's answer to the restart round proves, given its answer to the initial round. Sealed, and
 * carrying the values it judged, so the s8 phase discriminates on the type and renders the sentence from
 * [detail] — a string is never the discriminant here (standing directive #3).
 */
internal sealed interface ReanswerVerdict {
    /** RFC 8445 §9 + RFC 8842 §5.5: both credentials replaced, the DTLS identity kept. The only pass. */
    data class Restarted(val credentials: RoundCredentials.Present) : ReanswerVerdict

    /** The fingerprint moved: a NEW DTLS association, so this was a reconnect and not a restart. */
    data class TransportRebuilt(val before: Fingerprint, val after: Fingerprint) : ReanswerVerdict

    /** The credentials did not both change: the peer answered a restart offer without restarting. */
    data class NotRestarted(val gap: CredentialGap) : ReanswerVerdict

    /** One of the two rounds could not be read, so nothing about the peer is claimed either way. */
    data class Unreadable(val initial: RoundCredentials, val restarted: RoundCredentials) : ReanswerVerdict
}

/**
 * Judge the peer's [restarted] answer against its [initial] one.
 *
 * Order is deliberate and is itself a statement: a moved fingerprint is reported ahead of unchanged
 * credentials because it subsumes them — a peer that rebuilt its DTLS identity has abandoned the
 * association whatever it did with its ICE credentials, and naming the credential change instead would
 * describe the smaller half of what went wrong.
 */
internal fun judgeReanswer(
    initial: RoundCredentials,
    restarted: RoundCredentials,
): ReanswerVerdict {
    if (initial !is RoundCredentials.Present || restarted !is RoundCredentials.Present) {
        return ReanswerVerdict.Unreadable(initial, restarted)
    }
    if (!initial.fingerprint.sameIdentityAs(restarted.fingerprint)) {
        return ReanswerVerdict.TransportRebuilt(initial.fingerprint, restarted.fingerprint)
    }
    val ufragReplaced = initial.ufrag != restarted.ufrag
    val pwdReplaced = initial.pwd != restarted.pwd
    return when {
        ufragReplaced && pwdReplaced -> ReanswerVerdict.Restarted(restarted)
        ufragReplaced -> ReanswerVerdict.NotRestarted(CredentialGap.UfragOnly)
        pwdReplaced -> ReanswerVerdict.NotRestarted(CredentialGap.PwdOnly)
        else -> ReanswerVerdict.NotRestarted(CredentialGap.Neither)
    }
}

/**
 * Case-insensitive equality of the SDP fingerprint pair. RFC 8122 §5's hash-function token and hex digits
 * are both case-insensitive, so a peer that rendered the same certificate differently between two rounds
 * must not read as a rebuilt transport — the only difference that matters here is a different certificate.
 */
private fun Fingerprint.sameIdentityAs(other: Fingerprint): Boolean =
    hashFunction.equals(other.hashFunction, ignoreCase = true) && value.equals(other.value, ignoreCase = true)

/** The sentence s8 reports for this verdict. A diagnostic rendered FROM the type, never a substitute for it. */
internal fun ReanswerVerdict.detail(): String =
    when (this) {
        is ReanswerVerdict.Restarted ->
            "the peer re-answered with fresh ICE credentials (ufrag ${credentials.ufrag}) and the same DTLS " +
                "fingerprint, so it restarted ICE on the existing association (RFC 8445 §9, RFC 8842 §5.5)"
        is ReanswerVerdict.TransportRebuilt ->
            "the peer's re-answer changed its DTLS fingerprint (${before.hashFunction} ${before.value} → " +
                "${after.hashFunction} ${after.value}) — it built a NEW association instead of restarting ICE " +
                "on the existing one, which RFC 8842 §5.5 reserves for a peer that wants exactly that"
        is ReanswerVerdict.NotRestarted ->
            when (gap) {
                CredentialGap.Neither ->
                    "the peer re-answered our restart offer with the ICE credentials it already had — it " +
                        "never restarted, so our checks are aimed at a generation it has superseded"
                CredentialGap.UfragOnly ->
                    "the peer's re-answer changed a=ice-ufrag but kept a=ice-pwd — RFC 8445 §9 replaces both, " +
                        "and a half-replaced credential pair authenticates neither generation"
                CredentialGap.PwdOnly ->
                    "the peer's re-answer changed a=ice-pwd but kept a=ice-ufrag — RFC 8445 §9 replaces both, " +
                        "and a half-replaced credential pair authenticates neither generation"
            }
        is ReanswerVerdict.Unreadable ->
            "could not read the ICE credentials off both rounds of the peer's answers (round 0: $initial, " +
                "restart round: $restarted), so what the peer did with its ICE generation is unknown"
    }
