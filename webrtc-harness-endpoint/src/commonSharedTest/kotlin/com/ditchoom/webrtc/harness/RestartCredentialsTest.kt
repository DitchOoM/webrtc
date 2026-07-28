package com.ditchoom.webrtc.harness

import com.ditchoom.webrtc.sdp.Fingerprint
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The s8 phase's reading of the PEER's re-answer (issue #71): given the peer's answer to the initial round
 * and its answer to the ICE-restart round, did it actually restart?
 *
 * This is the deterministic sibling of the `restart-<family>` interop lanes. Those lanes run the judgement
 * against real Pion / werift / Chrome / Firefox / WebKit answers over real NAT kernels; this pins what each
 * possible answer MEANS, including the two shapes no cooperating peer will ever produce for us on demand —
 * a peer that re-answers without new credentials, and one that hands back a different certificate.
 */
class RestartCredentialsTest {
    @Test
    fun a_restart_answer_replaces_both_credentials_and_keeps_the_fingerprint() {
        val verdict = judge(answer(ufrag = "aaaa", pwd = "pwd-one"), answer(ufrag = "bbbb", pwd = "pwd-two"))
        val restarted = assertIs<ReanswerVerdict.Restarted>(verdict)
        assertEquals("bbbb", restarted.credentials.ufrag)
        assertEquals("pwd-two", restarted.credentials.pwd)
    }

    @Test
    fun an_answer_that_reuses_its_credentials_never_restarted() {
        val verdict = judge(answer(ufrag = "aaaa", pwd = "pwd-one"), answer(ufrag = "aaaa", pwd = "pwd-one"))
        assertEquals(CredentialGap.Neither, assertIs<ReanswerVerdict.NotRestarted>(verdict).gap)
    }

    @Test
    fun replacing_only_the_ufrag_is_a_half_replaced_credential_pair() {
        val verdict = judge(answer(ufrag = "aaaa", pwd = "pwd-one"), answer(ufrag = "bbbb", pwd = "pwd-one"))
        assertEquals(CredentialGap.UfragOnly, assertIs<ReanswerVerdict.NotRestarted>(verdict).gap)
    }

    @Test
    fun replacing_only_the_pwd_is_a_half_replaced_credential_pair() {
        val verdict = judge(answer(ufrag = "aaaa", pwd = "pwd-one"), answer(ufrag = "aaaa", pwd = "pwd-two"))
        assertEquals(CredentialGap.PwdOnly, assertIs<ReanswerVerdict.NotRestarted>(verdict).gap)
    }

    /**
     * Pins the ORDER of the two checks, which is a decision and not an accident: a peer that replaced its
     * credentials AND its certificate did restart ICE, but on a new DTLS association — so the association
     * (and every data channel on it) is gone, and reporting the credential half would describe the smaller
     * failure. This is the shape that s8's own "nothing closed" assertions cannot see, because they read
     * OUR stream ids.
     */
    @Test
    fun a_moved_fingerprint_outranks_a_correct_credential_change() {
        val verdict =
            judge(
                answer(ufrag = "aaaa", pwd = "pwd-one", fingerprint = FINGERPRINT_A),
                answer(ufrag = "bbbb", pwd = "pwd-two", fingerprint = FINGERPRINT_B),
            )
        val rebuilt = assertIs<ReanswerVerdict.TransportRebuilt>(verdict)
        assertEquals(Fingerprint("sha-256", FINGERPRINT_A), rebuilt.before)
        assertEquals(Fingerprint("sha-256", FINGERPRINT_B), rebuilt.after)
    }

    /**
     * RFC 8122 §5's hash-function token and hex digits are both case-insensitive, so the SAME certificate
     * rendered differently across two rounds must not read as a rebuilt transport — that would fail the
     * lane for a peer that did everything right.
     */
    @Test
    fun the_same_certificate_in_different_case_is_not_a_rebuilt_transport() {
        val verdict =
            judge(
                answer(ufrag = "aaaa", pwd = "pwd-one", hash = "sha-256", fingerprint = FINGERPRINT_A),
                answer(ufrag = "bbbb", pwd = "pwd-two", hash = "SHA-256", fingerprint = FINGERPRINT_A.uppercase()),
            )
        assertIs<ReanswerVerdict.Restarted>(verdict)
    }

    /**
     * JSEP (RFC 8829 §5.2.1) allows the ICE/DTLS parameters at session level as a default. No peer this
     * harness meets writes them there today, but reading such an answer as "the peer omitted its
     * credentials" would fail the lane for a legal SDP.
     */
    @Test
    fun session_level_credentials_are_read_when_the_media_section_omits_them() {
        val credentials = credentialsOf(sessionLevelAnswer(ufrag = "aaaa", pwd = "pwd-one"))
        val present = assertIs<RoundCredentials.Present>(credentials)
        assertEquals("aaaa", present.ufrag)
        assertEquals("pwd-one", present.pwd)
        assertEquals(Fingerprint("sha-256", FINGERPRINT_A), present.fingerprint)
    }

    /** The media section wins over a session-level default — the override half of RFC 8829 §5.2.1. */
    @Test
    fun media_level_credentials_override_the_session_default() {
        val credentials = credentialsOf(sessionLevelAnswer(ufrag = "session", pwd = "session-pwd", mediaUfrag = "media"))
        assertEquals("media", assertIs<RoundCredentials.Present>(credentials).ufrag)
    }

    @Test
    fun an_answer_without_a_fingerprint_names_the_attribute_it_lacks() {
        val credentials = credentialsOf(answer(ufrag = "aaaa", pwd = "pwd-one", fingerprint = null))
        assertEquals("a=fingerprint", assertIs<RoundCredentials.Missing>(credentials).attribute)
    }

    /**
     * An unreadable round claims NOTHING about the peer — it is its own verdict, not a pass and not an
     * accusation. The phase still fails on it (an answer we cannot read is a finding), but the reason
     * says so rather than reporting a credential comparison that never happened.
     */
    @Test
    fun a_round_that_does_not_parse_is_unreadable_rather_than_a_claim_about_the_peer() {
        val verdict = judgeReanswer(RoundCredentials.Unparseable, credentialsOf(answer(ufrag = "b", pwd = "p")))
        val unreadable = assertIs<ReanswerVerdict.Unreadable>(verdict)
        assertEquals(RoundCredentials.Unparseable, unreadable.initial)
    }

    /** Every verdict renders a non-empty sentence — the phase reports one of these verbatim. */
    @Test
    fun every_verdict_renders_a_reason() {
        val verdicts =
            listOf(
                judge(answer(ufrag = "a", pwd = "p"), answer(ufrag = "b", pwd = "q")),
                judge(answer(ufrag = "a", pwd = "p"), answer(ufrag = "a", pwd = "p")),
                judge(answer(ufrag = "a", pwd = "p"), answer(ufrag = "b", pwd = "p")),
                judge(answer(ufrag = "a", pwd = "p"), answer(ufrag = "a", pwd = "q")),
                judge(answer(ufrag = "a", pwd = "p", fingerprint = FINGERPRINT_A), answer(ufrag = "b", pwd = "q", fingerprint = FINGERPRINT_B)),
                judgeReanswer(RoundCredentials.Unparseable, RoundCredentials.Missing("a=ice-pwd")),
            )
        for (verdict in verdicts) assertTrue(verdict.detail().isNotBlank(), "no reason rendered for $verdict")
    }

    // ── fixtures ──

    private fun judge(
        initial: String,
        restarted: String,
    ): ReanswerVerdict = judgeReanswer(credentialsOf(initial), credentialsOf(restarted))

    /**
     * A data-channel answer in the shape every peer in the matrix writes one: ICE credentials, fingerprint
     * and setup role in the media section (RFC 8829 §5.2.1's per-m-section override).
     */
    private fun answer(
        ufrag: String,
        pwd: String,
        fingerprint: String? = FINGERPRINT_A,
        hash: String = "sha-256",
    ): String =
        buildString {
            append(SESSION_PREAMBLE)
            append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
            append("c=IN IP4 0.0.0.0\r\n")
            append("a=ice-ufrag:$ufrag\r\n")
            append("a=ice-pwd:$pwd\r\n")
            append("a=ice-options:trickle\r\n")
            if (fingerprint != null) append("a=fingerprint:$hash $fingerprint\r\n")
            append("a=setup:active\r\n")
            append("a=mid:0\r\n")
            append("a=sctp-port:5000\r\n")
            append("a=max-message-size:262144\r\n")
        }

    /** The same answer with the ICE/DTLS parameters at SESSION level, optionally overridden per media section. */
    private fun sessionLevelAnswer(
        ufrag: String,
        pwd: String,
        mediaUfrag: String? = null,
    ): String =
        buildString {
            append(SESSION_PREAMBLE)
            append("a=ice-ufrag:$ufrag\r\n")
            append("a=ice-pwd:$pwd\r\n")
            append("a=fingerprint:sha-256 $FINGERPRINT_A\r\n")
            append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
            append("c=IN IP4 0.0.0.0\r\n")
            if (mediaUfrag != null) append("a=ice-ufrag:$mediaUfrag\r\n")
            append("a=setup:active\r\n")
            append("a=mid:0\r\n")
            append("a=sctp-port:5000\r\n")
        }

    private companion object {
        const val SESSION_PREAMBLE =
            "v=0\r\n" +
                "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" +
                "s=-\r\n" +
                "t=0 0\r\n" +
                "a=group:BUNDLE 0\r\n" +
                "a=msid-semantic: WMS\r\n"

        const val FINGERPRINT_A =
            "8f:1a:cb:2d:4e:60:71:82:93:a4:b5:c6:d7:e8:f9:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9:0a"
        const val FINGERPRINT_B =
            "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
    }
}
