package com.ditchoom.webrtc.ice

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The ICE-server URL grammar (RFC 7064 `stun:`, RFC 7065 `turn:`) and — the point of the type — every
 * shape we decline, declined *by reason* rather than dropped. Before issue #136 nothing parsed these at
 * all on the native path, so a mis-typed or unsupported URL was indistinguishable from a server that
 * simply never answered.
 */
class IceServerUrlTest {
    @Test
    fun stunDefaultsToPort3478() {
        assertEquals(IceServerUrl.Stun("stun.example.org", 3478), parseIceServerUrl("stun:stun.example.org"))
    }

    @Test
    fun explicitPortWins() {
        assertEquals(IceServerUrl.Stun("stun.example.org", 19302), parseIceServerUrl("stun:stun.example.org:19302"))
        assertEquals(IceServerUrl.Turn("turn.example.org", 3479), parseIceServerUrl("turn:turn.example.org:3479"))
    }

    @Test
    fun turnAcceptsTheUdpTransportItAlreadySpeaks() {
        assertEquals(IceServerUrl.Turn("turn.example.org", 3478), parseIceServerUrl("turn:turn.example.org?transport=udp"))
        // The query may follow the port as well as the host — it is split off before either is read.
        assertEquals(IceServerUrl.Turn("turn.example.org", 3479), parseIceServerUrl("turn:turn.example.org:3479?transport=udp"))
    }

    @Test
    fun schemeAndQueryAreCaseInsensitive() {
        assertEquals(IceServerUrl.Turn("turn.example.org", 3478), parseIceServerUrl("TURN:turn.example.org?TRANSPORT=UDP"))
    }

    /** The host is not lowercased with them: a DNS name is case-insensitive, but an mDNS label need not be. */
    @Test
    fun hostKeepsItsCase() {
        assertEquals(IceServerUrl.Stun("Stun.Example.ORG", 3478), parseIceServerUrl("stun:Stun.Example.ORG"))
    }

    @Test
    fun bracketedIpv6LiteralKeepsItsColons() {
        assertEquals(IceServerUrl.Stun("2001:db8::1", 3478), parseIceServerUrl("stun:[2001:db8::1]"))
        assertEquals(IceServerUrl.Turn("2001:db8::1", 3479), parseIceServerUrl("turn:[2001:db8::1]:3479"))
    }

    @Test
    fun tlsSchemesAreRefusedByReasonRatherThanDropped() {
        for (url in listOf("turns:turn.example.org", "stuns:stun.example.org", "turns:turn.example.org:5349")) {
            val parsed = assertIs<IceServerUrl.Unsupported>(parseIceServerUrl(url), "expected $url to be refused")
            assertEquals(IceServerUrlRejection.TlsTransportUnsupported, parsed.reason)
            assertEquals(url, parsed.url, "the refusal carries the URL back, so a diagnostic can name it")
        }
    }

    @Test
    fun tcpTransportIsRefusedByItsOwnReason() {
        val parsed = assertIs<IceServerUrl.Unsupported>(parseIceServerUrl("turn:turn.example.org?transport=tcp"))
        assertEquals(IceServerUrlRejection.TcpTransportUnsupported, parsed.reason)
    }

    @Test
    fun unknownSchemeIsNamed() {
        val parsed = assertIs<IceServerUrl.Unsupported>(parseIceServerUrl("https:example.org"))
        assertEquals(IceServerUrlRejection.UnknownScheme("https"), parsed.reason)
    }

    @Test
    fun unknownQueryIsNamed() {
        val parsed = assertIs<IceServerUrl.Unsupported>(parseIceServerUrl("turn:turn.example.org?ttl=60"))
        assertEquals(IceServerUrlRejection.UnknownQuery("ttl=60"), parsed.reason)
    }

    @Test
    fun malformedAuthorityIsRefused() {
        for (url in listOf("stun:", "stun::3478", "stun:[2001:db8::1", "stun:[]:3478", "stun:[2001:db8::1]x")) {
            val parsed = assertIs<IceServerUrl.Unsupported>(parseIceServerUrl(url), "expected $url to be refused")
            assertEquals(IceServerUrlRejection.MalformedAuthority, parsed.reason, "for $url")
        }
    }

    /**
     * `toIntOrNull` accepts a leading sign, so a signed port would otherwise parse and then bind
     * something nobody asked for. Range and digits are both checked.
     */
    @Test
    fun portIsRejectedWhenSignedEmptyNonNumericOrOutOfRange() {
        for (text in listOf("+80", "-1", "", "80a", "0", "65536", "99999")) {
            val url = "stun:stun.example.org:$text"
            val parsed = assertIs<IceServerUrl.Unsupported>(parseIceServerUrl(url), "expected port '$text' to be refused")
            assertEquals(IceServerUrlRejection.InvalidPort(text), parsed.reason, "for port '$text'")
        }
        assertEquals(IceServerUrl.Stun("stun.example.org", 65535), parseIceServerUrl("stun:stun.example.org:65535"))
    }

    @Test
    fun parseUrlsKeepsOrderAndRefusalsTogether() {
        val server = IceServer(listOf("stun:stun.example.org", "turns:turn.example.org", "turn:turn.example.org:3479"))
        val parsed = server.parseUrls()
        assertEquals(3, parsed.size)
        assertEquals(IceServerUrl.Stun("stun.example.org", 3478), parsed[0])
        assertIs<IceServerUrl.Unsupported>(parsed[1])
        assertEquals(IceServerUrl.Turn("turn.example.org", 3479), parsed[2])
    }
}
