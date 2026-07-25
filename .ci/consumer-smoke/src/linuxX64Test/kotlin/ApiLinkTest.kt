package consumer.smoke

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * The Kotlin/Native **link gate**: reaching [Smoke] pulls the published `webrtc-testsuite` klib (and its
 * transitive `:webrtc`/`:webrtc-*` klibs) into a linked K/N test binary, so a klib left out of the
 * publish surfaces as a link-time failure here rather than slipping past dependency resolution. Runs no
 * network — its purpose is to make the published surface reachable for the native linker.
 */
class ApiLinkTest {
    @Test
    fun publishedSurfaceLinksOnNative() {
        assertEquals(5, Smoke.natTypes().size, "the published NatType taxonomy has five variants")
    }

    /**
     * The same gate for `com.ditchoom:webrtc` itself: touching the consumer API forces its klib (and the
     * `webrtc-sctp` klib behind `DataChannelConfig`) into the linked binary, so a coordinate that
     * resolves on the JVM but published no native variant fails here instead of in a consumer's build.
     */
    @Test
    fun publishedConsumerApiLinksOnNative() {
        assertEquals(2, Smoke.iceServers().size)
        assertEquals(2, Smoke.dataChannelConfigs().size)
        assertEquals("control", Smoke.dataChannelConfigs().first().label)
        assertNotNull(Smoke.peerConnectionConfig())
    }
}
