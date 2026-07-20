package consumer.smoke

import kotlin.test.Test
import kotlin.test.assertEquals

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
}
