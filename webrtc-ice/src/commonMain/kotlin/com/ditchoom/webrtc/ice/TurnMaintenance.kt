package com.ditchoom.webrtc.ice

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * How a [TurnAllocation] keeps itself alive once it exists (RFC 8656 §8 Refresh, §9 CreatePermission).
 *
 * A TURN allocation and its permissions both expire on the **server's** clock, and they expire
 * differently: the permission goes first and silently (outbound Send indications keep working, inbound
 * Data indications stop, so the session sees one-way loss and blames ICE consent 30 s later), and the
 * allocation goes next and takes the relayed transport address with it. coturn's defaults are 600 s and
 * 300 s — both shorter than an ordinary call — so for a peer behind a symmetric NAT, where the relay is
 * the only path, "we never refresh" means "every long call dies".
 *
 * This is a sealed policy rather than a `refresh: Boolean` because [None] is not a configuration anyone
 * should want in production: it exists so a fixture can prove the refresh is load-bearing (turn it off
 * and the same relay demonstrably dies), which is the only way a "the relay survived" assertion is worth
 * anything.
 */
public sealed interface TurnMaintenance {
    /**
     * Refresh the allocation and re-install its permissions ahead of expiry — the production default.
     *
     * @param refreshAt the fraction of the **granted** LIFETIME (the Allocate/Refresh response's LIFETIME
     *   attribute, not a guess) at which to send the next Refresh. The margin that remains is what absorbs
     *   a lost request and its retries — see [retryAt], which is what actually spends it.
     * @param permissionLifetime the server's permission lifetime. RFC 8656 §9 fixes it at 300 s and gives
     *   the client no attribute to read it from, so unlike [refreshAt] this is a stated assumption; it is
     *   a parameter so a fixture (or a server that documents something shorter) can say otherwise.
     * @param permissionRefreshAt the fraction of [permissionLifetime] at which to re-install every address
     *   in the permission set — *every* address, not just the one a datagram is currently headed for.
     * @param retryAt the fraction of the relevant lifetime to wait before re-attempting a round that went
     *   **unanswered** — distinct from a round the server *refused*, which no retry can recover. Small
     *   enough that several attempts fit inside the margin `refreshAt` leaves.
     */
    public data class Renewing(
        val refreshAt: Double = DEFAULT_REFRESH_FRACTION,
        val permissionLifetime: Duration = DEFAULT_PERMISSION_LIFETIME,
        val permissionRefreshAt: Double = DEFAULT_REFRESH_FRACTION,
        val retryAt: Double = DEFAULT_RETRY_FRACTION,
    ) : TurnMaintenance {
        init {
            require(refreshAt > 0.0 && refreshAt <= 1.0) { "refreshAt must be a fraction in (0, 1], was $refreshAt" }
            require(permissionRefreshAt > 0.0 && permissionRefreshAt <= 1.0) {
                "permissionRefreshAt must be a fraction in (0, 1], was $permissionRefreshAt"
            }
            require(permissionLifetime > Duration.ZERO) { "permissionLifetime must be positive, was $permissionLifetime" }
            require(retryAt > 0.0 && retryAt <= 1.0) { "retryAt must be a fraction in (0, 1], was $retryAt" }
        }

        // Floored so a pathologically short lifetime cannot turn the maintenance loop into a spin.
        internal fun refreshDelayFor(granted: Duration): Duration = (granted * refreshAt).coerceAtLeast(MIN_INTERVAL)

        internal val permissionRefreshDelay: Duration get() = (permissionLifetime * permissionRefreshAt).coerceAtLeast(MIN_INTERVAL)

        /** How long to wait before re-sending a Refresh that nobody answered. */
        internal fun refreshRetryDelayFor(granted: Duration): Duration = (granted * retryAt).coerceAtLeast(MIN_INTERVAL)

        /** How long to wait before re-sending a CreatePermission that nobody answered. */
        internal val permissionRetryDelay: Duration get() = (permissionLifetime * retryAt).coerceAtLeast(MIN_INTERVAL)
    }

    /**
     * Never Refresh and never re-install a permission: the allocation lives exactly as long as the server's
     * LIFETIME and its permissions exactly 300 s. Deallocation on close still happens — that is a
     * correctness property of shutting down, not of staying alive.
     *
     * Present for the anti-vacuity half of `TurnAllocationRefreshTest`, not as a supported deployment.
     */
    public data object None : TurnMaintenance
}

/** Refresh at three quarters of the granted lifetime, leaving a quarter of it as retry margin. */
private const val DEFAULT_REFRESH_FRACTION = 0.75

/** Retry an unanswered round at a twentieth of the lifetime — five attempts inside the quarter above. */
private const val DEFAULT_RETRY_FRACTION = 0.05

/** RFC 8656 §9: a permission lasts 300 s, and the protocol offers no way to learn a different value. */
private val DEFAULT_PERMISSION_LIFETIME: Duration = 300.seconds

private val MIN_INTERVAL: Duration = 1.milliseconds
