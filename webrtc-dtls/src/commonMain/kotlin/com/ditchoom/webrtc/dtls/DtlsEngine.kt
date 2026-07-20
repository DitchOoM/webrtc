package com.ditchoom.webrtc.dtls

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.ReadBuffer
import com.ditchoom.buffer.managed
import com.ditchoom.webrtc.dtls.crypto.SelfSignedCertificate
import com.ditchoom.webrtc.dtls.handshake.Dtls12Handshake
import com.ditchoom.webrtc.dtls.handshake.Dtls13Handshake
import com.ditchoom.webrtc.dtls.handshake.DtlsHandshakeFsm
import com.ditchoom.webrtc.dtls.wire.ClientHello
import com.ditchoom.webrtc.dtls.wire.ContentType
import com.ditchoom.webrtc.dtls.wire.DtlsRecord
import com.ditchoom.webrtc.dtls.wire.ExtensionType
import com.ditchoom.webrtc.dtls.wire.HandshakeFragment
import com.ditchoom.webrtc.dtls.wire.HandshakeType
import com.ditchoom.webrtc.dtls.wire.Tls13Bodies
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Negotiated DTLS version (RFC 6347 / 9147). [Unknown] covers a value we don't model. */
public enum class DtlsVersion { Dtls12, Dtls13, Unknown }

/**
 * Construction parameters for a [DtlsEngine], all seams with production defaults (directive #2/#6).
 * The one un-seamed source of entropy is BoringSSL's internal RNG shaping the ClientHello / keys —
 * the documented ±1-datagram Tier-B drift residue (RFC §5.1), not a Kotlin `Random.Default`.
 *
 * @param bufferFactory pooled buffers for the record I/O edge. Pass a **pooled native** factory in
 *   production: a native-backed buffer hands BoringSSL its own address (no staging copy), while a
 *   GC-heap buffer (the `managed()` default) is staged through an internal native scratch.
 * @param enableDtls13 negotiate up to DTLS 1.3; min always stays 1.2 (§11.3). **On by default**: both
 *   major browser engines now ship DTLS 1.3 for WebRTC (Firefox in Release, Chrome/BoringSSL on by
 *   default since the libwebrtc flip in 2025), and BoringSSL itself defaults to it. Version negotiation
 *   falls back to 1.2 for peers that lack 1.3 — notably Pion, whose released v3 is still 1.2-only. Set
 *   this false to pin 1.2 (e.g. to reproduce a 1.2-only interop lane).
 * @param maxDatagramSize the largest record datagram we read out of the backend in one step.
 * @param handshakeTimeout how long a driver waits for the handshake before failing it with
 *   [DtlsFailureReason.HandshakeTimeout]. DTLS itself retransmits a lost flight with exponential
 *   backoff and never gives up, so without a budget a peer that goes silent mid-handshake would hang
 *   the session forever; this is the liveness bound (RFC §5.3 #5: reach a state or a typed failure,
 *   never hang). Unused by the sans-io engine, which has no clock of its own — the driver enforces it.
 * @param random the injected entropy seam for the parts of the handshake the pure-Kotlin engine shapes
 *   itself — the `ClientHello`/`ServerHello` 32-byte `Random`, the cert serial, DTLS cookies. Seedable,
 *   so a fixture replays a handshake deterministically. (The ephemeral ECDHE keypair + the cert keypair
 *   still come from buffer-crypto's own CSPRNG, which is not seedable — the documented ±1-datagram
 *   Tier-B drift residue, not a `Random.Default`.)
 */
public class DtlsConfig(
    public val bufferFactory: BufferFactory = BufferFactory.managed(),
    public val enableDtls13: Boolean = true,
    public val maxDatagramSize: Int = 1500,
    public val handshakeTimeout: Duration = 30.seconds,
    @Suppress("UnseamedEntropy") public val random: Random = Random.Default,
)

/**
 * The observable state of a [DtlsEngine] — a sealed hierarchy where each state carries exactly the
 * data valid in it (DESIGN §4: no boolean/nullable soup). [Handshaking] → [Established] | [Failed];
 * [Closed] after an orderly shutdown. Illegal combinations are unrepresentable.
 */
public sealed interface DtlsState {
    /** The handshake is in flight; records are still being exchanged. */
    public object Handshaking : DtlsState

    /**
     * The handshake completed. [peerFingerprint] is the SHA-256 of the peer's certificate — the
     * caller verifies it against the SDP-advertised `a=fingerprint` (webrtc root), since the engine
     * is signaling-agnostic.
     */
    public class Established(
        public val peerFingerprint: CertificateFingerprint,
        public val negotiatedVersion: DtlsVersion,
    ) : DtlsState

    /** An orderly close_notify was completed in both directions (or begun locally). */
    public object Closed : DtlsState

    /** The transport failed with a typed [reason]; terminal. */
    public class Failed(
        public val reason: DtlsFailureReason,
    ) : DtlsState
}

/**
 * The result of one caller-clocked step: DTLS records to put on the wire ([records]), any decrypted
 * application data produced ([applicationData]), and the resulting [state]. Buffers are owned by the
 * caller after return.
 */
public class DtlsStep(
    public val records: List<ReadBuffer>,
    public val applicationData: List<ReadBuffer>,
    public val state: DtlsState,
)

/**
 * A caller-clocked, sans-io DTLS endpoint (RFC §5.1) — the swap that replaces the plaintext seam at
 * `DtlsTransportFactory.secure(...)`. There is no dispatcher, no `Clock.System`, no I/O and no
 * coroutine inside it: the driver (webrtc root) owns the socket and the clock, feeds this engine
 * inbound records + a virtual `nowMicros`, and puts the returned records on the wire. The DTLS
 * retransmission timers are driven off that injected `nowMicros`, so a lost-flight recovery replays
 * under `runTest` virtual time.
 *
 * This is a **pure-Kotlin** implementation (W4b): a single `commonMain` class over buffer-crypto's
 * primitives, running on every non-browser target (JVM/Android/Apple/Linux) with no native dependency.
 * It negotiates **DTLS 1.3** (`TLS_AES_128_GCM_SHA256`, RFC 9147) by default and falls back to **DTLS 1.2**
 * (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`) — a client picks its version FSM from
 * [DtlsConfig.enableDtls13], a server selects by peeking the peer's ClientHello `supported_versions`.
 * Browsers never construct it — there `peerConnectionSupport()` delegates to the platform
 * `RTCPeerConnection`. The BoringSSL backend that seeded this seam now lives only in `linuxTest` as a
 * differential-testing oracle (proving byte-level interop in both DTLS 1.2 and 1.3).
 *
 * `nowMicros` is epoch-microseconds from the driver's injected clock; the same value must be passed to
 * every call within one logical instant. [nextTimeoutMicros] returns the absolute epoch-micros at which
 * [onTimeout] must next be called (null = no timer armed).
 *
 * **Identity at construction, role at [start].** The engine generates its self-signed certificate when
 * it is constructed, so [localFingerprint] is readable immediately — which is what the session layer
 * needs, because the `a=fingerprint` goes into the *offer*, long before `a=setup` negotiates who is
 * client (RFC 8842). The role is therefore not a constructor parameter: an endpoint has an identity
 * from birth and learns its role from signaling later, exactly as WebRTC models it.
 *
 * Lifecycle: construct → [start] → feed [onDatagram]/[onTimeout] until [DtlsState.Established] → [send]
 * / receive application data → [beginClose] → [close]. Not thread-safe; confine to one driver coroutine.
 */
public class DtlsEngine(
    private val config: DtlsConfig,
) {
    // Generated once, at construction, so [localFingerprint] is readable before the role is negotiated.
    // Owned here (not by the handshake) and freed in [close]; the handshake reuses it per attempt.
    private val certificate: SelfSignedCertificate =
        SelfSignedCertificate.generate(config.bufferFactory, config.random)

    private var handshake: DtlsHandshakeFsm? = null
    private var role: DtlsRole? = null
    private var closed = false

    /**
     * Our own certificate's SHA-256 fingerprint — the `a=fingerprint` we advertise. Readable from
     * construction, before [start], so it can be put in the offer (see the class note on role).
     */
    public val localFingerprint: CertificateFingerprint get() = certificate.fingerprint

    /**
     * Adopt [role] (from the negotiated `a=setup`) and begin the handshake. A [DtlsRole.Client] sends the
     * ClientHello immediately (its version FSM chosen from [DtlsConfig.enableDtls13]) and this returns its
     * first flight. A [DtlsRole.Server] defers: it selects 1.3 or 1.2 by inspecting the peer's ClientHello
     * `supported_versions` on the first [onDatagram] (real version negotiation), so this returns no records.
     * Call exactly once, before any [onDatagram].
     */
    public fun start(
        role: DtlsRole,
        nowMicros: Long,
    ): DtlsStep {
        check(this.role == null) { "DtlsEngine.start(role, now) called twice" }
        this.role = role
        return when (role) {
            DtlsRole.Client -> newHandshake(useDtls13 = config.enableDtls13, role).also { handshake = it }.start(nowMicros)
            DtlsRole.Server -> DtlsStep(emptyList(), emptyList(), DtlsState.Handshaking) // FSM chosen on the ClientHello
        }
    }

    /** Feed one inbound DTLS record datagram; drives the handshake or decrypts application data. */
    public fun onDatagram(
        record: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep {
        val fsm =
            handshake ?: run {
                // Deferred server: pick the version from the ClientHello, then create + start + feed the FSM.
                val serverRole = checkNotNull(role) { "DtlsEngine.start(role, now) must be called before driving the engine" }
                val useDtls13 = config.enableDtls13 && clientHelloOffersDtls13(record)
                newHandshake(useDtls13, serverRole).also {
                    handshake = it
                    it.start(nowMicros) // server start emits no records; it waits for this ClientHello
                }
            }
        return fsm.onDatagram(record, nowMicros)
    }

    /** Fire an expired DTLS timer (retransmits the current flight). */
    public fun onTimeout(nowMicros: Long): DtlsStep =
        handshake?.onTimeout(nowMicros) ?: DtlsStep(emptyList(), emptyList(), DtlsState.Handshaking)

    /** Encrypt and enqueue application data once [DtlsState.Established]. */
    public fun send(
        applicationData: ReadBuffer,
        nowMicros: Long,
    ): DtlsStep =
        handshake?.sealApplicationData(applicationData, nowMicros)
            ?: DtlsStep(emptyList(), emptyList(), DtlsState.Handshaking)

    /** Begin an orderly close (queues a close_notify to send). */
    public fun beginClose(nowMicros: Long): DtlsStep =
        handshake?.beginClose(nowMicros) ?: DtlsStep(emptyList(), emptyList(), DtlsState.Closed)

    /** Absolute epoch-micros at which [onTimeout] must next run, or null if no timer is armed. */
    public fun nextTimeoutMicros(nowMicros: Long): Long? = handshake?.nextTimeoutMicros(nowMicros)

    /** Free the certificate identity and any handshake key material. Idempotent. */
    public fun close() {
        if (closed) return
        closed = true
        handshake?.close()
        certificate.close()
    }

    private fun newHandshake(
        useDtls13: Boolean,
        role: DtlsRole,
    ): DtlsHandshakeFsm =
        if (useDtls13) {
            Dtls13Handshake(config, role, certificate)
        } else {
            Dtls12Handshake(config, role, certificate)
        }

    /**
     * True if [datagram] carries a complete ClientHello offering DTLS 1.3 (a `supported_versions` listing
     * `0xFEFC`, the `TLS_AES_128_GCM_SHA256` suite, and a P-256 `key_share`). WebRTC ClientHellos are small
     * and unfragmented, so the server can decide the version from the first datagram; anything it cannot
     * parse as a 1.3-capable ClientHello falls back to the 1.2 FSM.
     */
    private fun clientHelloOffersDtls13(datagram: ReadBuffer): Boolean {
        val records = DtlsRecord.decodeAll(datagram) ?: return false
        for (record in records) {
            if (record.contentType.value != ContentType.Handshake.value) continue
            val fragments = HandshakeFragment.decodeAll(record.fragment) ?: continue
            for (fragment in fragments) {
                if (fragment.msgType.value != HandshakeType.ClientHello.value) continue
                if (fragment.fragmentOffset != 0 || fragment.fragmentLength != fragment.length) continue
                val ch = ClientHello.parse(fragment.fragmentBody) ?: continue
                val offersVersion =
                    ch.extensions
                        .firstOrNull { it.type.value == ExtensionType.SupportedVersions.value }
                        ?.let { Tls13Bodies.offersDtls13(it.body) } ?: false
                val offersKeyShare =
                    ch.extensions
                        .firstOrNull { it.type.value == ExtensionType.KeyShare.value }
                        ?.let { Tls13Bodies.parseKeyShareClientHello(it.body) != null } ?: false
                if (offersVersion && offersKeyShare) return true
            }
        }
        return false
    }
}
