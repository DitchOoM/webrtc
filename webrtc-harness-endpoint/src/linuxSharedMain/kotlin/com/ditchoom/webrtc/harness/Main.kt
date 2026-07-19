@file:OptIn(ExperimentalDatagramApi::class, ExperimentalTime::class)

package com.ditchoom.webrtc.harness

import com.ditchoom.buffer.BufferFactory
import com.ditchoom.buffer.deterministic
import com.ditchoom.buffer.flow.ExperimentalDatagramApi
import com.ditchoom.webrtc.BoringSslDtls
import com.ditchoom.webrtc.IceGatheringPolicy
import com.ditchoom.webrtc.NativePeerConnection
import com.ditchoom.webrtc.PeerConnectionConfig
import com.ditchoom.webrtc.PeerConnectionState
import com.ditchoom.webrtc.dtls.DtlsConfig
import com.ditchoom.webrtc.ice.IceConfig
import com.ditchoom.webrtc.sctp.association.SctpConfig
import com.ditchoom.webrtc.sctp.datachannel.DataChannelConfig
import com.ditchoom.webrtc.sdp.SdpType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.system.exitProcess
import kotlin.time.Clock
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * The L2/L3 interop **peer** — the "our side" endpoint the container harness runs behind real NAT kernels
 * (webrtc HANDOFF: the interop endpoint MUST be the native binary, the only one with a real DTLS
 * handshake). It composes the exact production stack — [NativePeerConnection] + [BoringSslDtls] over the
 * real-UDP [realUdpBinder] — gathers host/srflx(coturn)/relay(coturn TURN) candidates, exchanges
 * offer/answer/candidates over the UDP [UdpSignaling] rendezvous, and proves the data path with a
 * ping/pong over a data channel. Exit 0 = established + echoed; non-zero = a typed failure or timeout.
 */
fun main() {
    val cfg = HarnessConfig.fromEnv()
    println("[harness] role=${cfg.role} session=${cfg.session} policy=${cfg.icePolicy} local=${cfg.localIp}:${cfg.localPort}")
    val code = runBlocking { runPeer(cfg) }
    println("[harness] exit=$code")
    exitProcess(code)
}

private suspend fun runPeer(cfg: HarnessConfig): Int =
    coroutineScope {
        // One cancellable child scope for all long-lived machinery (pc, dtls, the gather/trickle/poll
        // loops) so the outer coroutineScope returns the moment the flow finishes and we cancel it.
        val bg = CoroutineScope(coroutineContext + Job())

        // Driver edge: the peer is a driver, not a sans-io core, so the injected clock's production value
        // is genuinely the wall clock (directive #2 — the seam is honored, its default supplied here).
        // The annotation MUST stay on the same line as Clock.System — the standing-directive grep is line-based.
        @Suppress("UnseamedEntropy") val clock: () -> Instant = { Clock.System.now() }

        // The one real-UDP integration fact: socket-udp's io_uring `send` rejects a GC-heap buffer, so
        // every OUTBOUND datagram — STUN checks (ICE), DTLS records, SCTP packets, and the signaling
        // frames — must be encoded into NATIVE memory. Inject buffer's Linux native factory
        // (deterministic() → malloc-backed NativeBuffer) into every layer's bufferFactory seam. (These
        // buffers are manual-free; the peer is a short-lived establish-and-echo process, so the bounded
        // native allocation is acceptable here — pooled release is the W3/W5-deferred production refactor.)
        val net = BufferFactory.deterministic()

        val dtls = BoringSslDtls(bg, clock, DtlsConfig(bufferFactory = net))
        val stun = resolveAddress(cfg.stunHost, cfg.stunPort)
        val turn = resolveAddress(cfg.turnHost, cfg.turnPort)

        val gathering =
            IceGatheringPolicy { driver ->
                if (cfg.icePolicy != IcePolicy.RelayOnly) {
                    driver.gatherHost(cfg.localIp, cfg.localPort, stunServer = stun)
                }
                // Relay is always gathered — it's the fallback path, and the only path under relayOnly.
                driver.gatherRelay(turn, cfg.turnUser, cfg.turnPass, cfg.localIp, cfg.relayPort)
            }

        val pc =
            NativePeerConnection(
                scope = bg,
                clock = clock,
                random = Random(cfg.seed),
                binder = realUdpBinder(),
                gathering = gathering,
                dtls = dtls,
                config =
                    PeerConnectionConfig(
                        iceConfig = IceConfig(bufferFactory = net),
                        sctpConfig = SctpConfig(bufferFactory = net),
                    ),
            )

        // Two signaling sockets (PUT + poll), owned here so they are closed AFTER bg.cancel() stops the
        // loops that use them — closing them earlier would leave those loops spinning on a closed socket.
        val sigOut = UdpSignaling.open(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session, net)
        val sigIn = UdpSignaling.open(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session, net)

        val ok =
            withTimeoutOrNull(cfg.timeout) {
                when (cfg.role) {
                    Role.Offerer -> runOfferer(bg, pc, cfg, sigOut, sigIn)
                    Role.Answerer -> runAnswerer(bg, pc, cfg, sigOut, sigIn)
                }
            } ?: run {
                println("[harness] TIMEOUT after ${cfg.timeout}; state=${pc.connectionState.value}")
                false
            }

        bg.cancel()
        sigOut.close()
        sigIn.close()
        pc.close()
        if (ok) 0 else 1
    }

private suspend fun runOfferer(
    bg: CoroutineScope,
    pc: NativePeerConnection,
    cfg: HarnessConfig,
    sigOut: UdpSignaling,
    sigIn: UdpSignaling,
): Boolean {
    val channel = pc.createDataChannel(DataChannelConfig(label = "harness"))
    val offer = pc.createOffer()
    pc.setLocalDescription(SdpType.Offer, offer)

    // One PUT socket, single-consumer: the offer first (record 0), then trickled candidates in order.
    val outbox = Channel<Triple<String, Int, String>>(Channel.UNLIMITED)
    outbox.trySend(Triple("offer", 0, offer))
    bg.launch { for ((slot, id, payload) in outbox) sigOut.put(slot, id, payload) }
    bg.launch {
        var i = 0
        pc.localIceCandidates.collect { outbox.trySend(Triple("cand/offerer", i++, it)) }
    }

    // One poll socket, single-consumer: the answer, then the answerer's trickled candidates.
    bg.launch {
        var answered = false
        var seen = 0
        while (isActive) {
            if (!answered) {
                val a = sigIn.poll("answer", 0)
                if (a.isNotEmpty()) {
                    pc.setRemoteDescription(SdpType.Answer, a.first())
                    answered = true
                }
            } else {
                val cands = sigIn.poll("cand/answerer", seen)
                seen += cands.size
                for (c in cands) pc.addIceCandidate(c)
            }
            delay(POLL_INTERVAL)
        }
    }

    if (!awaitEstablished(pc)) return false
    channel.send(textBuffer("ping"))
    val pong = withTimeoutOrNull(ECHO_TIMEOUT) { channel.receive().first() }?.text()
    println("[harness] offerer echo reply: $pong")
    return pong == "pong"
}

private suspend fun runAnswerer(
    bg: CoroutineScope,
    pc: NativePeerConnection,
    cfg: HarnessConfig,
    sigOut: UdpSignaling,
    sigIn: UdpSignaling,
): Boolean {
    // Await the offer (bounded by the outer watchdog), then answer.
    var offer: String? = null
    while (offer == null) {
        val o = sigIn.poll("offer", 0)
        if (o.isNotEmpty()) offer = o.first() else delay(POLL_INTERVAL)
    }
    pc.setRemoteDescription(SdpType.Offer, offer)
    val answer = pc.createAnswer()
    pc.setLocalDescription(SdpType.Answer, answer)

    val outbox = Channel<Triple<String, Int, String>>(Channel.UNLIMITED)
    outbox.trySend(Triple("answer", 0, answer))
    bg.launch { for ((slot, id, payload) in outbox) sigOut.put(slot, id, payload) }
    bg.launch {
        var i = 0
        pc.localIceCandidates.collect { outbox.trySend(Triple("cand/answerer", i++, it)) }
    }

    // The offer poll above is done, so this launched loop is the only consumer of sigIn (no receive race).
    bg.launch {
        var seen = 0
        while (isActive) {
            val cands = sigIn.poll("cand/offerer", seen)
            seen += cands.size
            for (c in cands) pc.addIceCandidate(c)
            delay(POLL_INTERVAL)
        }
    }

    val incoming = pc.incomingDataChannels.first()
    val msg = withTimeoutOrNull(ECHO_TIMEOUT) { incoming.receive().first() }?.text()
    println("[harness] answerer received: $msg")
    if (msg == "ping") incoming.send(textBuffer("pong"))
    val ok = awaitEstablished(pc) && msg == "ping"
    // Linger before teardown so SCTP reliably delivers + gets the final "pong" acked. Without this the
    // answerer closes its association the instant after send(), racing delivery, and the offerer's
    // channel.receive() times out (the pong was queued but never transmitted/retransmitted). The
    // offerer's ECHO_TIMEOUT bounds the wait on the other side; this window is shorter than that.
    if (ok) delay(FLUSH_LINGER)
    return ok
}

/** Suspend until the session reaches Connected (true) or a typed Failed (false, reason printed). */
private suspend fun awaitEstablished(pc: NativePeerConnection): Boolean {
    val terminal =
        pc.connectionState.first {
            it is PeerConnectionState.Connected || it is PeerConnectionState.Failed
        }
    if (terminal is PeerConnectionState.Failed) {
        println("[harness] FAILED: ${terminal.reason}")
        return false
    }
    println("[harness] CONNECTED")
    return true
}

private val POLL_INTERVAL = 200.milliseconds
private val ECHO_TIMEOUT = 10.seconds

// Answerer flush window: keep the SCTP association alive after send(pong) so reliable delivery + SACK
// complete before teardown. On the loopback/vnet RTT this is generous; bounded well under ECHO_TIMEOUT.
private val FLUSH_LINGER = 4.seconds
