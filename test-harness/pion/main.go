// Command pion-echo is the W7 Phase-2(a) interop **echo-peer**: a real Pion (Go) WebRTC endpoint that
// establishes a data channel against our native Kotlin/Native peer and echoes ping→pong. It proves our
// hand-written ICE + DTLS + SCTP + DCEP + SDP stack interoperates with an independent implementation —
// the differential oracle the harness exists to provide.
//
// It runs as the ANSWERER behind a NAT gateway (drop-in for the native answerer `peer_b`): it reads the
// same `WEBRTC_*` env the compose harness sets, gathers host/srflx/relay candidates from the same real
// coturn, and exchanges offer/answer/candidates over the same UDP rendezvous mailbox (see signaling.go).
//
// DTLS: Pion's released v3 speaks DTLS **1.2 only**, so the native offerer runs this lane with
// `WEBRTC_DTLS13=false` (its 1.2 fallback), and version negotiation meets at 1.2.
//
// Exit 0 = ICE/DTLS connected AND a "ping" was received and a "pong" echoed back; non-zero = the
// watchdog fired first (never established, or no ping) — mirroring the native peer's exit contract so
// run-interop.sh asserts BOTH sides exit 0.
//
// Semantics mode (WEBRTC_SEMANTICS=1, see docs/DC_SEMANTICS_INTEROP_DESIGN.md): this peer becomes a
// universal REFLECTOR — every channel, every message, echoed back verbatim on the channel it arrived on —
// and exits only on the offerer's explicit DONE handshake instead of a few seconds after the ping echo.
// It stays scenario-agnostic: it never reads a channel label to decide behaviour, so all of the
// data-channel semantics matrix (fragmentation, unordered, partial reliability, multiplexing) is driven
// and asserted entirely by the offerer.
//
// Renegotiation (issue #71): it also RE-ANSWERS. A second offer in the mailbox means the offerer restarted
// ICE (RFC 8445 §9) after the harness moved it onto another carrier, and this peer answers it on the same
// PeerConnection — which is what the `restart-pion` lane exists to prove a third-party stack does. Still no
// scenario logic: the round is read off the mailbox, not signalled, so a lane that never restarts never
// reaches the code.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/webrtc/v3"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := configFromEnv()
	fmt.Printf("[pion] role=answerer session=%s policy=%s local=%s dtls=1.2(v3)\n", cfg.session, cfg.icePolicy, cfg.localIP)

	// Overall watchdog: a bound, not a wall-clock budget — establish + reliable echo under a NAT/impaired
	// path is legitimately slower than a clean path (directive #4). In semantics mode it additionally has
	// to cover the offerer's whole phase sequence, which runs after phase 0's ping/pong.
	deadline := time.Now().Add(cfg.timeout)
	if cfg.semantics {
		deadline = deadline.Add(cfg.semanticsTimeout)
	}

	pc, err := newPeerConnection(cfg)
	if err != nil {
		fmt.Printf("[pion] FAILED to build peer connection: %v\n", err)
		return 1
	}
	defer func() { _ = pc.Close() }()

	// State signals, buffered so a callback never blocks Pion's internal goroutines.
	connected := make(chan struct{}, 1)
	failed := make(chan struct{}, 1)
	echoed := make(chan struct{}, 1)
	done := make(chan struct{}, 1)

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		fmt.Printf("[pion] connection state: %s\n", s)
		switch s {
		case webrtc.PeerConnectionStateConnected:
			trySignal(connected)
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			trySignal(failed)
		}
	})

	// The universal REFLECTOR (docs/DC_SEMANTICS_INTEROP_DESIGN.md §4): for EVERY channel the offerer
	// opens, echo EVERY message back on that same channel, verbatim — same bytes, same string/binary type.
	// Nothing here is scenario-aware: the label is logged, never branched on. That is what lets one dumb
	// answerer serve the whole semantics matrix (large/fragmented, unordered, partial-reliable, multiplexed)
	// while every assertion stays on the offerer side, in our Kotlin.
	//
	// The ONE historical exception is the liveness ritual: "ping" is echoed as "pong" (a string message the
	// native side decodes with .text()), so phase 0 is bit-for-bit the test this lane has always run.
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		// The negotiated DCEP properties Pion parsed out of our DATA_CHANNEL_OPEN. For the semantics
		// channels these ARE the "was the channel type honored end-to-end" evidence: s2/unordered must show
		// ordered=false, s3/rexmit maxRetransmits=0, s3/timed a finite maxPacketLifeTime. Printed in the
		// same shape by every reflector family so one grep works across Pion, werift and the browsers.
		fmt.Printf("[pion] dc-negotiated: label=%q id=%v ordered=%s maxRetransmits=%s maxPacketLifeTime=%s\n",
			dc.Label(), dc.ID(), fmtBool(dc.Ordered()), fmtU16(dc.MaxRetransmits()), fmtU16(dc.MaxPacketLifeTime()))
		dc.OnClose(func() { fmt.Printf("[pion] dc close: label=%q\n", dc.Label()) })
		rx := 0
		rxBytes := 0
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			rx++
			rxBytes += len(msg.Data)
			text := string(msg.Data)
			// Only a small payload is rendered; a large binary (s1's ~200 KB) is summarized by size.
			rendered := fmt.Sprintf("<%dB binary>", len(msg.Data))
			if len(msg.Data) <= 64 {
				rendered = fmt.Sprintf("%q", text)
			}
			fmt.Printf("[pion] received on %q: size=%d msg#%d rxBytes=%d string=%v data=%s\n",
				dc.Label(), len(msg.Data), rx, rxBytes, msg.IsString, rendered)

			if strings.TrimSpace(text) == "ping" {
				if err := dc.SendText("pong"); err != nil {
					fmt.Printf("[pion] failed to send pong: %v\n", err)
					return
				}
				fmt.Println("[pion] echoed: \"pong\"")
				trySignal(echoed)
				return
			}
			// Verbatim echo, preserving the string/binary distinction the message arrived with.
			var err error
			if msg.IsString {
				err = dc.SendText(text)
			} else {
				err = dc.Send(msg.Data)
			}
			if err != nil {
				fmt.Printf("[pion] failed to echo %d bytes on %q: %v\n", len(msg.Data), dc.Label(), err)
				return
			}
			// The offerer's completion handshake: once DONE has been echoed, the run is over and we may
			// tear down. This replaces the old "linger N seconds after the pong" race with an agreement.
			if strings.TrimSpace(text) == doneMarker {
				fmt.Println("[pion] DONE echoed — the offerer signalled the run is complete")
				trySignal(done)
			}
		})
	})

	// Two single-consumer signaling sockets (mirrors the native peer): sigOut for our PUTs (answer +
	// trickled candidates), sigIn for our polls (offer + the offerer's candidates).
	sigOut, err := openSignaling(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session)
	if err != nil {
		fmt.Printf("[pion] FAILED to open signaling (out): %v\n", err)
		return 1
	}
	defer sigOut.close()
	sigIn, err := openSignaling(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session)
	if err != nil {
		fmt.Printf("[pion] FAILED to open signaling (in): %v\n", err)
		return 1
	}
	defer sigIn.close()

	// Trickle our local candidates out as they are gathered. Registered BEFORE SetLocalDescription so no
	// candidate is missed. Pion emits `candidate:...` (lowercase udp, raddr/rport for srflx/relay) — the
	// exact grammar the native parser accepts.
	candOut := make(chan string, 32)
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return // end-of-candidates; the native side uses ICE consent, not this signal
		}
		select {
		case candOut <- c.ToJSON().Candidate:
		default:
			fmt.Println("[pion] WARN candidate outbox full, dropping")
		}
	})

	// 1. Await the offer (bounded by the watchdog), then set it as the remote description.
	offer := awaitOffer(sigIn, deadline)
	if offer == "" {
		fmt.Println("[pion] TIMEOUT waiting for offer")
		return 1
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		fmt.Printf("[pion] FAILED SetRemoteDescription(offer): %v\n", err)
		return 1
	}

	// 2. Answer, set it locally (this starts gathering + trickle), and publish it.
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		fmt.Printf("[pion] FAILED CreateAnswer: %v\n", err)
		return 1
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		fmt.Printf("[pion] FAILED SetLocalDescription: %v\n", err)
		return 1
	}
	// Publish the answer as stored by SetLocalDescription (trickle: no candidates embedded yet).
	if !sigOut.put("answer", 0, pc.LocalDescription().SDP) {
		fmt.Println("[pion] FAILED to publish answer to rendezvous")
		return 1
	}
	fmt.Println("[pion] answer published")

	// 3. One PUT queue with ONE draining goroutine, so exactly one goroutine ever writes sigOut — the
	//    single-consumer socket discipline signaling.go documents. Trickled candidates ride it, and so does
	//    a later round's answer (step 4), which is why the queue exists at all: before renegotiation there
	//    was only ever one writer and the answer could be PUT inline.
	outbox := make(chan outRecord, 64)
	go func() {
		for r := range outbox {
			sigOut.put(r.slot, r.recordId, r.payload)
		}
	}()
	go func() {
		i := 0
		for c := range candOut {
			outbox <- outRecord{slot: "cand/answerer", recordId: i, payload: c}
			i++
		}
	}()

	// 4. Poll the offerer's trickled candidates → AddICECandidate, and any LATER round's offer → re-answer
	//    (single consumer of sigIn — which is also why the re-answer is handled here rather than from a
	//    second loop that would race this one's socket read).
	go func() {
		seen := 0
		round := firstRestartRound
		zero := uint16(0)
		for time.Now().Before(deadline) {
			// A further offer means the offerer restarted ICE (RFC 8445 §9 — its s8 phase): re-answer it on
			// the SAME PeerConnection. A restart renegotiates ICE and nothing else, so the DTLS association
			// and every open data channel are untouched, and this side has nothing to do beyond answering
			// again (RFC 8842 §5.5). Failing to re-answer would leave the offerer's restart unconverged.
			if offers := sigIn.poll("offer", round); len(offers) > 0 {
				if reanswer(pc, outbox, round, offers[0]) {
					round++
				}
			}
			cands := sigIn.poll("cand/offerer", seen)
			for _, c := range cands {
				// Single m-line (mid:0); the native side sends bare candidate strings, so supply the
				// mline index Pion's API wants.
				if err := pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: c, SDPMLineIndex: &zero}); err != nil {
					fmt.Printf("[pion] AddICECandidate(%q) error: %v\n", c, err)
				}
			}
			seen += len(cands)
			time.Sleep(200 * time.Millisecond)
		}
	}()

	// 5. Wait for connected + echoed (or a typed failure / watchdog).
	if !waitEstablished(connected, failed, deadline) {
		fmt.Printf("[pion] FAILED to establish before deadline (state=%s)\n", pc.ConnectionState())
		return 1
	}
	fmt.Println("[pion] CONNECTED")

	if !waitEchoed(echoed, deadline) {
		fmt.Println("[pion] TIMEOUT waiting to receive ping / echo pong")
		return 1
	}

	if cfg.semantics {
		// Semantics mode: keep reflecting until the offerer's explicit DONE. Exiting on a timer here would
		// tear the association down mid-sequence — the linger below is exactly what DONE replaces.
		if !waitEchoed(done, deadline) {
			fmt.Println("[pion] TIMEOUT waiting for the offerer's DONE handshake")
			return 1
		}
		// Brief linger so the DONE echo is delivered and the offerer's graceful association SHUTDOWN
		// (RFC 4960 §9.2) is received and answered before this process exits.
		time.Sleep(3 * time.Second)
		fmt.Printf("[pion] connection state at exit: %s\n", pc.ConnectionState())
		fmt.Println("[pion] exit=0 (established + echoed + DONE)")
		return 0
	}

	// Linger so SCTP reliably delivers the final "pong" (and its SACK) before teardown — the native peer
	// does the same after its send. Bounded and well under the offerer's echo timeout.
	time.Sleep(3 * time.Second)
	fmt.Println("[pion] exit=0 (established + echoed)")
	return 0
}

// doneMarker is the offerer's completion word on the control channel (see the Kotlin ControlChannel).
const doneMarker = "DONE"

// The first offer/answer round that can only be an ICE restart. Round 0 negotiates the session; the
// offerer's s8 phase publishes round 1 after the harness moves it onto a second carrier. Both peers key
// their mailbox records by the same round, so the two halves line up without either announcing anything.
const firstRestartRound = 1

// outRecord is one queued PUT, drained by the single goroutine that owns sigOut (see step 3).
type outRecord struct {
	slot     string
	recordId int
	payload  string
}

// reanswer applies a later round's offer and publishes the answer under the SAME record id, so both peers'
// rounds line up in the mailbox. Deliberately the same three calls as round 0: a restart is a renegotiation
// of the existing session, not a second session. Returns false — leaving the round unconsumed so the next
// poll retries it — if the engine rejected the offer, since a half-applied round is worse than a retried one.
func reanswer(pc *webrtc.PeerConnection, outbox chan<- outRecord, round int, offer string) bool {
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		fmt.Printf("[pion] FAILED SetRemoteDescription(offer, round %d): %v\n", round, err)
		return false
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		fmt.Printf("[pion] FAILED CreateAnswer(round %d): %v\n", round, err)
		return false
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		fmt.Printf("[pion] FAILED SetLocalDescription(round %d): %v\n", round, err)
		return false
	}
	outbox <- outRecord{slot: "answer", recordId: round, payload: pc.LocalDescription().SDP}
	// The line run-interop.sh greps on the restart lanes: this peer's OWN report that it re-answered, which
	// is the half of the proof only the answerer can give. Every reflector family prints the same token.
	fmt.Printf("[pion] re-answered round %d — the offerer restarted ICE\n", round)
	return true
}

// fmtBool / fmtU16 render Pion's *bool / *uint16 DCEP properties in the SAME shape every reflector family
// prints ("true"/"false", a number, or "-" when the peer left it unset), so run-interop.sh can assert the
// negotiated channel type with one grep regardless of which stack answered.
func fmtBool(v bool) string {
	return strconv.FormatBool(v)
}

func fmtU16(v *uint16) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(int(*v))
}

func awaitOffer(sig *signaling, deadline time.Time) string {
	for time.Now().Before(deadline) {
		if recs := sig.poll("offer", 0); len(recs) > 0 {
			return recs[0]
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ""
}

func waitEstablished(connected, failed <-chan struct{}, deadline time.Time) bool {
	select {
	case <-connected:
		return true
	case <-failed:
		return false
	case <-time.After(time.Until(deadline)):
		return false
	}
}

func waitEchoed(echoed <-chan struct{}, deadline time.Time) bool {
	select {
	case <-echoed:
		return true
	case <-time.After(time.Until(deadline)):
		return false
	}
}

func trySignal(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// brk brackets a bare IPv6 literal so it's a legal host in a STUN/TURN URI (RFC 7064 → RFC 3986):
// `2001:db8:30::10` must become `[2001:db8:30::10]`, else Pion's URL parser reads the colons as extra
// port separators ("too many colons in address") and NewPeerConnection fails before ICE even starts. On
// the v6/dual lanes compose passes coturn's bare v6 literal as WEBRTC_STUN/TURN_HOST; a hostname or v4
// literal (no colon) passes through untouched, so v4 is unaffected.
func brk(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

// newPeerConnection builds a Pion PeerConnection pointed at the harness coturn for STUN + TURN, honoring
// the relay-only policy when requested.
func newPeerConnection(cfg config) (*webrtc.PeerConnection, error) {
	rtcCfg := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{fmt.Sprintf("stun:%s:%d", brk(cfg.stunHost), cfg.stunPort)}},
			{
				URLs:       []string{fmt.Sprintf("turn:%s:%d?transport=udp", brk(cfg.turnHost), cfg.turnPort)},
				Username:   cfg.turnUser,
				Credential: cfg.turnPass,
			},
		},
	}
	if cfg.icePolicy == "relay" {
		rtcCfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	return webrtc.NewPeerConnection(rtcCfg)
}

// ── config from WEBRTC_* env (the same vars the native peer reads) ──

type config struct {
	session        string
	localIP        string
	stunHost       string
	stunPort       int
	turnHost       string
	turnPort       int
	turnUser       string
	turnPass       string
	rendezvousHost string
	rendezvousPort int
	icePolicy      string
	timeout        time.Duration
	// Reflect until the offerer's DONE instead of exiting shortly after the ping echo — set by
	// run-interop.sh (WEBRTC_SEMANTICS=1) whenever the offerer runs the data-channel semantics sequence.
	semantics        bool
	semanticsTimeout time.Duration
}

func configFromEnv() config {
	return config{
		session:        env("WEBRTC_SESSION", "harness"),
		localIP:        env("WEBRTC_LOCAL_IP", ""),
		stunHost:       env("WEBRTC_STUN_HOST", "coturn"),
		stunPort:       envInt("WEBRTC_STUN_PORT", 3478),
		turnHost:       env("WEBRTC_TURN_HOST", "coturn"),
		turnPort:       envInt("WEBRTC_TURN_PORT", 3478),
		turnUser:       env("WEBRTC_TURN_USER", "webrtc"),
		turnPass:       env("WEBRTC_TURN_PASS", "webrtc"),
		rendezvousHost: env("WEBRTC_RENDEZVOUS_HOST", "rendezvous"),
		rendezvousPort: envInt("WEBRTC_RENDEZVOUS_PORT", 9999),
		icePolicy:      strings.ToLower(env("WEBRTC_ICE_POLICY", "all")),
		timeout:        time.Duration(envInt("WEBRTC_TIMEOUT_MS", 45000)) * time.Millisecond,
		semantics:      isTruthy(env("WEBRTC_SEMANTICS", "")),

		semanticsTimeout: time.Duration(envInt("WEBRTC_SEMANTICS_TIMEOUT_MS", 120000)) * time.Millisecond,
	}
}

// isTruthy accepts "1" / "true" (any case); anything else — including absent — leaves a flag off.
func isTruthy(v string) bool {
	return v == "1" || strings.EqualFold(v, "true")
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
