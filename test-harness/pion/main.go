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
	// path is legitimately slower than a clean path (directive #4).
	deadline := time.Now().Add(cfg.timeout)

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

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		fmt.Printf("[pion] connection state: %s\n", s)
		switch s {
		case webrtc.PeerConnectionStateConnected:
			trySignal(connected)
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			trySignal(failed)
		}
	})

	// The native offerer creates a DCEP data channel labelled "harness" and sends "ping"; we accept it and
	// echo "pong" as a string message (WebRTC string PPID), which the native side decodes with .text().
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		fmt.Printf("[pion] incoming data channel: label=%q id=%v\n", dc.Label(), dc.ID())
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			text := string(msg.Data)
			fmt.Printf("[pion] received: %q (string=%v)\n", text, msg.IsString)
			if strings.TrimSpace(text) == "ping" {
				if err := dc.SendText("pong"); err != nil {
					fmt.Printf("[pion] failed to send pong: %v\n", err)
					return
				}
				fmt.Println("[pion] echoed: \"pong\"")
				trySignal(echoed)
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

	// 3. Drain trickled local candidates → PUT to cand/answerer (single consumer of sigOut).
	go func() {
		i := 0
		for c := range candOut {
			sigOut.put("cand/answerer", i, c)
			i++
		}
	}()

	// 4. Poll the offerer's trickled candidates → AddICECandidate (single consumer of sigIn).
	go func() {
		seen := 0
		zero := uint16(0)
		for time.Now().Before(deadline) {
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

	// Linger so SCTP reliably delivers the final "pong" (and its SACK) before teardown — the native peer
	// does the same after its send. Bounded and well under the offerer's echo timeout.
	time.Sleep(3 * time.Second)
	fmt.Println("[pion] exit=0 (established + echoed)")
	return 0
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
	}
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
