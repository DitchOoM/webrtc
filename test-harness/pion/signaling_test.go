package main

import (
	"testing"
)

// TestSignalingRoundTrip drives put/poll against a REAL rendezvous.py running on 127.0.0.1:RENDEZVOUS_PORT
// (started by the test harness in signaling_roundtrip.sh). It proves the Go wire codec is byte-compatible
// with the Python relay and the native peer's schema.
func TestSignalingRoundTrip(t *testing.T) {
	sig, err := openSignaling("127.0.0.1", 9999, "testsess")
	if err != nil {
		t.Fatalf("openSignaling: %v", err)
	}
	defer sig.close()

	// Requires a rendezvous.py on 127.0.0.1:9999 (see signaling_roundtrip.sh); skip if none is running so
	// a plain `go test ./...` doesn't fail where the relay isn't up.
	if !sig.put("offer", 0, "HELLO-OFFER") {
		t.Skip("no rendezvous on 127.0.0.1:9999 — start rendezvous/rendezvous.py to run this round-trip test")
	}
	recs := sig.poll("offer", 0)
	if len(recs) != 1 || recs[0] != "HELLO-OFFER" {
		t.Fatalf("poll(offer) = %v, want [HELLO-OFFER]", recs)
	}

	// A second record + contiguous-run semantics.
	if !sig.put("offer", 1, "SECOND") {
		t.Fatal("put(offer,1) no ack")
	}
	recs = sig.poll("offer", 1)
	if len(recs) != 1 || recs[0] != "SECOND" {
		t.Fatalf("poll(offer, since=1) = %v, want [SECOND]", recs)
	}
}
