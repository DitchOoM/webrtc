package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// The signaling **rendezvous client** — the Go mirror of the native peer's `UdpSignaling.kt`. It speaks
// the exact same big-endian buffer-codec wire schema the Python relay (`rendezvous/rendezvous.py`) and
// the Kotlin peer (`SignalingWire.kt`) do, so a Pion peer and a native peer meet in the same mailbox:
//
//	PutRequest  : op=1(u8)  nonce(u32)  keyLen(u16)  key(utf8)  recordId(u32)  payloadLen(u32)  payload(utf8)
//	GetRequest  : op=2(u8)  nonce(u32)  keyLen(u16)  key(utf8)  since(u32)
//	Response    : status(u8)  nonce(u32)  total(u32)  records[]   (each: payloadLen(u32) payload)
//
// key = "<session>/<slot>"; slots are offer | answer | cand/offerer | cand/answerer. A PUT stores a
// record under (key, recordId) — id-keyed so a retransmit is idempotent; a GET returns the contiguous
// run of records at or after `since`.
//
// `nonce` is the request/response correlator: UDP has no request/response pairing, so a delayed or
// duplicate reply whose nonce doesn't match the awaited request is drained and discarded rather than
// mis-paired (exactly as the native peer's `awaitReply` does). Each Signaling instance owns ONE socket
// driven by ONE goroutine (open a second instance for a concurrent activity), so two goroutines never
// race the socket's read.
const (
	opPut byte = 1
	opGet byte = 2

	putTimeout = 15 * time.Second
	getTimeout = 1 * time.Second
	retransmit = 500 * time.Millisecond
	readChunk  = 65535
)

type signaling struct {
	conn    *net.UDPConn
	session string
	nonce   uint32
}

// openSignaling dials the rendezvous relay from a fresh ephemeral UDP socket (its own single-consumer
// socket, matching the native peer's sigOut/sigIn split).
func openSignaling(host string, port int, session string) (*signaling, error) {
	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, err
	}
	return &signaling{conn: conn, session: session}, nil
}

func (s *signaling) close() { _ = s.conn.Close() }

func (s *signaling) nextNonce() uint32 {
	n := s.nonce
	s.nonce++
	return n
}

// put PUTs payload as record recordId into slot, retransmitting until a matching-nonce ack or putTimeout.
func (s *signaling) put(slot string, recordId int, payload string) bool {
	nonce := s.nextNonce()
	req := encodePut(nonce, s.session+"/"+slot, uint32(recordId), payload)
	deadline := time.Now().Add(putTimeout)
	for time.Now().Before(deadline) {
		if _, err := s.conn.Write(req); err != nil {
			return false
		}
		// Wait one retransmit interval for an ack echoing OUR nonce (stale acks are drained).
		if _, ok := s.awaitReply(nonce, time.Now().Add(retransmit)); ok {
			return true
		}
	}
	return false
}

// poll GETs the records of slot at or after index `since`; returns the new records in order (empty on a
// lost datagram or an as-yet-empty slot — the caller polls again and advances its own `since`).
func (s *signaling) poll(slot string, since int) []string {
	nonce := s.nextNonce()
	req := encodeGet(nonce, s.session+"/"+slot, uint32(since))
	if _, err := s.conn.Write(req); err != nil {
		return nil
	}
	records, ok := s.awaitReply(nonce, time.Now().Add(getTimeout))
	if !ok {
		return nil
	}
	return records
}

// awaitReply reads datagrams until one whose response echoes expectedNonce (returning its records), or
// the deadline passes. Non-matching / undecodable datagrams are discarded — this is both the correlation
// and the drain of stale replies.
func (s *signaling) awaitReply(expectedNonce uint32, deadline time.Time) ([]string, bool) {
	buf := make([]byte, readChunk)
	for {
		if err := s.conn.SetReadDeadline(deadline); err != nil {
			return nil, false
		}
		n, err := s.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, false
			}
			// Timeout (or transient) — the awaited reply did not arrive in this window.
			return nil, false
		}
		nonce, records, ok := decodeResponse(buf[:n])
		if ok && nonce == expectedNonce {
			return records, true
		}
		// else: stale/duplicate/undecodable — drain and keep waiting until the deadline.
	}
}

// ── wire codecs (big-endian) — byte-for-byte the KSP-generated buffer-codec schema ──

func encodePut(nonce uint32, key string, recordId uint32, payload string) []byte {
	k := []byte(key)
	p := []byte(payload)
	out := make([]byte, 0, 1+4+2+len(k)+4+4+len(p))
	out = append(out, opPut)
	out = binary.BigEndian.AppendUint32(out, nonce)
	out = binary.BigEndian.AppendUint16(out, uint16(len(k)))
	out = append(out, k...)
	out = binary.BigEndian.AppendUint32(out, recordId)
	out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
	out = append(out, p...)
	return out
}

func encodeGet(nonce uint32, key string, since uint32) []byte {
	k := []byte(key)
	out := make([]byte, 0, 1+4+2+len(k)+4)
	out = append(out, opGet)
	out = binary.BigEndian.AppendUint32(out, nonce)
	out = binary.BigEndian.AppendUint16(out, uint16(len(k)))
	out = append(out, k...)
	out = binary.BigEndian.AppendUint32(out, since)
	return out
}

// decodeResponse parses status(u8) nonce(u32) total(u32) then records[] until the datagram end. Returns
// (nonce, records, ok); ok=false on any truncation so a malformed datagram is discarded, never fatal.
func decodeResponse(data []byte) (uint32, []string, bool) {
	if len(data) < 9 {
		return 0, nil, false
	}
	// data[0] = status (0 = OK); we don't discriminate on it (a non-OK reply just won't advance us).
	nonce := binary.BigEndian.Uint32(data[1:5])
	// data[5:9] = total (informational; the caller tracks its own `since`).
	pos := 9
	var records []string
	for pos+4 <= len(data) {
		plen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+plen > len(data) {
			return 0, nil, false // truncated record → discard the whole datagram
		}
		records = append(records, string(data[pos:pos+plen]))
		pos += plen
	}
	return nonce, records, true
}
