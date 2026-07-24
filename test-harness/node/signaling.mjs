// The signaling **rendezvous client** — the Node/werift mirror of pion/signaling.go (and thus of the
// native peer's `UdpSignaling.kt`). It speaks the EXACT same big-endian buffer-codec wire schema the
// Python relay (`rendezvous/rendezvous.py`), the Go peer (`signaling.go`) and the Kotlin peer
// (`SignalingWire.kt`) do, so a werift peer, a Pion peer and a native peer all meet in the same mailbox:
//
//   PutRequest  : op=1(u8)  nonce(u32)  keyLen(u16)  key(utf8)  recordId(u32)  payloadLen(u32)  payload(utf8)
//   GetRequest  : op=2(u8)  nonce(u32)  keyLen(u16)  key(utf8)  since(u32)
//   Response    : status(u8)  nonce(u32)  total(u32)  records[]   (each: payloadLen(u32) payload)
//
// key = "<session>/<slot>"; slots are offer | answer | cand/offerer | cand/answerer. A PUT stores a
// record under (key, recordId) — id-keyed so a retransmit is idempotent; a GET returns the contiguous
// run of records at or after `since`.
//
// `nonce` is the request/response correlator: UDP has no request/response pairing, so a delayed or
// duplicate reply whose nonce doesn't match the awaited request is DRAINED and discarded rather than
// mis-paired (exactly as the Go `awaitReply` / the native peer's `awaitReply` do). Each Signaling
// instance owns ONE connected socket with ONE outstanding awaited reply at a time (open a second
// instance for a concurrent activity — the peer uses a sigOut/sigIn split), so two flows never race the
// socket's read.
//
// EVERY multi-byte field is big-endian: `writeUInt32BE` / `readUInt32BE`, `writeUInt16BE`. A single
// wrong endianness or field width and the werift peer silently never meets the offerer in the mailbox.

import dgram from "node:dgram";
import net from "node:net";

const OP_PUT = 1;
const OP_GET = 2;

const PUT_TIMEOUT_MS = 15000; // total budget for a PUT to be ack'd (retransmitting throughout)
const GET_TIMEOUT_MS = 1000; //  one poll's wait for its matching-nonce response
const RETRANSMIT_MS = 500; //    per-retransmit wait for a PUT ack

// openSignaling dials the rendezvous relay from a fresh ephemeral UDP socket (its own single-consumer
// socket, matching the native peer's + Pion's sigOut/sigIn split).
//
// Socket family: the Go peer uses network "udp" + JoinHostPort so it dials a v6 rendezvous too — on the
// v6/dual lanes the host is a bare v6 literal (e.g. 2001:db8:30::20). Node's dgram is family-typed at
// creation, so we pick udp6 for a v6 literal and udp4 otherwise (the harness always passes an IP literal
// — RENDEZVOUS_IP / RENDEZVOUS_IP6 — never a hostname). `socket.connect(port, host)` takes the BARE host
// (no brackets), like Go's DialUDP, so the v6 literal is passed through unbracketed.
export function openSignaling(host, port, session) {
  const type = net.isIPv6(host) ? "udp6" : "udp4";
  const socket = dgram.createSocket(type);
  const sig = new Signaling(socket, session);
  return new Promise((resolve, reject) => {
    const onError = (err) => reject(err);
    socket.once("error", onError);
    // Connected UDP: the kernel filters datagrams to this peer (mirrors Go's DialUDP), so a stray
    // datagram from elsewhere can never be mistaken for a reply.
    socket.connect(port, host, () => {
      socket.off("error", onError);
      resolve(sig);
    });
  });
}

class Signaling {
  constructor(socket, session) {
    this.socket = socket;
    this.session = session;
    this.nonce = 0;
    // The single outstanding awaited reply: { nonce, resolve, timer } or null. One at a time — each
    // logical flow (`awaitOffer`/answer-put on one socket; the poll/drain loops each on their own) drives
    // its socket sequentially, so we never have two concurrent awaits on one socket.
    this.pending = null;
    socket.on("message", (msg) => this._onMessage(msg));
    // Swallow socket errors: they surface to the caller as a timed-out awaitReply (→ PUT retransmit / an
    // empty poll), exactly as a transient error does in the Go blocking-read version.
    socket.on("error", () => {});
  }

  close() {
    try {
      this.socket.close();
    } catch {
      // already closed
    }
  }

  nextNonce() {
    const n = this.nonce;
    this.nonce = (this.nonce + 1) >>> 0; // wrap as an unsigned 32-bit counter
    return n;
  }

  // _onMessage is the single 'message' handler: decode, and if it echoes the awaited nonce resolve the
  // waiter with its records; otherwise it is stale/duplicate/undecodable → drain and discard.
  _onMessage(msg) {
    const decoded = decodeResponse(msg);
    if (!decoded) return; // undecodable → drain
    const p = this.pending;
    if (p && decoded.nonce === p.nonce) {
      this.pending = null;
      clearTimeout(p.timer);
      p.resolve(decoded.records);
    }
    // else: nonce mismatch (a stale/duplicate reply) → discard, keep waiting until the deadline.
  }

  // awaitReply resolves with the records of the response echoing `expectedNonce`, or null if the timeout
  // elapses first. null vs [] is meaningful: [] is a valid (ack'd) response with zero records; null is
  // "no matching reply arrived in this window".
  awaitReply(expectedNonce, timeoutMs) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (this.pending && this.pending.nonce === expectedNonce) this.pending = null;
        resolve(null);
      }, timeoutMs);
      this.pending = { nonce: expectedNonce, resolve, timer };
    });
  }

  // put PUTs payload as record recordId into slot, retransmitting the SAME request (same nonce) until a
  // matching-nonce ack or PUT_TIMEOUT_MS. Reusing one nonce across retransmits (as the Go version does)
  // makes the whole PUT idempotent: any ack for that nonce completes it.
  async put(slot, recordId, payload) {
    const nonce = this.nextNonce();
    const req = encodePut(nonce, `${this.session}/${slot}`, recordId >>> 0, payload);
    const deadline = Date.now() + PUT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      this.socket.send(req);
      const records = await this.awaitReply(nonce, RETRANSMIT_MS);
      if (records !== null) return true; // any matching-nonce reply is an ack
    }
    return false;
  }

  // poll GETs the records of slot at or after index `since`; returns the new records in order (empty on a
  // lost datagram or an as-yet-empty slot — the caller polls again and advances its own `since`).
  async poll(slot, since) {
    const nonce = this.nextNonce();
    const req = encodeGet(nonce, `${this.session}/${slot}`, since >>> 0);
    this.socket.send(req);
    const records = await this.awaitReply(nonce, GET_TIMEOUT_MS);
    return records === null ? [] : records;
  }
}

// ── wire codecs (big-endian) — byte-for-byte the KSP-generated buffer-codec schema ──

function encodePut(nonce, key, recordId, payload) {
  const k = Buffer.from(key, "utf8");
  const p = Buffer.from(payload, "utf8");
  const out = Buffer.allocUnsafe(1 + 4 + 2 + k.length + 4 + 4 + p.length);
  let o = 0;
  o = out.writeUInt8(OP_PUT, o);
  o = out.writeUInt32BE(nonce >>> 0, o);
  o = out.writeUInt16BE(k.length, o);
  o += k.copy(out, o);
  o = out.writeUInt32BE(recordId >>> 0, o);
  o = out.writeUInt32BE(p.length >>> 0, o);
  o += p.copy(out, o);
  return out;
}

function encodeGet(nonce, key, since) {
  const k = Buffer.from(key, "utf8");
  const out = Buffer.allocUnsafe(1 + 4 + 2 + k.length + 4);
  let o = 0;
  o = out.writeUInt8(OP_GET, o);
  o = out.writeUInt32BE(nonce >>> 0, o);
  o = out.writeUInt16BE(k.length, o);
  o += k.copy(out, o);
  o = out.writeUInt32BE(since >>> 0, o);
  return out;
}

// decodeResponse parses status(u8) nonce(u32) total(u32) then records[] until the datagram end. Returns
// { nonce, records } or null on any truncation, so a malformed datagram is discarded, never fatal.
function decodeResponse(data) {
  if (data.length < 9) return null;
  // data[0] = status (0 = OK); we don't discriminate on it (a non-OK reply just won't advance us).
  const nonce = data.readUInt32BE(1);
  // data[5:9] = total (informational; the caller tracks its own `since`).
  let pos = 9;
  const records = [];
  while (pos + 4 <= data.length) {
    const plen = data.readUInt32BE(pos);
    pos += 4;
    if (pos + plen > data.length) return null; // truncated record → discard the whole datagram
    records.push(data.toString("utf8", pos, pos + plen));
    pos += plen;
  }
  return { nonce, records };
}
