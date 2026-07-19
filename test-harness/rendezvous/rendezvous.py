#!/usr/bin/env python3
"""L2 harness signaling rendezvous — a stateless in-memory UDP keyed mailbox.

The two native peers exchange their SDP offer/answer + trickled ICE candidates through this relay
because, behind their NAT gateways, they cannot reach each other directly (that is what ICE is
establishing). It reaches both peers on the public harness network exactly the way coturn does.

Signaling rides UDP (not TCP/HTTP) on purpose: the native Kotlin/Native peer links `socket-udp` (the
one crypto-free socket module) but CANNOT link socket core / socket-quic without a BoringSSL
duplicate-symbol break against buffer-crypto's copy (see ~/git/cinterop-issues). So the peer speaks the
only transport it can — raw UDP — and this relay speaks it back. Nothing is written to disk.

Wire format — big-endian — MUST match the KSP-generated buffer-codec schema in the peer's
`SignalingWire.kt` (PutRequest / GetRequest / MailboxResponse / MailboxRecord):

    PutRequest  : op=1(u8)  nonce(u32)  keyLen(u16)  key(utf8)  recordId(u32)  payloadLen(u32)  payload(utf8)
    GetRequest  : op=2(u8)  nonce(u32)  keyLen(u16)  key(utf8)  since(u32)
    Response    : status=0(u8)  nonce(u32)  total(u32)  records[]   (each record: payloadLen(u32) payload)

`key` is "<session>/<slot>"; a slot is offer | answer | cand/offerer | cand/answerer. A PUT stores a
record under (key, recordId) — id-keyed so a UDP retransmit is idempotent. A GET returns the CONTIGUOUS
run of records from index `since` (stopping at the first missing recordId), so a reordered/late PUT can
never make the poller skip a record: the gap just waits for that record's retransmit. Records are
returned in recordId order.

`nonce` is echoed back in the response — the client's request/response correlator over UDP (a delayed or
duplicate reply that doesn't match the awaited nonce is drained + discarded rather than mis-paired).
"""
import os
import socket
import struct

OP_PUT = 1
OP_GET = 2

# key(str) -> { recordId(int) -> payload(bytes) }
mailboxes: dict[str, dict[int, bytes]] = {}


def _response(nonce: int, records: list[bytes], total: int) -> bytes:
    out = bytearray()
    out += struct.pack(">BII", 0, nonce, total)  # status=0 (OK), echoed nonce, total record count
    for payload in records:
        out += struct.pack(">I", len(payload)) + payload
    return bytes(out)


def _handle(data: bytes) -> bytes | None:
    if not data:
        return None
    op = data[0]
    pos = 1
    (nonce,) = struct.unpack_from(">I", data, pos)  # correlator, echoed back
    pos += 4
    (key_len,) = struct.unpack_from(">H", data, pos)
    pos += 2
    key = data[pos:pos + key_len].decode("utf-8")
    pos += key_len

    if op == OP_PUT:
        (record_id, payload_len) = struct.unpack_from(">II", data, pos)
        pos += 8
        payload = data[pos:pos + payload_len]
        mailboxes.setdefault(key, {})[record_id] = payload
        # Ack: an empty-records response — the peer's put() only needs a nonce-matching datagram to confirm.
        return _response(nonce, [], len(mailboxes[key]))

    if op == OP_GET:
        (since,) = struct.unpack_from(">I", data, pos)
        box = mailboxes.get(key, {})
        records: list[bytes] = []
        i = since
        while i in box:  # contiguous run from `since` — stop at the first gap
            records.append(box[i])
            i += 1
        return _response(nonce, records, len(box))

    return None  # unknown opcode — ignore


def main() -> None:
    port = int(os.environ.get("RENDEZVOUS_PORT", "9999"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[rendezvous] UDP keyed-mailbox listening on 0.0.0.0:{port}", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        op = data[0] if data else 0
        print(f"[rendezvous] rx {len(data)}B op={op} from {addr}", flush=True)
        try:
            reply = _handle(data)
        except Exception as e:  # never let one malformed datagram kill the relay
            print(f"[rendezvous] drop malformed datagram from {addr}: {e}", flush=True)
            continue
        if reply is not None:
            sock.sendto(reply, addr)


if __name__ == "__main__":
    main()
