#!/usr/bin/env python3
"""L2 harness signaling rendezvous — a stateless in-memory keyed mailbox, reachable two ways.

The peers exchange their SDP offer/answer + trickled ICE candidates through this relay because,
behind their NAT gateways, they cannot reach each other directly (that is what ICE is establishing).
It reaches every peer on the public harness network exactly the way coturn does.

**Two front doors onto ONE mailbox** (a single in-memory `mailboxes` dict, guarded by a lock):

  * a **UDP** face (the historical one) — the native Kotlin/Native peer links `socket-udp` (the one
    crypto-free socket module) but CANNOT link socket core / socket-quic without a BoringSSL
    duplicate-symbol break against buffer-crypto's copy (see ~/git/cinterop-issues), so it speaks the
    only transport it can — raw UDP — and this relay speaks it back. The Pion (Go) peer mirrors it.

  * an **HTTP** face (W7 Phase 2(b)) — a browser (headless Chrome, the interop lane) has **no raw
    UDP** (JS can only fetch/WebSocket), so the Chrome answerer signals over HTTP against the SAME
    mailbox. A browser and a native peer therefore still meet in the same slot: the native offerer
    PUTs its offer over UDP, the browser polls it over HTTP; the browser PUTs its answer over HTTP,
    the native peer polls it over UDP. Nothing is written to disk.

UDP wire format — big-endian — MUST match the KSP-generated buffer-codec schema in the peer's
`SignalingWire.kt` (PutRequest / GetRequest / MailboxResponse / MailboxRecord):

    PutRequest  : op=1(u8)  nonce(u32)  keyLen(u16)  key(utf8)  recordId(u32)  payloadLen(u32)  payload(utf8)
    GetRequest  : op=2(u8)  nonce(u32)  keyLen(u16)  key(utf8)  since(u32)
    Response    : status=0(u8)  nonce(u32)  total(u32)  records[]   (each record: payloadLen(u32) payload)

HTTP face — same semantics as a PUT/GET, JSON in/out, CORS-open so a browser page from any origin
(the Playwright driver loads over http://localhost) can reach it:

    POST /put   {"key": "<session>/<slot>", "id": <int>, "payload": "<utf8 text>"}  -> {"total": <int>}
    GET  /poll?key=<session>/<slot>&since=<int>                                     -> {"records": [...], "total": <int>}

`key` is "<session>/<slot>"; a slot is offer | answer | cand/offerer | cand/answerer. A PUT stores a
record under (key, recordId) — id-keyed so a UDP retransmit / HTTP retry is idempotent. A GET/poll
returns the CONTIGUOUS run of records from index `since` (stopping at the first missing recordId), so
a reordered/late PUT can never make the poller skip a record: the gap just waits for that record's
retransmit. Records are returned in recordId order.

`nonce` (UDP only) is echoed back in the response — the client's request/response correlator over UDP
(a delayed or duplicate reply that doesn't match the awaited nonce is drained + discarded rather than
mis-paired). HTTP is request/response by construction, so it needs no nonce.
"""
import json
import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

OP_PUT = 1
OP_GET = 2

# key(str) -> { recordId(int) -> payload(bytes) }. Shared by BOTH faces, so all access takes _lock.
mailboxes: dict[str, dict[int, bytes]] = {}
_lock = threading.Lock()


def store_record(key: str, record_id: int, payload: bytes) -> int:
    """Idempotently store payload under (key, record_id); return the slot's record count."""
    with _lock:
        mailboxes.setdefault(key, {})[record_id] = payload
        return len(mailboxes[key])


def contiguous_records(key: str, since: int) -> tuple[list[bytes], int]:
    """The contiguous run of records at or after `since` (stop at the first gap), plus the slot total."""
    with _lock:
        box = mailboxes.get(key, {})
        records: list[bytes] = []
        i = since
        while i in box:
            records.append(box[i])
            i += 1
        return records, len(box)


# ── UDP face ──────────────────────────────────────────────────────────────────────────────────────

def _udp_response(nonce: int, records: list[bytes], total: int) -> bytes:
    out = bytearray()
    out += struct.pack(">BII", 0, nonce, total)  # status=0 (OK), echoed nonce, total record count
    for payload in records:
        out += struct.pack(">I", len(payload)) + payload
    return bytes(out)


def _udp_handle(data: bytes) -> bytes | None:
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
        total = store_record(key, record_id, payload)
        # Ack: an empty-records response — the peer's put() only needs a nonce-matching datagram to confirm.
        return _udp_response(nonce, [], total)

    if op == OP_GET:
        (since,) = struct.unpack_from(">I", data, pos)
        records, total = contiguous_records(key, since)
        return _udp_response(nonce, records, total)

    return None  # unknown opcode — ignore


def _serve_udp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[rendezvous] UDP keyed-mailbox listening on 0.0.0.0:{port}", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        op = data[0] if data else 0
        print(f"[rendezvous] udp rx {len(data)}B op={op} from {addr}", flush=True)
        try:
            reply = _udp_handle(data)
        except Exception as e:  # never let one malformed datagram kill the relay
            print(f"[rendezvous] drop malformed datagram from {addr}: {e}", flush=True)
            continue
        if reply is not None:
            sock.sendto(reply, addr)


# ── HTTP face (browser lane) ────────────────────────────────────────────────────────────────────────

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class _HttpHandler(BaseHTTPRequestHandler):
    # Quiet the default per-request stderr logging; we print our own concise line instead.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        pass

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:  # CORS preflight
        self.send_response(204)
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/put":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length).decode("utf-8"))
            key = str(req["key"])
            record_id = int(req["id"])
            payload = str(req["payload"]).encode("utf-8")
        except Exception as e:
            self._send_json(400, {"error": f"bad request: {e}"})
            return
        total = store_record(key, record_id, payload)
        print(f"[rendezvous] http PUT key={key!r} id={record_id} ({len(payload)}B) total={total}", flush=True)
        self._send_json(200, {"total": total})

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path != "/poll":
            self._send_json(404, {"error": "not found"})
            return
        qs = parse_qs(url.query)
        key = qs.get("key", [""])[0]
        try:
            since = int(qs.get("since", ["0"])[0])
        except ValueError:
            since = 0
        records, total = contiguous_records(key, since)
        print(f"[rendezvous] http GET  key={key!r} since={since} -> {len(records)} rec (total={total})", flush=True)
        self._send_json(200, {"records": [r.decode("utf-8", "replace") for r in records], "total": total})


def _serve_http(port: int) -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _HttpHandler)
    print(f"[rendezvous] HTTP keyed-mailbox listening on 0.0.0.0:{port}", flush=True)
    httpd.serve_forever()


def main() -> None:
    udp_port = int(os.environ.get("RENDEZVOUS_PORT", "9999"))
    http_port = int(os.environ.get("RENDEZVOUS_HTTP_PORT", "9998"))
    # HTTP on a daemon thread so both faces share this process's `mailboxes`; UDP on the main thread.
    threading.Thread(target=_serve_http, args=(http_port,), daemon=True).start()
    _serve_udp(udp_port)


if __name__ == "__main__":
    main()
