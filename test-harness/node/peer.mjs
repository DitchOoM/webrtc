// node-echo is the W7 Phase-2(a) interop **echo-peer** running the pure-TypeScript **werift** WebRTC
// stack: a real, independent JavaScript-engine WebRTC endpoint that establishes a data channel against
// our native Kotlin/Native (or JVM) peer and echoes ping→pong. It is a third-family differential oracle
// alongside Pion (Go) and the browsers — proving our hand-written ICE + DTLS + SCTP + DCEP + SDP stack
// interoperates with yet another independent implementation. This file is a faithful port of
// pion/main.go: same env contract, same rendezvous wire protocol (signaling.mjs), same exit contract.
//
// It runs as the ANSWERER behind a NAT gateway (drop-in for the native answerer `peer_b`): it reads the
// same `WEBRTC_*` env the compose harness sets, gathers host/srflx/relay candidates from the same real
// coturn, and exchanges offer/answer/candidates over the same UDP rendezvous mailbox (see signaling.mjs).
//
// DTLS: werift speaks DTLS **1.2 only** — confirmed in werift-dtls: its record-layer ProtocolVersion is
// `{ major: 254, minor: 253 }` (= 0xFEFD = DTLS 1.2) in packages/dtls/src/context/dtls.ts, and it ships
// only the classic 6-flight 1.2 handshake (client flights 1/3/5, server flights 2/4/6) with no DTLS 1.3
// flights. So — exactly like the Pion lane — the native/JVM offerer runs this lane with
// `WEBRTC_DTLS13=false` (its 1.2 fallback), and version negotiation meets at 1.2. (Even were that ever to
// change, pinning 1.2 is the conservative choice and matches the Pion precedent.)
//
// Exit 0 = ICE/DTLS connected AND a "ping" was received and a "pong" echoed back; non-zero = the
// watchdog fired first (never established, or no ping) — mirroring the native peer's exit contract so
// run-interop.sh asserts BOTH sides exit 0.

import { RTCPeerConnection } from "werift";
import { openSignaling } from "./signaling.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const cfg = configFromEnv();
  console.log(
    `[node] role=answerer session=${cfg.session} policy=${cfg.icePolicy} local=${cfg.localIP} dtls=1.2(werift)`,
  );

  // Overall watchdog: a bound, not a wall-clock budget — establish + reliable echo under a NAT/impaired
  // path is legitimately slower than a clean path (directive #4).
  const deadline = Date.now() + cfg.timeoutMs;

  const pc = newPeerConnection(cfg);

  // Observable state, flipped from werift's event callbacks (booleans polled by the watchdog waiters).
  let connected = false;
  let failed = false;
  let echoed = false;

  // werift uses an Observable-style `.subscribe()` for events (not addEventListener). connectionState
  // values: "new"|"connecting"|"connected"|"disconnected"|"failed"|"closed".
  pc.connectionStateChange.subscribe((s) => {
    console.log(`[node] connection state: ${s}`);
    if (s === "connected") connected = true;
    else if (s === "failed" || s === "closed") failed = true;
  });

  // The native offerer creates a DCEP data channel labelled "harness" and sends "ping"; we accept it and
  // echo "pong" as a STRING message. werift's `channel.send(string)` uses the WebRTC string PPID
  // (WEBRTC_STRING) — the native side decodes it with .text() — while a Buffer would send the binary PPID.
  pc.onDataChannel.subscribe((dc) => {
    console.log(`[node] incoming data channel: label=${JSON.stringify(dc.label)} id=${dc.id}`);
    dc.onMessage.subscribe((data) => {
      // werift delivers a string for the string PPID and a Buffer for binary; the native "ping" is a
      // string, so `data` is a JS string here.
      const isString = typeof data === "string";
      const text = isString ? data : data.toString("utf8");
      console.log(`[node] received: ${JSON.stringify(text)} (string=${isString})`);
      if (text.trim() === "ping") {
        try {
          dc.send("pong");
        } catch (e) {
          console.log(`[node] failed to send pong: ${e}`);
          return;
        }
        console.log('[node] echoed: "pong"');
        echoed = true;
      }
    });
  });

  // Two single-consumer signaling sockets (mirrors the native + Pion peers): sigOut for our PUTs (answer +
  // trickled candidates), sigIn for our polls (offer + the offerer's candidates).
  let sigOut;
  let sigIn;
  try {
    sigOut = await openSignaling(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session);
    sigIn = await openSignaling(cfg.rendezvousHost, cfg.rendezvousPort, cfg.session);
  } catch (e) {
    console.log(`[node] FAILED to open signaling: ${e}`);
    return 1;
  }

  // Trickle our local candidates out as they are gathered. Registered BEFORE setLocalDescription so no
  // candidate is missed. werift's `onIceCandidate` emits the candidate's `.toJSON()` (or undefined at
  // end-of-candidates); its `.candidate` string is produced by candidateToSdp WITHOUT the leading
  // "candidate:" token (that token is only prepended when serialized into an SDP `a=` line). The native
  // parser expects the `candidate:...` grammar (the same grammar Pion emits), so toCandidateLine() adds
  // the prefix when absent.
  const candOut = [];
  pc.onIceCandidate.subscribe((candidate) => {
    if (!candidate || !candidate.candidate) return; // end-of-candidates; native uses ICE consent, not this
    candOut.push(toCandidateLine(candidate.candidate));
  });

  // 1. Await the offer (bounded by the watchdog), then set it as the remote description.
  const offer = await awaitOffer(sigIn, deadline);
  if (!offer) {
    console.log("[node] TIMEOUT waiting for offer");
    return 1;
  }
  try {
    await pc.setRemoteDescription({ type: "offer", sdp: offer });
  } catch (e) {
    console.log(`[node] FAILED setRemoteDescription(offer): ${e}`);
    return 1;
  }

  // 2. Answer, set it locally (this starts gathering + trickle), and publish it as stored by
  //    setLocalDescription (trickle: no candidates embedded yet).
  let answerSdp;
  try {
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    answerSdp = pc.localDescription.sdp;
  } catch (e) {
    console.log(`[node] FAILED createAnswer/setLocalDescription: ${e}`);
    return 1;
  }
  if (!(await sigOut.put("answer", 0, answerSdp))) {
    console.log("[node] FAILED to publish answer to rendezvous");
    return 1;
  }
  console.log("[node] answer published");

  // 3. Drain trickled local candidates → PUT to cand/answerer (single consumer of sigOut). A background
  //    loop; runs until the deadline, then the process exits and tears it down.
  (async () => {
    let i = 0;
    while (Date.now() < deadline) {
      if (candOut.length > 0) {
        await sigOut.put("cand/answerer", i, candOut.shift());
        i++;
      } else {
        await sleep(50);
      }
    }
  })();

  // 4. Poll the offerer's trickled candidates → addIceCandidate (single consumer of sigIn). The native
  //    side sends bare `candidate:...` strings for a single m-line, so we supply sdpMLineIndex 0; werift's
  //    IceCandidate.fromJSON strips the "candidate:" prefix and resolves the m-section by that index.
  (async () => {
    let seen = 0;
    while (Date.now() < deadline) {
      const cands = await sigIn.poll("cand/offerer", seen);
      for (const c of cands) {
        try {
          await pc.addIceCandidate({ candidate: c, sdpMLineIndex: 0 });
        } catch (e) {
          console.log(`[node] addIceCandidate(${JSON.stringify(c)}) error: ${e}`);
        }
      }
      seen += cands.length;
      await sleep(200);
    }
  })();

  // 5. Wait for connected + echoed (or a typed failure / watchdog).
  if (!(await waitUntil(() => connected, () => failed, deadline))) {
    console.log(`[node] FAILED to establish before deadline (state=${pc.connectionState})`);
    return 1;
  }
  console.log("[node] CONNECTED");

  if (!(await waitUntil(() => echoed, () => false, deadline))) {
    console.log("[node] TIMEOUT waiting to receive ping / echo pong");
    return 1;
  }

  // Linger so SCTP reliably delivers the final "pong" (and its SACK) before teardown — the native peer
  // does the same after its send. Bounded and well under the offerer's echo timeout.
  await sleep(3000);
  console.log("[node] exit=0 (established + echoed)");
  return 0;
}

// awaitOffer polls the `offer` slot until a record appears or the watchdog fires.
async function awaitOffer(sig, deadline) {
  while (Date.now() < deadline) {
    const recs = await sig.poll("offer", 0);
    if (recs.length > 0) return recs[0];
    await sleep(200);
  }
  return "";
}

// waitUntil resolves true when ok() becomes true, false when fail() becomes true or the deadline passes.
// A poll loop (not an event wait) — the state booleans are flipped by werift's callbacks.
async function waitUntil(ok, fail, deadline) {
  while (Date.now() < deadline) {
    if (ok()) return true;
    if (fail()) return false;
    await sleep(50);
  }
  return false;
}

// toCandidateLine brings werift's bare candidate string up to the `candidate:...` grammar the native
// parser (and Pion) use — see the onIceCandidate comment above. A string already carrying the prefix
// (defensive) passes through untouched.
function toCandidateLine(c) {
  return c.startsWith("candidate:") ? c : `candidate:${c}`;
}

// brk brackets a bare IPv6 literal so it's a legal host in a STUN/TURN URI (RFC 7064 → RFC 3986):
// `2001:db8:30::10` must become `[2001:db8:30::10]`, else werift's ICE-server URL parser reads the colons
// as extra port separators and construction fails before ICE even starts. On the v6/dual lanes compose
// passes coturn's bare v6 literal as WEBRTC_STUN/TURN_HOST; a hostname or v4 literal (no colon) passes
// through untouched, so v4 is unaffected.
function brk(host) {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

// newPeerConnection builds a werift RTCPeerConnection pointed at the harness coturn for STUN + TURN,
// honoring the relay-only policy when requested. werift's RTCIceServer shape is { urls, username?,
// credential? } (urls a single string), and iceTransportPolicy is "all" | "relay".
function newPeerConnection(cfg) {
  const config = {
    iceServers: [
      { urls: `stun:${brk(cfg.stunHost)}:${cfg.stunPort}` },
      {
        urls: `turn:${brk(cfg.turnHost)}:${cfg.turnPort}?transport=udp`,
        username: cfg.turnUser,
        credential: cfg.turnPass,
      },
    ],
  };
  if (cfg.icePolicy === "relay") config.iceTransportPolicy = "relay";
  return new RTCPeerConnection(config);
}

// ── config from WEBRTC_* env (the same vars the native + Pion peers read) ──

function configFromEnv() {
  return {
    session: env("WEBRTC_SESSION", "harness"),
    localIP: env("WEBRTC_LOCAL_IP", ""),
    stunHost: env("WEBRTC_STUN_HOST", "coturn"),
    stunPort: envInt("WEBRTC_STUN_PORT", 3478),
    turnHost: env("WEBRTC_TURN_HOST", "coturn"),
    turnPort: envInt("WEBRTC_TURN_PORT", 3478),
    turnUser: env("WEBRTC_TURN_USER", "webrtc"),
    turnPass: env("WEBRTC_TURN_PASS", "webrtc"),
    rendezvousHost: env("WEBRTC_RENDEZVOUS_HOST", "rendezvous"),
    rendezvousPort: envInt("WEBRTC_RENDEZVOUS_PORT", 9999),
    icePolicy: env("WEBRTC_ICE_POLICY", "all").toLowerCase(),
    timeoutMs: envInt("WEBRTC_TIMEOUT_MS", 45000),
  };
}

function env(name, def) {
  const v = process.env[name];
  return v !== undefined && v !== "" ? v : def;
}

function envInt(name, def) {
  const v = process.env[name];
  if (v !== undefined && v !== "") {
    const n = parseInt(v, 10);
    if (!Number.isNaN(n)) return n;
  }
  return def;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.log(`[node] FATAL: ${e && e.stack ? e.stack : e}`);
    process.exit(1);
  });
