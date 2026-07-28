// W7 Phase 2(b) interop echo-peer — a real headless **browser** (via Playwright) that establishes a
// WebRTC data channel against our native Kotlin/Native peer and echoes ping→pong. It is the browser
// counterpart of the Pion (Go) lane: an independent, production WebRTC engine that our hand-written ICE +
// DTLS + SCTP + DCEP + SDP stack must interoperate with. Parameterized by the `BROWSER` env:
//
//   * `chromium` — Chromium's libwebrtc (BoringSSL DTLS, libwebrtc ICE, dcSCTP).
//   * `firefox`  — Firefox's stack (NSS DTLS, nICEr ICE, usrsctp) — a *fully independent* second oracle.
//   * `webkit`   — Safari's engine (Playwright's cross-platform WebKit) — a third oracle; emits `.local`
//                  mDNS host candidates (no disable pref), so it connects via coturn srflx/relay.
//
// All negotiate **DTLS 1.3**, so the native offerer runs these lanes at its DEFAULT (WEBRTC_DTLS13 unset).
//
// It runs as the ANSWERER behind a NAT gateway (drop-in for the native answerer `peer_b`): the native
// offerer creates the offer + the "harness" data channel and sends "ping"; this side answers, accepts
// the channel, and echoes "pong". Signaling rides the rendezvous **HTTP face** (rendezvous.py) because
// a browser has no raw UDP — it PUTs/polls the SAME keyed mailbox the native peer reaches over UDP, so
// the two meet in the same slot (offer/answer/cand/*).
//
// The browser's ICE/DTLS/SRTP runs in the engine's native code (not JS), so the raw-UDP limitation
// applies only to signaling: the media/ICE path traverses the real NAT exactly like Pion's. Host-candidate
// mDNS obfuscation is disabled (Chrome flag / Firefox pref) so our peer is fed real-IP candidates, not
// unresolvable `.local` names; srflx/relay carry connectivity across the NATs regardless.
//
// Exit 0 = connected AND a "ping" was received and a "pong" echoed back (then a short linger so SCTP
// reliably delivers the final pong); non-zero = the watchdog fired first. Mirrors the native/Pion exit
// contract so run-interop.sh asserts BOTH sides exit 0.
//
// Semantics mode (WEBRTC_SEMANTICS=1, see docs/DC_SEMANTICS_INTEROP_DESIGN.md): the page becomes a
// universal REFLECTOR — every channel, every message, echoed back verbatim on the channel it arrived on —
// and the run ends on the offerer's explicit DONE handshake rather than a timer. The browser is exactly
// why the reflector is dumb: nothing beyond the W3C RTCDataChannel API can be injected here, so all of the
// semantics matrix (fragmentation, unordered, partial reliability, multiplexing) is driven and asserted by
// the offerer, and this side only has to echo and REPORT (the `dc-negotiated:` line below is the
// end-to-end proof that our DCEP channel types were honored).
//
// Renegotiation (issue #71): the page also RE-ANSWERS. A second offer in the mailbox means the offerer
// restarted ICE (RFC 8445 §9) after the harness moved it onto another carrier, and the page answers it on
// the same RTCPeerConnection — which is what the `restart-<engine>` lanes exist to prove a production
// browser engine does. Still no scenario logic: the round is read off the mailbox, not signalled, so a lane
// that never restarts never reaches the code.
//
// Diagnostics: on every run (pass OR fail) it logs the engine's own `getStats()` — a 2s-cadence + per-edge
// timeline (`getStats-timeline:`) plus a readable digest (`stats-summary:`) — and rich per-message /
// per-channel accounting (negotiated ordered/maxRetransmits, size, running count, bufferedAmount). All of it
// rides the page-console → node-stdout → container-log path that collect_diagnostics captures into the
// failure bundle as <browser>.log, so a red semantics lane is root-caused from the browser's OWN counters
// (bytes/messages/retransmits, selected pair + RTT, DTLS state) rather than inferred from a pcap.

import http from 'node:http';
import { chromium, firefox, webkit } from 'playwright';

function env(name, def) {
  const v = process.env[name];
  return v !== undefined && v !== '' ? v : def;
}
function envInt(name, def) {
  const n = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(n) ? n : def;
}

const BROWSER = env('BROWSER', 'chromium').toLowerCase();

// A bare IPv6 literal must be bracketed inside a URL authority (RFC 3986) — `stun:[fd00::10]:3478`,
// `http://[fd00::11]:9998`. On v6-only lanes the harness passes coturn / rendezvous as bare v6 literals;
// unbracketed, the browser reads the address' own colons as the port and `new RTCPeerConnection` throws
// `ICE server parsing failed: Invalid port`. Hostnames ("coturn") and v4 literals have no ':' → passthrough.
const brk = (h) => (h.includes(':') ? `[${h}]` : h);

const cfg = {
  session: env('WEBRTC_SESSION', 'harness'),
  localIP: env('WEBRTC_LOCAL_IP', ''),
  base: `http://${brk(env('WEBRTC_RENDEZVOUS_HOST', 'rendezvous'))}:${envInt('WEBRTC_RENDEZVOUS_HTTP_PORT', 9998)}`,
  stunHost: brk(env('WEBRTC_STUN_HOST', 'coturn')),
  stunPort: envInt('WEBRTC_STUN_PORT', 3478),
  turnHost: brk(env('WEBRTC_TURN_HOST', 'coturn')),
  turnPort: envInt('WEBRTC_TURN_PORT', 3478),
  turnUser: env('WEBRTC_TURN_USER', 'webrtc'),
  turnPass: env('WEBRTC_TURN_PASS', 'webrtc'),
  icePolicy: env('WEBRTC_ICE_POLICY', 'all').toLowerCase(),
  timeoutMs: envInt('WEBRTC_TIMEOUT_MS', 45000),
  browser: BROWSER,
  // mDNS host-candidate obfuscation. OFF by default (the NAT lanes want real-IP host candidates our peer
  // can resolve). The same-LAN mdns lane sets WEBRTC_MDNS_OBFUSCATE=1 so the browser emits obfuscated
  // `.local` host candidates and our MulticastMdnsResolver resolves them over multicast on the shared L2.
  mdnsObfuscate: env('WEBRTC_MDNS_OBFUSCATE', '0') === '1',
  // Data-channel semantics mode (docs/DC_SEMANTICS_INTEROP_DESIGN.md): reflect every channel until the
  // offerer's explicit DONE instead of exiting a few seconds after the ping echo, which would tear the
  // association down mid-sequence. Set by run-interop.sh for every lane; off leaves the historical
  // establish-and-echo behaviour byte-identical.
  semantics: env('WEBRTC_SEMANTICS', '0') === '1' || env('WEBRTC_SEMANTICS', '').toLowerCase() === 'true',
  semanticsTimeoutMs: envInt('WEBRTC_SEMANTICS_TIMEOUT_MS', 120000),
};

// The answerer, evaluated INSIDE the browser page (this function is serialized and run in the browser,
// so it may reference only its `cfg` argument + browser globals — RTCPeerConnection, fetch, TextDecoder).
// It is engine-agnostic: standard W3C APIs, identical for Chromium and Firefox.
async function answererInPage(cfg) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const keyFor = (slot) => `${cfg.session}/${slot}`;
  const log = (...a) => console.log(`[${cfg.browser}]`, ...a);

  const put = async (slot, id, payload) => {
    try {
      await fetch(cfg.base + '/put', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: keyFor(slot), id, payload }),
      });
    } catch (e) {
      log('put error', slot, e.message);
    }
  };
  const poll = async (slot, since) => {
    try {
      const r = await fetch(cfg.base + `/poll?key=${encodeURIComponent(keyFor(slot))}&since=${since}`);
      const j = await r.json();
      return j.records || [];
    } catch (e) {
      log('poll error', slot, e.message);
      return [];
    }
  };

  const iceServers = [{ urls: `stun:${cfg.stunHost}:${cfg.stunPort}` }];
  iceServers.push({
    urls: `turn:${cfg.turnHost}:${cfg.turnPort}?transport=udp`,
    username: cfg.turnUser,
    credential: cfg.turnPass,
  });
  const pcCfg = { iceServers };
  if (cfg.icePolicy === 'relay') pcCfg.iceTransportPolicy = 'relay';
  log(`role=answerer session=${cfg.session} policy=${cfg.icePolicy} local=${cfg.localIP} dtls=1.3`);

  const pc = new RTCPeerConnection(pcCfg);
  // In semantics mode the watchdog additionally has to cover the offerer's whole phase sequence, which
  // runs after phase 0's ping/pong. A bound, not a budget — the run ends on DONE, not on the clock.
  const deadline = Date.now() + cfg.timeoutMs + (cfg.semantics ? cfg.semanticsTimeoutMs : 0);

  let echoed = false;
  let sawDone = false;
  let failReason = null;
  let resolveDone;
  const done = new Promise((res) => (resolveDone = res));

  // getStats() diagnostics — the browser engine's OWN accounting (bytes/messages per data channel,
  // retransmits, bufferedAmount, the selected candidate pair + RTT, DTLS/SCTP transport state). For the
  // semantics lanes (large/fragmented, unordered, partial-reliable) this is the ground truth that a pcap can
  // only infer. Sampled on a 2s cadence PLUS at each lifecycle edge into a timeline, dumped as one JSON blob
  // at teardown so it rides the captured container log → the failure bundle (collect_diagnostics greps the
  // <browser>.log). RTCStatsReport is a Map; we keep only the types that matter and flatten to plain objects.
  const startT = Date.now();
  const statsTimeline = [];
  const STATS_TYPES = ['transport', 'sctp-transport', 'candidate-pair', 'local-candidate',
    'remote-candidate', 'data-channel', 'peer-connection'];
  const snapshotStats = async (tag) => {
    const snap = { tag, tMs: Date.now() - startT, entries: [] };
    try {
      const report = await pc.getStats();
      report.forEach((s) => { if (STATS_TYPES.includes(s.type)) snap.entries.push(s); });
    } catch (e) {
      snap.error = e && e.message ? e.message : String(e);
    }
    statsTimeline.push(snap);
    return snap;
  };
  // A compact, human-first digest of the FINAL snapshot: the selected pair + RTT, transport DTLS state, and
  // per-channel message/byte counters. Returned in the result (a readable backstop if the full timeline log
  // line is ever truncated) and logged on its own line. Firefox marks the winning pair `selected`, Chrome
  // `nominated`+`succeeded` — accept either.
  const summarizeStats = (snap) => {
    if (!snap) return null;
    const out = { tMs: snap.tMs, selectedPair: null, transport: null, dataChannels: [] };
    for (const s of snap.entries) {
      if (s.type === 'candidate-pair' && (s.nominated || s.selected || s.state === 'succeeded')) {
        out.selectedPair = {
          state: s.state, nominated: s.nominated,
          rttMs: s.currentRoundTripTime != null ? Math.round(s.currentRoundTripTime * 1000) : null,
          bytesSent: s.bytesSent, bytesReceived: s.bytesReceived,
        };
      }
      if (s.type === 'transport') {
        out.transport = {
          dtlsState: s.dtlsState, tlsVersion: s.tlsVersion, dtlsCipher: s.dtlsCipher,
          bytesSent: s.bytesSent, bytesReceived: s.bytesReceived,
        };
      }
      if (s.type === 'data-channel') {
        out.dataChannels.push({
          label: s.label, state: s.state,
          messagesSent: s.messagesSent, messagesReceived: s.messagesReceived,
          bytesSent: s.bytesSent, bytesReceived: s.bytesReceived,
        });
      }
    }
    return out;
  };
  const statsTimer = setInterval(() => { snapshotStats('periodic'); }, 2000);

  pc.oniceconnectionstatechange = () => log('ice state:', pc.iceConnectionState);
  // Gathering visibility: which local candidates the engine actually produced, and — via the
  // icecandidateerror event — every STUN/TURN server it FAILED to reach (url + STUN error code). This is
  // what distinguishes "the engine gathered nothing at all" from "it tried the relay and the relay rejected
  // it" when a lane yields zero remote candidates (e.g. a browser on a pure-v6 stack).
  pc.onicegatheringstatechange = () => log('ice gathering state:', pc.iceGatheringState);
  pc.onicecandidateerror = (e) =>
    log(`icecandidateerror: url=${e.url} code=${e.errorCode} text=${JSON.stringify(e.errorText)} host=${e.hostCandidate ?? '-'}`);
  pc.onconnectionstatechange = () => {
    log('connection state:', pc.connectionState);
    if (pc.connectionState === 'connected') { log('CONNECTED'); snapshotStats('connected'); }
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      failReason = 'connectionState=' + pc.connectionState;
      snapshotStats('failed');
      resolveDone();
    }
  };

  // The universal REFLECTOR (docs/DC_SEMANTICS_INTEROP_DESIGN.md §4): for EVERY channel the offerer opens,
  // echo EVERY message back on that same channel, verbatim — same bytes, same string/binary type. Nothing
  // here is scenario-aware: the label is logged, never branched on. The browser is precisely why the design
  // works this way — we cannot inject behaviour past the W3C API here, so the answerer must be dumb and
  // every scenario decision and assertion must live on the offerer side, in our Kotlin.
  //
  // The ONE historical exception is the liveness ritual: "ping" is echoed as the string "pong" (the native
  // side decodes it with .text()), so phase 0 is bit-for-bit the test these lanes have always run.
  pc.ondatachannel = (ev) => {
    const dc = ev.channel;
    dc.binaryType = 'arraybuffer';
    // Negotiated DCEP properties — proof the browser honored our DATA_CHANNEL_OPEN. For the semantics
    // phases these ARE the assertion surface, and run-interop.sh greps exactly this line: s2/unordered must
    // show ordered=false, s3/rexmit maxRetransmits=0, s3/timed a finite maxPacketLifeTime. (Phase 0's
    // control channel: ordered=true, both unset = reliable.) An unset value renders as "-", the same shape
    // the Pion and werift reflectors print, so one grep works across every answerer family.
    const show = (v) => (v === undefined || v === null ? '-' : String(v));
    log('dc-negotiated:', 'label=' + JSON.stringify(dc.label), 'id=' + dc.id,
        'ordered=' + show(dc.ordered), 'maxRetransmits=' + show(dc.maxRetransmits),
        'maxPacketLifeTime=' + show(dc.maxPacketLifeTime), 'protocol=' + JSON.stringify(dc.protocol),
        'negotiated=' + dc.negotiated);
    dc.onopen = () => { log('dc open:', JSON.stringify(dc.label), 'readyState=' + dc.readyState); snapshotStats('dc-open'); };
    dc.onclosing = () => log('dc closing:', JSON.stringify(dc.label), 'readyState=' + dc.readyState);
    // Mirror-close: if the offerer closes its half, close ours too (the reflector holds no state past the
    // channel). Since our stack gained RFC 6525 RE-CONFIG this fires MID-SESSION, on the s7 phase, and
    // this `dc close:` line is the browser's own report that its channel closed — the half of s7's proof
    // only the peer can give (run-interop.sh greps it, and the engine's outgoing reset is what hands the
    // stream id back to our side).
    dc.onclose = () => {
      log('dc close:', JSON.stringify(dc.label), 'readyState=' + dc.readyState);
      try { dc.close(); } catch { /* already closed */ }
    };
    dc.onerror = (e) => log('dc error:', JSON.stringify(dc.label), (e && e.error && e.error.message) ? e.error.message : String(e));
    let rxCount = 0;
    let rxBytes = 0;
    dc.onmessage = (m) => {
      const isString = typeof m.data === 'string';
      const size = isString ? m.data.length : m.data.byteLength;
      rxCount += 1;
      rxBytes += size;
      const text = isString ? m.data : new TextDecoder().decode(new Uint8Array(m.data));
      // Per-message accounting (size + running count + bufferedAmount). On the large/fragmented phase this
      // is how we see the reassembled message land intact; on a burst phase, how many arrived and in what
      // order. Only a small payload is echoed verbatim into the log; a big binary is summarized by size.
      log('received on', JSON.stringify(dc.label) + ':', 'size=' + size, 'msg#' + rxCount, 'rxBytes=' + rxBytes,
          'string=' + isString, 'bufferedAmount=' + dc.bufferedAmount,
          size <= 64 ? 'data=' + JSON.stringify(text) : 'data=<' + size + 'B binary>');
      if (text.trim() === 'ping') {
        try {
          dc.send('pong');
          echoed = true;
          log('echoed: "pong" bufferedAmount=' + dc.bufferedAmount);
          // Without the semantics sequence the run is over here, so linger just long enough for SCTP to
          // deliver the final pong (and its SACK) — the native and Pion peers do the same after their send.
          // With it, the run ends on the offerer's explicit DONE instead (below), never on a timer.
          if (!cfg.semantics) setTimeout(() => resolveDone(), 3000);
        } catch (e) {
          log('failed to send pong:', e.message);
        }
        return;
      }
      try {
        // Verbatim echo. `m.data` is already a string or an ArrayBuffer, so passing it straight back
        // preserves both the bytes and the string/binary PPID the message arrived with.
        dc.send(m.data);
      } catch (e) {
        log('failed to echo', size, 'bytes on', JSON.stringify(dc.label) + ':', e.message);
        return;
      }
      // The offerer's completion handshake: once DONE has been echoed the run is over and we may tear
      // down. This replaces the old "linger N seconds after the pong" race with an explicit agreement.
      if (text.trim() === 'DONE') {
        log('DONE echoed — the offerer signalled the run is complete');
        sawDone = true;
        snapshotStats('done');
        // Brief linger so the DONE echo is delivered and the offerer's graceful association SHUTDOWN
        // (RFC 4960 §9.2) is received and answered — the browser's own transport state at teardown is the
        // clean-close evidence for s6.
        setTimeout(() => resolveDone(), 3000);
      }
    };
  };

  // Trickle our local candidates out as gathered. Registered before setLocalDescription so none is missed.
  let candOutId = 0;
  pc.onicecandidate = (ev) => {
    if (!ev.candidate) { log('local candidate: <end-of-candidates>'); return; } // native side uses ICE consent, not this signal
    log('local candidate:', ev.candidate.candidate);
    put('cand/answerer', candOutId++, ev.candidate.candidate);
  };

  // The first offer/answer round that can only be an ICE restart. Round 0 negotiates the session; the
  // offerer's s8 phase publishes round 1 after the harness moves it onto a second carrier. Both peers key
  // their mailbox records by the same round, so the two halves line up without either announcing anything.
  const FIRST_RESTART_ROUND = 1;

  // Apply a later round's offer and publish the answer under the SAME record id, so both peers' rounds line
  // up in the mailbox. Deliberately the same three calls as round 0: a restart is a renegotiation of the
  // existing session, not a second session. Returns false — leaving the round unconsumed so the next poll
  // retries it — if the engine rejected the offer, since a half-applied round is worse than a retried one.
  const reanswer = async (offer, round) => {
    try {
      await pc.setRemoteDescription({ type: 'offer', sdp: offer });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await put('answer', round, pc.localDescription.sdp);
    } catch (e) {
      log(`FAILED to re-answer round ${round}:`, e.message);
      return false;
    }
    // The line run-interop.sh greps on the restart lanes: this peer's OWN report that it re-answered, which
    // is the half of the proof only the answerer can give. Every reflector family prints the same token.
    log(`re-answered round ${round} — the offerer restarted ICE`);
    snapshotStats('reanswered');
    return true;
  };

  // 1. Await the offer (bounded by the watchdog), then set it as the remote description.
  let offer = null;
  while (Date.now() < deadline) {
    const recs = await poll('offer', 0);
    if (recs.length) { offer = recs[0]; break; }
    await sleep(200);
  }
  if (!offer) return { ok: false, reason: 'timeout waiting for offer' };
  await pc.setRemoteDescription({ type: 'offer', sdp: offer });

  // 2. Answer, set it locally (starts gathering + trickle), and publish it.
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await put('answer', 0, pc.localDescription.sdp);
  log('answer published');

  // 3. Poll the offerer's trickled candidates → addIceCandidate (single m-line, sdpMLineIndex 0), and any
  //    LATER round's offer → re-answer.
  //
  //    The loop runs to the deadline, NOT to `echoed` as it once did. Stopping at the first echo was
  //    harmless while a session only ever negotiated once — every candidate that mattered had already
  //    arrived — but it starves an ICE RESTART: the offerer's re-gathered generation trickles its
  //    candidates long after phase 0's ping/pong, and a browser that stopped polling would answer the
  //    restart offer and then never learn where to send.
  (async () => {
    let seen = 0;
    let round = FIRST_RESTART_ROUND;
    while (Date.now() < deadline && !sawDone) {
      // A further offer means the offerer restarted ICE (RFC 8445 §9 — its s8 phase): re-answer it on the
      // SAME RTCPeerConnection. A restart renegotiates ICE and nothing else, so the DTLS association and
      // every open data channel are untouched, and this side has nothing to do beyond answering again
      // (RFC 8842 §5.5). Failing to re-answer would leave the offerer's restart unconverged.
      const offers = await poll('offer', round);
      if (offers.length && (await reanswer(offers[0], round))) round++;
      const cands = await poll('cand/offerer', seen);
      for (const c of cands) {
        try {
          await pc.addIceCandidate({ candidate: c, sdpMLineIndex: 0 });
        } catch (e) {
          log('addIceCandidate error:', e.message);
        }
      }
      seen += cands.length;
      await sleep(200);
    }
  })();

  // 4. Wait for connected+echoed (echo arms a 3s linger→resolve), or a typed failure / watchdog.
  const watchdog = setTimeout(() => resolveDone(), Math.max(0, deadline - Date.now()));
  await done;
  clearTimeout(watchdog);
  clearInterval(statsTimer);

  // Final snapshot + full timeline dump — on BOTH success and failure, so a red lane always carries the
  // engine's own view of what happened (the whole point of this instrumentation). The timeline is one JSON
  // line (greppable as `getStats-timeline:` in the <browser>.log); the summary is a readable digest.
  await snapshotStats('final');
  log('getStats-timeline:', JSON.stringify(statsTimeline));
  const statsSummary = summarizeStats(statsTimeline[statsTimeline.length - 1]);
  log('stats-summary:', JSON.stringify(statsSummary));

  try { pc.close(); } catch { /* ignore */ }
  // Exit contract, mirroring the native/Pion/werift peers: established + echoed, and — in semantics mode —
  // the offerer's DONE handshake. Ending on DONE (not a timer) is what keeps the association alive for the
  // whole phase sequence.
  if (echoed && (!cfg.semantics || sawDone)) return { ok: true, done: sawDone, state: pc.connectionState, stats: statsSummary };
  if (echoed && cfg.semantics) {
    return { ok: false, reason: "echoed the ping but the offerer's DONE never arrived", state: pc.connectionState, stats: statsSummary };
  }
  if (failReason) return { ok: false, reason: failReason, state: pc.connectionState, stats: statsSummary };
  return { ok: false, reason: 'no ping/echo before deadline', state: pc.connectionState, stats: statsSummary };
}

// Per-engine launch config. The in-page answerer is identical; only how we start the browser differs.
function launcher() {
  if (cfg.browser === 'firefox') {
    return {
      type: firefox,
      options: {
        headless: true,
        firefoxUserPrefs: {
          // NAT lanes: false → real-IP host candidates our peer resolves directly. The same-LAN mdns lane
          // sets true → obfuscated `.local` host candidates our MulticastMdnsResolver resolves for real.
          'media.peerconnection.ice.obfuscate_host_addresses': cfg.mdnsObfuscate,
        },
      },
    };
  }
  if (cfg.browser === 'webkit') {
    // WebKit is Safari's engine (via Playwright's cross-platform build) — a THIRD independent stack
    // (libwebrtc-derived but Apple's fork + its own build). Unlike Chrome/Firefox it exposes NO pref to
    // disable mDNS host-candidate obfuscation, so it emits `.local` host candidates our peer can't
    // resolve — connectivity therefore rides the coturn **srflx/relay** candidates across the NATs (our
    // ICE agent skips the unresolvable `.local` hosts; srflx/relay carry it, as the native lanes note).
    return { type: webkit, options: { headless: true } };
  }
  // chromium (default)
  const chromeArgs = ['--no-sandbox', '--disable-dev-shm-usage'];
  // NAT lanes: disable Chromium's default mDNS host-candidate hiding so it emits real-IP host candidates
  // our peer resolves directly. The same-LAN mdns lane omits this flag → Chromium KEEPS its default `.local`
  // obfuscation, and our MulticastMdnsResolver resolves those candidates for real over the shared L2.
  if (!cfg.mdnsObfuscate) {
    chromeArgs.push('--disable-features=WebRtcHideLocalIpsWithMdns');
  }
  return {
    type: chromium,
    options: { headless: true, args: chromeArgs },
  };
}

async function main() {
  // A trivial local page so the answerer runs in a real (secure-context) origin — localhost is
  // "potentially trustworthy", which keeps WebRTC + fetch unrestricted; signaling fetch()es are
  // cross-origin to the rendezvous, which answers with CORS `*`.
  const server = http.createServer((_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><meta charset="utf-8"><title>browser-interop</title>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const { type, options } = launcher();
  const browser = await type.launch(options);

  let result;
  try {
    const page = await browser.newPage();
    page.on('console', (m) => console.log(m.text()));
    page.on('pageerror', (e) => console.log(`[${cfg.browser}:pageerror]`, e.message));
    await page.goto(`http://127.0.0.1:${port}/`);
    // Node-side hard guard: the in-page deadline should resolve first; this only fires if the page hangs.
    result = await Promise.race([
      page.evaluate(answererInPage, cfg),
      new Promise((res) =>
        setTimeout(
          () => res({ ok: false, reason: 'node watchdog: page hung' }),
          cfg.timeoutMs + (cfg.semantics ? cfg.semanticsTimeoutMs : 0) + 15000,
        )),
    ]);
  } finally {
    await browser.close().catch(() => {});
    server.close();
  }

  console.log(`[${cfg.browser}] result:`, JSON.stringify(result));
  if (result && result.ok) {
    console.log(`[${cfg.browser}] exit=0 (established + echoed)`);
    process.exit(0);
  }
  console.log(`[${cfg.browser}] exit=1 (` + (result ? result.reason : 'unknown') + ')');
  process.exit(1);
}

main().catch((e) => {
  console.log(`[${cfg.browser}] FATAL:`, e && e.stack ? e.stack : e);
  process.exit(1);
});
