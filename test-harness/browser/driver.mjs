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

const cfg = {
  session: env('WEBRTC_SESSION', 'harness'),
  localIP: env('WEBRTC_LOCAL_IP', ''),
  base: `http://${env('WEBRTC_RENDEZVOUS_HOST', 'rendezvous')}:${envInt('WEBRTC_RENDEZVOUS_HTTP_PORT', 9998)}`,
  stunHost: env('WEBRTC_STUN_HOST', 'coturn'),
  stunPort: envInt('WEBRTC_STUN_PORT', 3478),
  turnHost: env('WEBRTC_TURN_HOST', 'coturn'),
  turnPort: envInt('WEBRTC_TURN_PORT', 3478),
  turnUser: env('WEBRTC_TURN_USER', 'webrtc'),
  turnPass: env('WEBRTC_TURN_PASS', 'webrtc'),
  icePolicy: env('WEBRTC_ICE_POLICY', 'all').toLowerCase(),
  timeoutMs: envInt('WEBRTC_TIMEOUT_MS', 45000),
  browser: BROWSER,
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
  const deadline = Date.now() + cfg.timeoutMs;

  let echoed = false;
  let failReason = null;
  let resolveDone;
  const done = new Promise((res) => (resolveDone = res));

  pc.oniceconnectionstatechange = () => log('ice state:', pc.iceConnectionState);
  pc.onconnectionstatechange = () => {
    log('connection state:', pc.connectionState);
    if (pc.connectionState === 'connected') log('CONNECTED');
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      failReason = 'connectionState=' + pc.connectionState;
      resolveDone();
    }
  };

  // The native offerer opens a DCEP channel labelled "harness" and sends "ping" (a binary-PPID message
  // — its text helper isn't WebRTC-string-typed), so accept both binary and string, decode, and echo a
  // string "pong" (which the native side decodes with .text()).
  pc.ondatachannel = (ev) => {
    const dc = ev.channel;
    dc.binaryType = 'arraybuffer';
    log('incoming data channel:', JSON.stringify(dc.label), 'id=', dc.id);
    dc.onmessage = (m) => {
      const text = typeof m.data === 'string' ? m.data : new TextDecoder().decode(new Uint8Array(m.data));
      log('received:', JSON.stringify(text), '(string=' + (typeof m.data === 'string') + ')');
      if (text.trim() === 'ping') {
        try {
          dc.send('pong');
          echoed = true;
          log('echoed: "pong"');
          // Linger so SCTP reliably delivers the final pong (and its SACK) before teardown — the native
          // and Pion peers do the same after their send. Bounded and well under the offerer's echo timeout.
          setTimeout(() => resolveDone(), 3000);
        } catch (e) {
          log('failed to send pong:', e.message);
        }
      }
    };
  };

  // Trickle our local candidates out as gathered. Registered before setLocalDescription so none is missed.
  let candOutId = 0;
  pc.onicecandidate = (ev) => {
    if (!ev.candidate) return; // end-of-candidates; the native side uses ICE consent, not this signal
    put('cand/answerer', candOutId++, ev.candidate.candidate);
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

  // 3. Poll the offerer's trickled candidates → addIceCandidate (single m-line, sdpMLineIndex 0).
  (async () => {
    let seen = 0;
    while (Date.now() < deadline && !echoed) {
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

  try { pc.close(); } catch { /* ignore */ }
  if (echoed) return { ok: true, state: pc.connectionState };
  if (failReason) return { ok: false, reason: failReason, state: pc.connectionState };
  return { ok: false, reason: 'no ping/echo before deadline', state: pc.connectionState };
}

// Per-engine launch config. The in-page answerer is identical; only how we start the browser differs.
function launcher() {
  if (cfg.browser === 'firefox') {
    return {
      type: firefox,
      options: {
        headless: true,
        firefoxUserPrefs: {
          // Emit real-IP host candidates (not obfuscated `.local` mDNS names our peer can't resolve).
          'media.peerconnection.ice.obfuscate_host_addresses': false,
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
  return {
    type: chromium,
    options: {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-features=WebRtcHideLocalIpsWithMdns',
      ],
    },
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
      new Promise((res) => setTimeout(() => res({ ok: false, reason: 'node watchdog: page hung' }), cfg.timeoutMs + 15000)),
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
