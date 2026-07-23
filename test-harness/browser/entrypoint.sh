#!/usr/bin/env sh
# Browser interop container entrypoint — the exact mirror of the native/Pion peer entrypoints: point the
# default route at this LAN's NAT gateway (so all traffic to coturn + the rendezvous is NAT'd like the
# real internet), then exec the Playwright driver. Config (incl. BROWSER) comes from env (docker-compose).
set -eu

# Rewrite the default route to the NAT gateway (requires NET_ADMIN; Docker's default is the bridge gw).
# Must happen BEFORE the browser launches so its ICE agent binds/routes through the NAT like a real peer.
if [ -n "${GATEWAY_IP:-}" ]; then
    ip route replace default via "$GATEWAY_IP"
    echo "[${BROWSER:-browser}] default route via NAT gateway $GATEWAY_IP"
fi
# Same for the v6 default route on the dual/v6 lanes (GATEWAY_IP6 = the NAT's LAN v6 address; compose.ipv6.yml
# sets it on the browser services). Without this the browser has no route to the pub subnet and its fetch to
# the rendezvous / STUN to coturn just fail ("Failed to fetch" → page hang). The peer entrypoints already do
# this — the browser one was v4-only, which is why every v6 browser lane hung. Unset on v4.
if [ -n "${GATEWAY_IP6:-}" ]; then
    ip -6 route replace default via "$GATEWAY_IP6"
    echo "[${BROWSER:-browser}] v6 default route via NAT gateway $GATEWAY_IP6"
fi
# Firefox aborts ALL ICE gathering (nICEr "Couldn't gather ICE candidates", error=10 — reproduced) on a
# host with no IPv4 DEFAULT ROUTE, even for its IPv6 candidates: its gather bootstrap does a default-address
# route lookup that fails when there is no v4 route at all. So on the v6-only lane Firefox gathers nothing
# and every firefox⇄peer connection fails — while Chrome/WebKit and our native peer gather + connect fine.
# Give ONLY the Firefox container a non-routable dummy IPv4 (TEST-NET-1, RFC 5737) AND a v4 default route via
# a blackhole next hop, purely to satisfy that route lookup. It adds NO v4 to the data path: there is no v4
# gateway / coturn / rendezvous on this lane, the next hop 192.0.2.1 does not exist, so the v4 host candidate
# is unreachable and never selected — ICE still establishes over PURE v6 (verified: selected pair is the
# fd00:32::100 v6 host). An IPv4 address ALONE does not fix it; the default ROUTE is the operative part.
# v6-only ⇔ GATEWAY_IP unset (compose.v6only.yml clears it) while GATEWAY_IP6 is set. FIREFOX_V4_SHIM is the
# caller-side kill switch (default 1 = on; set 0 to disable and observe the raw Firefox v6-only failure).
if [ "${FIREFOX_V4_SHIM:-1}" = "1" ] && [ "${BROWSER:-}" = "firefox" ] && [ -z "${GATEWAY_IP:-}" ] && [ -n "${GATEWAY_IP6:-}" ]; then
    if ip addr add 192.0.2.99/24 dev eth0 2>/dev/null; then
        ip route add default via 192.0.2.1 dev eth0 metric 4096 2>/dev/null || true
        echo "[firefox] added non-routable dummy IPv4 192.0.2.99/24 + v4 default (v6-only ICE-gather bootstrap; no v4 data path)"
    fi
fi

echo "[${BROWSER:-browser}] $(ip -o -4 addr show scope global | awk '{print $2, $4}')"

exec node driver.mjs
