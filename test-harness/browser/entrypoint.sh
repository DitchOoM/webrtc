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
echo "[${BROWSER:-browser}] $(ip -o -4 addr show scope global | awk '{print $2, $4}')"

exec node driver.mjs
