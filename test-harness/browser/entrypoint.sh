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
echo "[${BROWSER:-browser}] $(ip -o -4 addr show scope global | awk '{print $2, $4}')"

exec node driver.mjs
