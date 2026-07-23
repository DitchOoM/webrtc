#!/usr/bin/env sh
# Pion peer container entrypoint — the exact mirror of the native peer's entrypoint: point the default
# route at this LAN's NAT gateway (so all traffic to coturn + rendezvous is NAT'd like the real internet),
# then exec the Pion echo-peer. It reads its whole config from WEBRTC_* env (set in docker-compose).
set -eu

# Rewrite the default route to the NAT gateway (requires NET_ADMIN; Docker's default is the bridge gw).
if [ -n "${GATEWAY_IP:-}" ]; then
    ip route replace default via "$GATEWAY_IP"
    echo "[pion] default route via NAT gateway $GATEWAY_IP"
fi
# Same for the v6 default route on the dual/v6 lanes (GATEWAY_IP6 = the NAT's LAN v6 address; compose.ipv6.yml
# sets it on pion). Without it pion can't reach coturn/rendezvous over v6 — like the browser lanes, this was
# a v4-only entrypoint (the native + jvm peers already do this). Unset on v4.
if [ -n "${GATEWAY_IP6:-}" ]; then
    ip -6 route replace default via "$GATEWAY_IP6"
    echo "[pion] v6 default route via NAT gateway $GATEWAY_IP6"
fi
echo "[pion] $(ip -o -4 addr show scope global | awk '{print $2, $4}')"

exec pion-echo
