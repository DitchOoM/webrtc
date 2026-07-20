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
echo "[pion] $(ip -o -4 addr show scope global | awk '{print $2, $4}')"

exec pion-echo
