#!/usr/bin/env sh
# Peer container entrypoint: point the default route at this LAN's NAT gateway (so all traffic to coturn
# + rendezvous is NAT'd exactly like the real internet), then exec the native peer binary. The peer reads
# its whole config from WEBRTC_* env (set per-peer in docker-compose from harness.env).
set -eu

# Rewrite the default route to the NAT gateway (requires NET_ADMIN; Docker's default is the bridge gw).
if [ -n "${GATEWAY_IP:-}" ]; then
    ip route replace default via "$GATEWAY_IP"
    echo "[peer] default route via NAT gateway $GATEWAY_IP"
fi
echo "[peer] $(ip -o -4 addr show scope global | awk '{print $2, $4}')"

exec peer
