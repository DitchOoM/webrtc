#!/usr/bin/env sh
# JVM peer container entrypoint: point the default route at this LAN's NAT gateway (so all traffic to
# coturn + rendezvous is NAT'd exactly like the real internet), then exec the JVM peer. It reads its whole
# config from WEBRTC_* env (set per-peer in docker-compose from harness.env) — the SAME peer program as the
# native binary, just on the JVM (socket-udp's NIO datapath instead of io_uring, so no seccomp=unconfined).
set -eu

# Rewrite the default route to the NAT gateway (requires NET_ADMIN; Docker's default is the bridge gw).
if [ -n "${GATEWAY_IP:-}" ]; then
    ip route replace default via "$GATEWAY_IP"
    echo "[peer-jvm] default route via NAT gateway $GATEWAY_IP"
fi
# Same for the v6 default route on the dual/v6 lanes (GATEWAY_IP6 = the NAT's LAN v6 address). Unset on v4.
if [ -n "${GATEWAY_IP6:-}" ]; then
    ip -6 route replace default via "$GATEWAY_IP6"
    echo "[peer-jvm] v6 default route via NAT gateway $GATEWAY_IP6"
fi
echo "[peer-jvm] $(ip -o addr show scope global | awk '{print $2, $4}')"

exec java -jar /usr/local/lib/peer.jar
