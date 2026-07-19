#!/usr/bin/env sh
# Install one RFC 4787 NAT profile, then stay alive as the LAN's gateway.
#
# Env (from docker-compose): NAT_PROFILE, NAT_WAN_IP, NAT_LAN_IP, PEER_IP, ICE_PORT.
# The container has one interface on the public net (NAT_WAN_IP) and one on the peer's LAN (NAT_LAN_IP);
# we locate each by its address (Docker's eth0/eth1 ordering isn't stable).
#
# ── RFC 4787 fidelity (honest) ────────────────────────────────────────────────────────────────────
# A NAT profile = a (mapping behavior, filtering behavior) pair. What stock netfilter models:
#   port-restricted cone : EIM mapping (MASQUERADE preserves the source port) + Address+Port-dependent
#                          filtering (conntrack return only). FAITHFUL.
#   symmetric            : Endpoint-DEPENDENT mapping (MASQUERADE --random-fully → different external port
#                          per destination, so a peer's coturn-learned srflx is useless to the other peer
#                          → forces the TURN relay) + Address+Port filtering. FAITHFUL.
#   address-restricted   : EIM mapping + Address-dependent (any port) filtering, modeled with the `recent`
#                          module (record dest IPs on egress, allow return from those IPs on any port).
#                          FAITHFUL for the WebRTC hole-punch; `recent` is coarser than true per-flow NAT
#                          state, noted.
#   full-cone            : EIM mapping + Endpoint-INDEPENDENT filtering, modeled for the fixed ICE_PORT:
#                          MASQUERADE preserves the port, a static DNAT forwards inbound UDP on that port
#                          to the peer from ANY source. FAITHFUL for the one port that matters to ICE.
set -eu

WAN=$(ip -o -4 addr show | awk -v ip="$NAT_WAN_IP" '$4 ~ "^"ip"/" {print $2; exit}')
LAN=$(ip -o -4 addr show | awk -v ip="$NAT_LAN_IP" '$4 ~ "^"ip"/" {print $2; exit}')
[ -n "$WAN" ] && [ -n "$LAN" ] || { echo "[nat] could not resolve WAN/LAN ifaces (wan=$NAT_WAN_IP lan=$NAT_LAN_IP)" >&2; ip -o -4 addr show >&2; exit 1; }
echo "[nat] profile=$NAT_PROFILE WAN=$WAN($NAT_WAN_IP) LAN=$LAN($NAT_LAN_IP) peer=$PEER_IP ice=$ICE_PORT"

iptables -F
iptables -t nat -F
iptables -P FORWARD DROP

# Baseline: the LAN may initiate outbound; return traffic for those flows is allowed by conntrack. That
# alone is Address+Port-dependent (port-restricted) filtering — each profile below adjusts from here.
iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
iptables -A FORWARD -i "$WAN" -o "$LAN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

case "$NAT_PROFILE" in
  port-restricted)
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
    ;;
  symmetric)
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE --random-fully
    ;;
  address-restricted)
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
    # Record every destination IP the LAN sends to, then allow inbound UDP from those IPs on ANY port.
    # The `--set` rule MUST run before the baseline `-i LAN -o WAN -j ACCEPT` (line 35) — that ACCEPT is
    # terminating, so an APPENDED `--set` would never execute and the `recent` list would stay empty,
    # silently degrading this profile to port-restricted. Insert the recorder at the head of FORWARD
    # (before the baseline ACCEPT); it has no `-j`, so it records and falls through to the ACCEPT.
    iptables -I FORWARD 1 -i "$LAN" -o "$WAN" -m recent --name seen --rdest --set
    iptables -A FORWARD -i "$WAN" -o "$LAN" -p udp -m recent --name seen --rsource --rcheck --seconds 120 -j ACCEPT
    ;;
  full-cone)
    iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
    # Endpoint-independent: forward inbound UDP on the mapped ICE port to the peer from any source.
    iptables -t nat -A PREROUTING -i "$WAN" -p udp --dport "$ICE_PORT" -j DNAT --to-destination "$PEER_IP:$ICE_PORT"
    iptables -A FORWARD -i "$WAN" -o "$LAN" -p udp -d "$PEER_IP" --dport "$ICE_PORT" -j ACCEPT
    ;;
  *)
    echo "[nat] unknown NAT_PROFILE='$NAT_PROFILE' (want: port-restricted|address-restricted|full-cone|symmetric)" >&2
    exit 1
    ;;
esac

echo "[nat] nat table:"; iptables -t nat -S
echo "[nat] filter table:"; iptables -S
exec sleep infinity
