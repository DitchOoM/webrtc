#!/usr/bin/env sh
# Apply/clear netem impairment on this NAT's public-facing interface — the data path between the peers.
# Invoked by run-interop.sh via `docker compose exec`. Composes with any NAT profile.
#   netem.sh add <netem args…>   e.g. netem.sh add loss 5% delay 20ms 5ms distribution normal
#   netem.sh del
set -eu
WAN=$(ip -o -4 addr show | awk -v ip="$NAT_WAN_IP" '$4 ~ "^"ip"/" {print $2; exit}')
case "${1:-}" in
  add) shift; tc qdisc replace dev "$WAN" root netem "$@"; echo "[netem] $WAN: $*" ;;
  del) tc qdisc del dev "$WAN" root 2>/dev/null || true; echo "[netem] $WAN: cleared" ;;
  *) echo "usage: netem.sh add <args…>|del" >&2; exit 1 ;;
esac
