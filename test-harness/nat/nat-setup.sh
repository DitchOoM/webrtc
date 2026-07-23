#!/usr/bin/env sh
# Install one RFC 4787 NAT profile (v4) and/or a routed-v6 stateful firewall, then stay alive as the LAN's
# gateway.
#
# Env (from docker-compose): NAT_PROFILE, NAT_WAN_IP, NAT_LAN_IP, PEER_IP, ICE_PORT, and — on the dual/v6
# lanes — NAT_WAN_IP6, NAT_LAN_IP6, PEER_IP6. The container has one interface on the public net and one on
# the peer's LAN, each carrying its v4 and (on dual) v6 address; we locate each by its address (Docker's
# eth0/eth1 ordering isn't stable). A family's block installs ONLY when that family's WAN+LAN addresses are
# actually assigned to interfaces — so this same script serves v4-only, dual-stack, and v6-only lanes
# unchanged: on a v4 lane the v6 addresses aren't present (compose.ipv6.yml not layered) and the v6 block is
# skipped; on a v6-only lane (enable_ipv4:false) the v4 block is skipped. At least one family must be present.
#
# ── RFC 4787 fidelity (honest) ────────────────────────────────────────────────────────────────────
# A v4 NAT profile = a (mapping behavior, filtering behavior) pair. What stock netfilter models:
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
#
# ── routed IPv6 (NOT NAT66) ─────────────────────────────────────────────────────────────────────────
# Real dual-stack WebRTC over v6 uses globally/ULA-addressed hosts behind a FILTERING firewall, never NAT66.
# So over v6 this container is a pure ROUTER: no MASQUERADE, addresses pass through unchanged. Only the RFC
# 4787 *filtering* half maps to v6 (the *mapping* half is a v4 address-exhaustion artifact with no v6
# analog) — so exactly the three filtering behaviors carry over: endpoint-independent (full-cone),
# address-dependent (address-restricted, `recent`), and address+port-dependent (port-restricted / the
# stateful baseline). symmetric/cgnat/hairpin/mixed-sym never reach the v6 block (family-skipped upstream);
# any other profile falls back to the stateful baseline.
set -eu

install_v4() {
    WAN=$(ip -o -4 addr show | awk -v ip="$NAT_WAN_IP" '$4 ~ "^"ip"/" {print $2; exit}')
    LAN=$(ip -o -4 addr show | awk -v ip="$NAT_LAN_IP" '$4 ~ "^"ip"/" {print $2; exit}')
    [ -n "$WAN" ] && [ -n "$LAN" ] || { echo "[nat] v4 addresses not both assigned (wan=$NAT_WAN_IP lan=$NAT_LAN_IP) — skipping v4 block"; return 1; }
    echo "[nat] v4 profile=$NAT_PROFILE WAN=$WAN($NAT_WAN_IP) LAN=$LAN($NAT_LAN_IP) peer=$PEER_IP ice=$ICE_PORT"

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
        # The `--set` rule MUST run before the baseline `-i LAN -o WAN -j ACCEPT` (that ACCEPT is
        # terminating, so an APPENDED `--set` would never execute and the `recent` list would stay empty,
        # silently degrading this profile to port-restricted). Insert the recorder at the head of FORWARD
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

    # ── behind-carrier (NAT444 / hairpin) mode — v4 only ──────────────────────────────────────────────
    # When NAT_CARRIER_GW is set, this NAT is a customer CPE sitting BEHIND a carrier-grade NAT rather than
    # on the public net directly: its upstream is the carrier shared space (NAT_CAR_IP interface), and every
    # public destination is reached through the carrier NAT (NAT_CARRIER_GW). This is a SECOND translation on
    # top of the profile above, so a peer's reflexive candidate becomes the CARRIER's public IP (NAT444).
    # The carrier NAT itself runs this same script WITHOUT NAT_CARRIER_GW (it IS the public-facing hop).
    if [ -n "${NAT_CARRIER_GW:-}" ]; then
        CAR=$(ip -o -4 addr show | awk -v ip="$NAT_CAR_IP" '$4 ~ "^"ip"/" {print $2; exit}')
        [ -n "$CAR" ] || { echo "[nat] could not resolve carrier iface (car=$NAT_CAR_IP)" >&2; ip -o -4 addr show >&2; exit 1; }
        # Masquerade the LAN onto the carrier link (the CPE→carrier translation) and forward LAN⇄carrier.
        iptables -t nat -A POSTROUTING -o "$CAR" -j MASQUERADE
        iptables -A FORWARD -i "$LAN" -o "$CAR" -j ACCEPT
        iptables -A FORWARD -i "$CAR" -o "$LAN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        # Pull the whole public net through the carrier NAT. CARRIER_ROUTES are the two /25 halves of the pub
        # /24 — more specific than the pub interface's connected /24, so they win for EVERY public address
        # (coturn, rendezvous, and the far peer's srflx alike), making the double-NAT faithful end to end.
        for r in ${CARRIER_ROUTES:-}; do ip route replace "$r" via "$NAT_CARRIER_GW"; done
        echo "[nat] behind carrier $NAT_CARRIER_GW via $CAR($NAT_CAR_IP); pub routed: ${CARRIER_ROUTES:-}"
    fi

    echo "[nat] v4 nat table:"; iptables -t nat -S
    echo "[nat] v4 filter table:"; iptables -S
    return 0
}

install_v6() {
    [ -n "${NAT_WAN_IP6:-}" ] && [ -n "${NAT_LAN_IP6:-}" ] || return 1
    WAN6=$(ip -o -6 addr show | awk -v ip="$NAT_WAN_IP6" '$4 ~ "^"ip"/" {print $2; exit}')
    LAN6=$(ip -o -6 addr show | awk -v ip="$NAT_LAN_IP6" '$4 ~ "^"ip"/" {print $2; exit}')
    [ -n "$WAN6" ] && [ -n "$LAN6" ] || { echo "[nat] v6 addresses not both assigned (wan6=$NAT_WAN_IP6 lan6=$NAT_LAN_IP6) — skipping v6 block"; return 1; }
    echo "[nat] v6 ROUTER (no NAT66) profile=$NAT_PROFILE WAN6=$WAN6($NAT_WAN_IP6) LAN6=$LAN6($NAT_LAN_IP6) peer6=${PEER_IP6:-?} ice=$ICE_PORT"

    ip6tables -F
    ip6tables -P FORWARD DROP

    # No MASQUERADE — v6 hosts are globally/ULA-routable, the router just forwards + filters. LAN always
    # initiates outbound.
    ip6tables -A FORWARD -i "$LAN6" -o "$WAN6" -j ACCEPT

    if [ "${V6_FORCE_RELAY:-0}" = "1" ]; then
        # firewall-relay6 lane: drop ALL inbound v6 to the LAN EXCEPT the return path from coturn, so direct
        # and server-reflexive v6 hole-punching both fail and ICE must DISCOVER the TURN relay (network-forced
        # fallback, ice_policy=all — distinct from relay-only's policy-forced gathering). ~3 lines, as designed.
        [ -n "${COTURN_IP6:-}" ] || { echo "[nat] V6_FORCE_RELAY set but COTURN_IP6 empty" >&2; exit 1; }
        [ -n "${RENDEZVOUS_IP6:-}" ] || { echo "[nat] V6_FORCE_RELAY set but RENDEZVOUS_IP6 empty" >&2; exit 1; }
        ip6tables -A FORWARD -i "$WAN6" -o "$LAN6" -s "$COTURN_IP6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        # The rendezvous SIGNALING channel must stay reachable — this lane forces the MEDIA path onto the TURN
        # relay by blocking direct/srflx peer hole-punching, NOT by severing signaling. Without this the
        # answerer never receives the offer (return from rendezvous dropped → descriptions=0) and ICE never
        # even starts, so nothing reaches the relay to prove. The rendezvous is infra, not a peer address, so
        # allowing its return leaves the peer↔peer path (the far NAT's WAN / the far peer's ULA) still blocked
        # → relay is still network-forced.
        ip6tables -A FORWARD -i "$WAN6" -o "$LAN6" -s "$RENDEZVOUS_IP6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        echo "[nat] v6 FORCE-RELAY: WAN→LAN dropped except returns from coturn ($COTURN_IP6) + rendezvous ($RENDEZVOUS_IP6)"
    else
        # Stateful firewall baseline (== v4 port-restricted filtering): conntrack allows the return only.
        ip6tables -A FORWARD -i "$WAN6" -o "$LAN6" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        case "$NAT_PROFILE" in
          address-restricted)
            # Address-dependent filtering: record dest IPs on egress, allow return from those IPs on any port.
            # Same head-insert ordering rationale as the v4 block (the baseline ACCEPT is terminating).
            ip6tables -I FORWARD 1 -i "$LAN6" -o "$WAN6" -m recent --name seen6 --rdest --set
            ip6tables -A FORWARD -i "$WAN6" -o "$LAN6" -p udp -m recent --name seen6 --rsource --rcheck --seconds 120 -j ACCEPT
            ;;
          full-cone)
            # Endpoint-independent filtering: allow inbound UDP on the ICE port to the peer from ANY source.
            # No DNAT — the peer's own global/ULA address is the destination (no translation on v6).
            ip6tables -A FORWARD -i "$WAN6" -o "$LAN6" -p udp -d "$PEER_IP6" --dport "$ICE_PORT" -j ACCEPT
            ;;
          *)
            : # port-restricted (and any non-v6 profile that slips through) = the stateful baseline above.
            ;;
        esac
    fi

    echo "[nat] v6 filter table:"; ip6tables -S
    return 0
}

installed=0
install_v4 && installed=1
install_v6 && installed=1
[ "$installed" = "1" ] || { echo "[nat] neither a v4 nor a v6 family was assigned — nothing to install" >&2; ip -o addr show >&2; exit 1; }

exec sleep infinity
