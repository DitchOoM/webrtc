#!/usr/bin/env sh
# Substitute harness.env values into turnserver.conf, then exec coturn. Env comes from docker-compose's
# env_file (harness.env), so the config mirrors the single source of truth instead of duplicating ports.
set -eu

CONF=/tmp/turnserver.conf
sed \
  -e "s/__STUN_PORT__/${STUN_PORT}/g" \
  -e "s/__TURN_USER__/${TURN_USER}/g" \
  -e "s/__TURN_PASS__/${TURN_PASS}/g" \
  -e "s/__TURN_REALM__/${TURN_REALM}/g" \
  -e "s/__TURN_MIN_PORT__/${TURN_MIN_PORT}/g" \
  -e "s/__TURN_MAX_PORT__/${TURN_MAX_PORT}/g" \
  /etc/coturn/turnserver.conf > "$CONF"

# Append the listening/relay addresses per family (see turnserver.conf). coturn aborts if asked to
# listen on an address that isn't assigned, so each family's lines are added ONLY when that family is live:
# v4 unless COTURN_IP4_DISABLED=1 (v6-only lane), v6 when COTURN_IP6_ENABLED=1 (dual/v6 lane).
#
# NO `external-ip`. It is for a server behind NAT, which coturn here is not — it sits ON the public net at
# the address it relays from, so any mapping it could express is the identity. It was actively harmful:
# coturn accepts a BARE `external-ip` exactly ONCE ("ERROR: You cannot define external IP more than once in
# the configuration" — it keeps the FIRST and drops the rest), and the one it keeps is applied GLOBALLY,
# family and all. So on the dual lane the v4 address won and every IPv6 allocation was REPORTED as
# `172.30.0.10:<v6-relay-port>` — the right port on the wrong family. A peer then created a permission for
# a v4 peer on a v6 allocation and coturn refused it `443: Peer Address Family Mismatch`, which is how a
# `relay-only` dual lane failed with `AllPairsFailed` and no candidate that was ever reachable.
# Not our client's misreading — coturn's OWN client fails identically against it:
#   docker exec <coturn> turnutils_uclient -v -x -y -c -u … <v6-addr>
#     with    external-ip → "IPv4. Received relay addr: 172.40.0.10:49186" + "relay addr cannot be received"
#     without external-ip → "IPv6. Received relay addr: 2001:db8:40::10:49160" + success
# Third instance in this file's history of "the config is not what the server applied" (see `-n` below).
listen=""
if [ "${COTURN_IP4_DISABLED:-0}" != "1" ]; then
    { echo "listening-ip=${COTURN_IP}"; echo "relay-ip=${COTURN_IP}"; } >> "$CONF"
    listen="${COTURN_IP}:${STUN_PORT}"
fi
if [ "${COTURN_IP6_ENABLED:-0}" = "1" ]; then
    { echo "listening-ip=${COTURN_IP6}"; echo "relay-ip=${COTURN_IP6}"; } >> "$CONF"
    listen="${listen:+$listen + }[${COTURN_IP6}]:${STUN_PORT}"
fi
# The mdns overlay (compose.mdns.yml) also parks coturn on lan0, where the mdns peer and browser reach it
# with no router in between — and they are pointed at COTURN_LAN0_IP. An explicit listening-ip list is
# exhaustive, so that address has to be named here or the lane gets no STUN at all. Gated like the others:
# coturn aborts if told to listen on an address it was not assigned.
if [ "${COTURN_LAN0_ENABLED:-0}" = "1" ]; then
    { echo "listening-ip=${COTURN_LAN0_IP}"; echo "relay-ip=${COTURN_LAN0_IP}"; } >> "$CONF"
    listen="${listen:+$listen + }${COTURN_LAN0_IP}:${STUN_PORT}"
fi

# Per-lane TURN lifecycle directives (harness.env's TURN lifecycle block). Each is appended ONLY when the
# lane set it, so every other lane runs coturn's defaults byte-unchanged — and each one that IS set is
# echoed below, because "the setting is in the file" has never been evidence the server applied it (see the
# `-n` account further down, which cost months of an open relay). The ECHO is the check: a lane asserting a
# 438 or a 486 can read this line in `docker compose logs coturn` and know the directive was even offered.
lifecycle=""
if [ -n "${TURN_STALE_NONCE:-}" ]; then
    echo "stale-nonce=${TURN_STALE_NONCE}" >> "$CONF"
    lifecycle="${lifecycle} stale-nonce=${TURN_STALE_NONCE}"
fi
if [ -n "${TURN_MAX_ALLOCATE_LIFETIME:-}" ]; then
    echo "max-allocate-lifetime=${TURN_MAX_ALLOCATE_LIFETIME}" >> "$CONF"
    lifecycle="${lifecycle} max-allocate-lifetime=${TURN_MAX_ALLOCATE_LIFETIME}"
fi
if [ -n "${TURN_USER_QUOTA:-}" ]; then
    echo "user-quota=${TURN_USER_QUOTA}" >> "$CONF"
    lifecycle="${lifecycle} user-quota=${TURN_USER_QUOTA}"
fi

echo "[coturn] starting STUN/TURN on ${listen} realm=${TURN_REALM} user=${TURN_USER}"
echo "[coturn] lifecycle:${lifecycle:- (coturn defaults: nonce 600s, allocation 3600s, no quota)}"

# NO `-n`. In coturn `-n` means "do NOT use a configuration file" — with it, everything above (and every
# directive in turnserver.conf: lt-cred-mech, user, realm, min-port/max-port) is silently inert and the
# server runs with credential type *none*, i.e. an OPEN RELAY that accepts any allocation. Every relay
# lane was authenticating against nothing.
#
# The reason it survived review for so long: stock `coturn/coturn:4.6`'s own docker-entrypoint.sh
# re-expands its args with `eval "echo $i"`, and `echo -n` prints nothing, so `-n` is *deleted* there.
# `docker run coturn/coturn:4.6 -c cfg -n` therefore reads the config while this direct `exec` did not —
# same flags, opposite server. Repro:
#   docker run --rm --entrypoint bash coturn/coturn:4.6 -c 'i=-n; printf "[%s]\n" "$(eval "echo $i")"'  → []
#
# Symptom to watch for if it ever regresses: relay ports outside TURN_MIN_PORT..TURN_MAX_PORT in the
# gathered candidates (coturn's built-in default range is 49152-65535), which is what exposed it.
exec turnserver -c "$CONF"
