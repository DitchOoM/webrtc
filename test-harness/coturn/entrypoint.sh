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

# Append the listening/relay/external addresses per family (see turnserver.conf). coturn aborts if asked to
# listen on an address that isn't assigned, so each family's lines are added ONLY when that family is live:
# v4 unless COTURN_IP4_DISABLED=1 (v6-only lane), v6 when COTURN_IP6_ENABLED=1 (dual/v6 lane).
listen=""
if [ "${COTURN_IP4_DISABLED:-0}" != "1" ]; then
    { echo "listening-ip=${COTURN_IP}"; echo "relay-ip=${COTURN_IP}"; echo "external-ip=${COTURN_IP}"; } >> "$CONF"
    listen="${COTURN_IP}:${STUN_PORT}"
fi
if [ "${COTURN_IP6_ENABLED:-0}" = "1" ]; then
    { echo "listening-ip=${COTURN_IP6}"; echo "relay-ip=${COTURN_IP6}"; echo "external-ip=${COTURN_IP6}"; } >> "$CONF"
    listen="${listen:+$listen + }[${COTURN_IP6}]:${STUN_PORT}"
fi
# The mdns overlay (compose.mdns.yml) also parks coturn on lan0, where the mdns peer and browser reach it
# with no router in between — and they are pointed at COTURN_LAN0_IP. An explicit listening-ip list is
# exhaustive, so that address has to be named here or the lane gets no STUN at all. Gated like the others:
# coturn aborts if told to listen on an address it was not assigned.
if [ "${COTURN_LAN0_ENABLED:-0}" = "1" ]; then
    { echo "listening-ip=${COTURN_LAN0_IP}"; echo "relay-ip=${COTURN_LAN0_IP}"; echo "external-ip=${COTURN_LAN0_IP}"; } >> "$CONF"
    listen="${listen:+$listen + }${COTURN_LAN0_IP}:${STUN_PORT}"
fi

echo "[coturn] starting STUN/TURN on ${listen} realm=${TURN_REALM} user=${TURN_USER}"

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
