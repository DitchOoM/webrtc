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

echo "[coturn] starting STUN/TURN on ${listen} realm=${TURN_REALM} user=${TURN_USER}"
exec turnserver -c "$CONF" -n
