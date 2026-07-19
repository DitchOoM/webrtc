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
  -e "s/__COTURN_IP__/${COTURN_IP}/g" \
  /etc/coturn/turnserver.conf > "$CONF"

echo "[coturn] starting STUN/TURN on ${COTURN_IP}:${STUN_PORT} realm=${TURN_REALM} user=${TURN_USER}"
exec turnserver -c "$CONF" -n
