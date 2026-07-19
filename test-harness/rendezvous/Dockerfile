# UDP signaling rendezvous relay — a stateless in-memory keyed mailbox (stdlib only, no deps). Multi-arch.
FROM python:3.12-alpine
COPY rendezvous/rendezvous.py /rendezvous.py
# procps gives a real `pgrep` for the compose healthcheck (busybox pgrep lacks -f reliability).
RUN apk add --no-cache procps
ENTRYPOINT ["python3", "-u", "/rendezvous.py"]
