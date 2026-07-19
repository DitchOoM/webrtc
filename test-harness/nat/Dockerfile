# NAT gateway container: an Alpine router with iproute2 + iptables that connects a peer's private LAN to
# the public harness network, applying one of the four RFC 4787 NAT profiles (selected by NAT_PROFILE).
# Requires NET_ADMIN (iptables/route) and net.ipv4.ip_forward (set via compose sysctls). Multi-arch base.
FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables
COPY nat/nat-setup.sh /nat-setup.sh
COPY nat/netem.sh /netem.sh
RUN chmod +x /nat-setup.sh /netem.sh
ENTRYPOINT ["/nat-setup.sh"]
