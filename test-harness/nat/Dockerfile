# NAT gateway container: an Alpine router with iproute2 + iptables that connects a peer's private LAN to
# the public harness network, applying one of the four RFC 4787 NAT profiles (selected by NAT_PROFILE).
# Requires NET_ADMIN (iptables/route) and net.ipv4.ip_forward (set via compose sysctls). Multi-arch base.
#
# The image is also the harness's forensic-capture toolbox (design §B): `tcpdump` backs the ring-buffered
# per-scenario packet capture (the gold-standard replay input) — run in the NATs directly and, via a
# netns-sharing sidecar, over coturn; `conntrack-tools` dumps the live mapping/filtering state on failure;
# `ip6tables` installs the v6 filter chains for the routed-v6 lanes. All are inert on the green v4 path.
FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables ip6tables tcpdump conntrack-tools
COPY nat/nat-setup.sh /nat-setup.sh
COPY nat/netem.sh /netem.sh
RUN chmod +x /nat-setup.sh /netem.sh
ENTRYPOINT ["/nat-setup.sh"]
