#!/bin/sh
# UPF start-up: create the ogstun interface that carries UE traffic, give it the
# UE pool's gateway address, NAT the pool out of eth0, then exec the UPF.
set -eu

UE_POOL="${UE_POOL:-10.45.0.0/16}"
UE_GW="${UE_GW:-10.45.0.1/16}"

if ! ip link show ogstun >/dev/null 2>&1; then
    ip tuntap add name ogstun mode tun
fi
ip addr replace "${UE_GW}" dev ogstun
ip link set ogstun up

# NAT is only needed for UEs to reach beyond the testbed; keep going without it.
if iptables -t nat -C POSTROUTING -s "${UE_POOL}" ! -o ogstun -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "${UE_POOL}" ! -o ogstun -j MASQUERADE; then
    echo "upf-entrypoint: NAT enabled for ${UE_POOL}"
else
    echo "upf-entrypoint: WARNING iptables NAT unavailable; UEs can reach the UPF gateway only" >&2
fi

exec open5gs-upfd -c /etc/open5gs/upf.yaml
