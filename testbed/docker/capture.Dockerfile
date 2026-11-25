# Capture sidecar: records N2 (NGAP/SCTP), N4 (PFCP/UDP 8805) and SBI (HTTP/2 TCP 7777)
# from the testbed bridge into rotating pcap files. Passive: it only listens.
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
