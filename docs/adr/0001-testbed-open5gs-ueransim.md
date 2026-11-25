# ADR-0001: Testbed on Open5GS + UERANSIM, built from pinned source

- Status: Accepted
- Date: 2026-11-25

## Context
We need a real 5G Standalone core and a RAN/UE simulator that run in Docker on a
16 GB Windows laptop, speak standard NGAP/NAS/PFCP/SBI, and are widely used in
published research so results are comparable.

## Options
| Option | For | Against |
|---|---|---|
| **Open5GS + UERANSIM** | Most used open-source SA pair; C implementation; 3GPP Rel-17; light on RAM; used in NWDAF and 5GC anomaly-detection papers | AGPL-3.0 core (fine: we only talk to it over the network, never link it) |
| free5GC + UERANSIM | Go, popular in academia; used in recent continuous-time-graph detection work | Heavier; kernel GTP module (gtp5g) needed on the host, which Docker Desktop's kernel lacks |
| OAI 5GC + OAI RAN | Full stack incl. real radio | Much heavier; overkill without SDR hardware |

## Decision
Open5GS v2.7.x for the core and UERANSIM v3.2.x for gNB/UEs. We build both from
**pinned release tags** in our own Dockerfiles (Phase 1) rather than relying on
third-party images, so the exact versions are reproducible and auditable.

## Consequences
- The UPF needs `/dev/net/tun` and `NET_ADMIN`; NGAP needs SCTP in the Docker kernel (checked by `scripts/check-host.sh`).
- Our attack results are against Open5GS behaviour; we state that and avoid generalising to commercial cores.
- Switching to free5GC later only affects `testbed/`; the probe and analytics are implementation-agnostic.
