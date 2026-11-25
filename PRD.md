# PRD — Prahari-5GC

> *Prahari* (प्रहरी): sentry. A security analytics layer that watches a 5G core's
> control plane, detects signalling attacks, and explains them.

## 1. Problem

A 5G Standalone core is a set of network functions (AMF, SMF, UPF, NRF, …) that talk
to each other and to base stations over control-plane protocols: NGAP on N2, PFCP on
N4, and HTTP/2 service-based interfaces (SBI). These interfaces carry every
registration, session setup and policy decision in the network.

Three facts make them a real attack surface:

1. **Inside-the-perimeter trust.** Many deployments rely on network isolation rather
   than per-message authentication on N2/N4. Anyone who reaches those links (a
   compromised container, a misconfigured transport network, a rogue base station)
   can speak the protocol.
2. **Cloud-native sprawl.** Network functions now run as containers that discover
   each other through the NRF. A fake or hijacked NF can register itself, scan
   others, or tear sessions down.
3. **Detection is immature.** Operators monitor KPIs, not adversarial behaviour.
   Recent work (SAGE-5GC, 2026) shows ML anomaly detectors for the 5G core lose
   accuracy sharply against attacks crafted to evade them, and there is still no
   public 5G-core attack dataset the community has agreed on.

## 2. Goal

Build an end-to-end, reproducible system that:

- runs a real 5G SA core and simulated RAN on a laptop,
- decodes its control-plane traffic passively at line rate,
- detects a defined catalogue of signalling attacks with measured accuracy and latency,
- stays useful when the attacker adapts (measured robustness, not claimed),
- explains each alert in plain language mapped to the 3GPP procedure it abuses.

## 3. Users

| User | Need | What Prahari gives them |
|---|---|---|
| NOC/SOC analyst at an operator or private-5G site | Know *that* something abnormal is happening on the core and *what* it is | Live alert timeline, per-UE/per-session drill-down, LLM-written incident summary |
| Telecom security researcher | Reproducible attacks, labelled data, honest evaluation | Attack injector, dataset builder, evaluation + adversarial harness |
| Core-network developer | Confidence their NF handles malformed and hostile signalling | Fuzz-hardened decoders, attack replays, regression captures |

## 4. Scope

### In scope

- Control plane on **N2 (NGAP + NAS-5GS)**, **N4 (PFCP)** and **SBI (HTTP/2, JSON)**.
- Open5GS core + UERANSIM gNB/UEs in Docker (see ADR-0001).
- Passive capture only. Prahari never sits inline and never drops traffic.
- 12 attack scenarios across N2, N4 and SBI (see `docs/threat-model.md`).
- Local-first: everything runs on one machine; the LLM runs locally by default.

### Out of scope (stated so the claims stay honest)

- User plane (N3/N9 GTP-U payload inspection), radio-layer attacks (jamming, RF fake base stations), roaming (N32/SEPP).
- Carrier-grade scale. Targets below are for a laptop testbed.
- Blocking or automated response. Prahari recommends; a human acts.

## 5. Features

| ID | Feature | Phase |
|---|---|---|
| F1 | Reproducible 5G SA testbed with N UEs, health checks, smoke test | 1 |
| F2 | C++ passive probe: libpcap capture, L2–L4, SCTP reassembly | 2 |
| F3 | PFCP decoder (header + key IEs) | 0 (header), 2 |
| F4 | NGAP (APER) + plain NAS-5GS decoder | 3 |
| F5 | SBI decoder: HTTP/2 frames + HPACK, NF/service mapping | 3 |
| F6 | UE/session correlation; SUPI pseudonymisation (HMAC) | 3 |
| F7 | Event export: JSON Lines → Kafka `prahari.events.v1`; Prometheus metrics | 3 |
| F8 | Attack injector (12 scenarios) + benign traffic generator | 4 |
| F9 | Labelled dataset builder + dataset card | 4 |
| F10 | Detection: rules → Isolation Forest → sequence model (PyTorch) | 5 |
| F11 | Streaming scorer + evaluation harness (precision/recall/F1, latency, FP/hour) | 5 |
| F12 | Adversarial robustness evaluation + hardening | 6 |
| F13 | LLM triage agent: local model, 3GPP-grounded, structured output | 7 |
| F14 | SOC console: FastAPI + React, live timeline, drill-down; Grafana ops view | 8 |
| F15 | PQC stretch: hybrid ML-KEM TLS on SBI + latency benchmark | 9 |

## 6. Success metrics (targets, to be replaced by measured numbers)

| Metric | Target |
|---|---|
| Probe throughput (offline pcap, one core) | ≥ 200k PFCP msgs/s; ≥ 50k NGAP msgs/s |
| Probe safety | Zero crashes in ≥ 1h fuzzing per decoder; ASan/UBSan-clean |
| Detection, in-distribution | Macro-F1 ≥ 0.90 across the attack catalogue |
| False alarms on benign traffic | ≤ 1 per hour at the chosen threshold |
| Detection latency (first attack message → alert) | p95 ≤ 2 s |
| Robustness | Report F1 drop under adaptive attacks, before vs after hardening |
| Triage faithfulness | ≥ 90% of summaries cite the correct procedure and evidence (manual eval set) |

## 7. Constraints

- Hardware: one laptop (i9-13980HX, 16 GB RAM, RTX 4060 8 GB), Windows + Docker Desktop (WSL2).
- Free and open-source components only.
- No real subscriber data, ever. Test IMSIs use the 001/01 test PLMN.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Docker Desktop kernel lacks SCTP | `scripts/check-host.sh` detects it on day 1; fallback to a WSL2 Ubuntu distro or VM (ADR-0005) |
| NGAP ASN.1 PER decoding is complex | Decode only the top-level PDU + the IEs we need; fuzz it; cross-check with tshark |
| Synthetic data inflates scores | Separate benign/attack runs, time-split evaluation, adversarial phase, publish limits |
| 16 GB RAM pressure | Cap UE count; Kafka in KRaft single-node mode; profile in Phase 1 |
