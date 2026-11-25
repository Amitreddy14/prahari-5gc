# Architecture — Prahari-5GC

## 1. System overview

```mermaid
flowchart LR
    subgraph TB["Testbed (Docker network core: 172.22.0.0/24)"]
        UE["UERANSIM UEs"] --- GNB["UERANSIM gNB"]
        GNB -- "N2: NGAP/SCTP :38412" --> AMF
        AMF -- SBI --> NRF
        AMF -- SBI --> SMF
        SMF -- "N4: PFCP/UDP :8805" --> UPF
        ATK["Attack injector"] -.-> AMF
        ATK -.-> UPF
        ATK -.-> NRF
    end

    TB -- "mirrored packets (pcap)" --> PROBE["prahari-probe (C++20)"]
    PROBE -- "JSON Lines" --> KAFKA[("Kafka<br/>prahari.events.v1")]
    PROBE -- metrics --> PROM[("Prometheus")]
    KAFKA --> DET["Detector (Python)<br/>rules · IForest · sequence model"]
    DET -- alerts --> ALERTS[("Kafka<br/>prahari.alerts.v1")]
    ALERTS --> LLM["Triage agent<br/>(local LLM)"]
    LLM --> API["Console API (FastAPI)"]
    ALERTS --> API
    API --> UI["SOC console (React)"]
    PROM --> GRAF["Grafana"]
```

The design is **passive and one-way**: packets are copied to the probe; nothing
downstream can affect the core. A probe crash loses visibility, never service.

## 2. Components

| Component | Language / tech | Responsibility | Phase |
|---|---|---|---|
| Testbed | Open5GS v2.7.x, UERANSIM v3.2.x, MongoDB, Docker Compose | Real 5G SA core + simulated RAN; subscriber provisioning | 1 |
| Capture | tcpdump/libpcap on the `core` bridge | Copy N2/N4/SBI packets without touching the NFs | 1–2 |
| `probe/` | C++20, CMake, libpcap, nghttp2 (HPACK), librdkafka, GoogleTest, libFuzzer | Decode, correlate, pseudonymise, emit events | 0, 2, 3 |
| `schemas/` | JSON Schema 2020-12 | The event contract between C++ and Python | 0 |
| `attacks/` | Python (scapy, pycrate, httpx[h2]) | 12 attack scenarios + benign traffic profile, all labelled | 4 |
| `analytics/` | Python 3.11+, pydantic v2, scikit-learn, PyTorch | Dataset builder, detectors, streaming scorer, evaluation | 0, 4–6 |
| `triage/` | Python, Ollama (local LLM) | Turn an alert + evidence into a structured incident summary | 7 |
| `console/` | FastAPI + React/Vite (TypeScript) | Live alert timeline, drill-down, triage view | 8 |
| `deploy/` | Compose, Prometheus, Grafana | Run everything with one command; ops dashboards | 1, 8, 9 |

## 3. Data flow, one message end-to-end

1. The SMF sends a PFCP *Session Establishment Request* to the UPF (UDP 8805).
2. The capture point copies the frame. The probe reads it via libpcap.
3. Probe pipeline: link layer → IPv4/IPv6 → UDP → `pfcp::decode` → IE walk → F-SEID → session table update.
4. The probe builds a `SignallingEvent` (see `schemas/event.v1.schema.json`), hashes any SUPI with HMAC-SHA256, and produces it to Kafka.
5. The detector consumes events, updates per-UE / per-session / per-peer state and windows, and scores them.
6. Above threshold → an alert (with the evidence event IDs) goes to `prahari.alerts.v1`.
7. The triage agent reads the alert plus its evidence and writes a summary: what happened, which 3GPP procedure was abused, likely impact, suggested next step.
8. The console streams alerts and summaries to the analyst over WebSocket.

## 4. Probe internals (C++)

```
pcap source ─▶ L2/L3/L4 parse ─▶ demux by port/proto ─┬─▶ PFCP decoder  ─┐
 (live/offline)                                       ├─▶ NGAP decoder ─▶ NAS decoder
                                                      └─▶ HTTP/2 + HPACK ─┤
                                                                          ▼
                                       correlation tables (UE, SEID, stream)
                                                                          ▼
                                       event builder ─▶ JSON ─▶ sink (stdout | file | Kafka)
```

Rules every decoder follows (enforced by `rules.md` and tests):

- Input is a `std::span<const std::uint8_t>`; reads go through `ByteReader` (bounds-checked by construction).
- Malformed input returns `Result<T>` with a `DecodeError`. No exceptions, no asserts on input data.
- A malformed message is still emitted as an event with `decode_status != ok`: malformed signalling is evidence.
- Each decoder has unit tests from spec-built vectors, real-capture vectors (from Phase 2), and a libFuzzer target run in CI.

## 5. Folder structure

```
prahari-5gc/
├── PRD.md  Architecture.md  rules.md  design.md  task.md  memory.md
├── README.md  LICENSE  Makefile
├── probe/                    C++20 passive probe
│   ├── CMakeLists.txt  CMakePresets.json  cmake/
│   ├── include/prahari/      public headers (ByteReader, Result, decoders)
│   ├── src/                  implementations + main.cpp (CLI)
│   ├── tests/                GoogleTest unit tests
│   └── fuzz/                 libFuzzer targets + seed corpora
├── analytics/                Python package prahari_analytics
│   ├── src/prahari_analytics/
│   └── tests/
├── schemas/                  event contract + examples
├── testbed/                  (Phase 1) compose, Open5GS/UERANSIM configs, provisioning
├── attacks/                  (Phase 4) injector + benign generator
├── triage/                   (Phase 7) LLM triage agent
├── console/                  (Phase 8) FastAPI + React
├── deploy/                   (Phase 1+) Prometheus, Grafana, release compose
├── docs/
│   ├── adr/                  architecture decision records
│   └── threat-model.md       attack catalogue + adversary model
├── scripts/                  check-host.sh and helpers
├── docker/                   dev image
└── .devcontainer/  .github/workflows/
```

## 6. Network plan (testbed)

| Network | Subnet | Purpose |
|---|---|---|
| `core` (Docker bridge) | 172.22.0.0/24 | All NFs, gNB, injector, capture |
| UE pool (Open5GS `ogstun`) | 10.45.0.0/16 | IPs assigned to UEs' PDU sessions |

| NF | IP | Ports |
|---|---|---|
| AMF | 172.22.0.5 | NGAP 38412/sctp, SBI 7777/tcp |
| SMF | 172.22.0.7 | PFCP 8805/udp, SBI 7777/tcp |
| UPF | 172.22.0.8 | PFCP 8805/udp, GTP-U 2152/udp |
| NRF | 172.22.0.10 | SBI 7777/tcp |
| AUSF, UDM, UDR, PCF, NSSF, BSF | 172.22.0.11–16 | SBI 7777/tcp |
| MongoDB | 172.22.0.30 | 27017 (internal only, no host port) |
| gNB | 172.22.0.20 | NGAP client, GTP-U |
| UE simulator (UERANSIM) | 172.22.0.21 | UEs ×N, `uesimtunN` interfaces |
| Provisioning (one-shot) | 172.22.0.31 | — |
| Attack injector | 172.22.0.40 | — |
| Capture sidecar | host netns | tcpdump on bridge `prahari-core` |

Kafka, Prometheus and Grafana live on a separate `obs` network; only the probe joins both.

## 7. Tech stack and why

| Choice | Why | ADR |
|---|---|---|
| Open5GS + UERANSIM | Most widely used open-source 5G SA pair; 3GPP Rel-17; used by the NWDAF research we build on | 0001 |
| C++20 probe | Line-rate parsing of hostile input; the language C-DOT's core teams use; deterministic memory | 0002 |
| JSON Lines on Kafka + JSON Schema | Debuggable, language-neutral, schema-checked on both sides; binary format only if measurements demand it | 0003 |
| Python analytics | PyTorch/scikit-learn ecosystem; fast iteration on models | 0004 |
| Docker Desktop (WSL2) | Matches the dev laptop; preflight + documented fallback | 0005 |
| Local LLM (Ollama) | Signalling metadata stays on the machine; advisory-only role | 0006 |

## 8. Cross-cutting concerns

- **Privacy:** SUPI/IMSI never leaves the probe in clear (keyed hash). Raw pcaps are git-ignored.
- **Observability:** the probe exports counters (packets, decode errors per protocol, Kafka lag/drops) to Prometheus from Phase 3.
- **Reproducibility:** pinned image tags and source versions; every dataset run records `run_id`, git SHA, and attack parameters.
- **Security of Prahari itself:** console behind auth from day one; Kafka/Mongo not exposed on host ports; no secrets in the repo (`.env` git-ignored).
