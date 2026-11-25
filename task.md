# task.md — phases and tasks

Status: ✅ done · 🔄 in progress · ⬜ not started. Work one task at a time.

## Phase plan

| Phase | Name | Outcome | Status |
|---|---|---|---|
| 0 | Foundation | Docs, ADRs, threat model, probe + analytics skeletons, event contract, CI, dev container, preflight | ✅ tagged `phase-0` |
| 1 | Testbed | Open5GS + UERANSIM from pinned source in Compose; N UEs register, open PDU sessions, ping through UPF; captures on N2/N4/SBI | 🔄 (awaiting your run + merge) |
| 2 | Probe I: capture + PFCP | libpcap live/offline, Ethernet/SLL/IPv4/IPv6/UDP/SCTP, full PFCP IE walk, JSONL output, real-capture tests vs tshark, throughput benchmark | ⬜ |
| 3 | Probe II: NGAP, NAS, SBI, Kafka | NGAP APER top-level + key IEs, plain NAS-5GS, HTTP/2 + HPACK, correlation tables, SUPI HMAC, Kafka producer, Prometheus metrics | ⬜ |
| 4 | Attacks + dataset | 12-scenario injector with target allowlist, benign generator, labelled runs, Parquet dataset, dataset card | ⬜ |
| 5 | Detection | Rules, Isolation Forest, sequence model; streaming scorer; evaluation harness and results table | ⬜ |
| 6 | Adversarial robustness | Adaptive evasion attacks, measured degradation, hardening, paper-ready results | ⬜ |
| 7 | LLM triage | Local-LLM agent, 3GPP notes KB, schema-validated output, faithfulness eval | ⬜ |
| 8 | SOC console | FastAPI (auth, rate limits) + React timeline, drill-down, session ladder; Grafana ops dashboard | ⬜ |
| 9 | PQC + release | Hybrid ML-KEM TLS on SBI with latency benchmark; one-command release compose; README with measured results | ⬜ |

## Phase 0 — Foundation

- ✅ 0.1 Six-file scaffold: PRD, Architecture, rules, design, task, memory
- ✅ 0.2 ADRs 0001–0006
- ✅ 0.3 Threat model + 12-attack catalogue
- ✅ 0.4 Event contract v1: JSON Schema + 3 examples
- ✅ 0.5 Probe skeleton: CMake presets, strict warnings, `ByteReader`, `Result`, PFCP header decoder, CLI (`--version`, `decode-pfcp`)
- ✅ 0.6 Probe tests: 13 GoogleTest cases + 3 CLI tests; libFuzzer target + seeds
- ✅ 0.7 Analytics skeleton: pydantic event models, `supi_hash`, 17 contract tests
- ✅ 0.8 CI: lint, probe ×3 (GCC debug/release, Clang ASan+UBSan+tidy), fuzz-smoke, analytics ×2 Pythons
- ✅ 0.9 Dev container + Makefile + `scripts/check-host.sh`
- ✅ 0.10 Preflight 5/5 on the dev laptop; PR #1 merged; tagged `phase-0`

## Phase 1 — Testbed

- ✅ 1.1 Dockerfiles: Open5GS v2.7.7 and UERANSIM v3.2.8 from pinned tags, commit-verified, multi-stage, `ldd` guard, non-root NFs
- ✅ 1.2 Compose: `prahari-core` bridge 172.22.0.0/24, fixed NF IPs, MongoDB internal-only, health-gated start order
- ✅ 1.3 NF configs (NRF, AMF, SMF, UPF, AUSF, UDM, UDR, PCF, NSSF, BSF), test PLMN 001/01, direct NRF discovery (no SCP)
- ✅ 1.4 Idempotent subscriber provisioning (`provision.js`), keys from `.env`, PLMN-overflow guard
- ✅ 1.5 gNB config + UE template; UE count via `PRAHARI_UE_COUNT`
- ✅ 1.6 Capture sidecar: tcpdump on the bridge, rotating pcaps (N2/N4/SBI only)
- ✅ 1.7 `scripts/smoke.sh`: health, provisioning, NG Setup, N/N registrations, user-plane ping, capture coverage
- ✅ 1.8 `scripts/profile.sh`: CPU/RAM per container at 10/50/100 UEs → `docs/results/testbed-profile.md`
- ✅ 1.9 Testbed README with diagram, start order, troubleshooting
- ✅ 1.10 CI: `testbed-config` (compose/YAML/JS) and `testbed-e2e` (build from source + smoke test, pcaps as artifact)
- ✅ 1.11 Probe regression tests from real Open5GS PFCP traffic (Association Setup Request/Response)
- ✅ 1.12 Smoke test 6/6 on the dev laptop (10 UEs)
- ⬜ 1.13 **You:** run the profile (10/50 UEs), PR, CI green (incl. `testbed-e2e`), merge, tag `phase-1`

## Phase 2 — Probe I: capture + PFCP (next)

- ⬜ 2.1 pcap source (live interface + offline file) with libpcap, BPF filter, packet timestamps
- ⬜ 2.2 L2/L3/L4: Ethernet, Linux SLL/SLL2, VLAN, IPv4, IPv6, UDP, SCTP (DATA chunk extraction)
- ⬜ 2.3 PFCP IE walker + key IEs: Node ID, F-SEID, Cause, Recovery Time Stamp, Create/Update/Remove PDR/FAR (IDs)
- ⬜ 2.4 Session table: SEID ↔ SMF/UPF peer, establishment → deletion lifecycle
- ⬜ 2.5 Event builder: `SignallingEvent` v1 JSON, IP → NF mapping, sink to stdout/JSONL file
- ⬜ 2.6 Real-capture tests: testbed pcaps vs tshark, field by field
- ⬜ 2.7 Throughput benchmark (offline pcap, msgs/s, one core) and fuzz targets for every new decoder
