# task.md — phases and tasks

Status: ✅ done · 🔄 in progress · ⬜ not started. Work one task at a time.

## Phase plan

| Phase | Name | Outcome | Status |
|---|---|---|---|
| 0 | Foundation | Docs, ADRs, threat model, probe + analytics skeletons, event contract, CI, dev container, preflight | ✅ tagged `phase-0` |
| 1 | Testbed | Open5GS + UERANSIM from pinned source in Compose; N UEs register, open PDU sessions, ping through UPF; captures on N2/N4/SBI | ✅ PR #2, CI green |
| 2 | Probe I: capture + PFCP | libpcap live/offline, Ethernet/SLL/IPv4/IPv6/UDP/SCTP, full PFCP IE walk, JSONL output, real-capture tests vs tshark, throughput benchmark | 🔄 (awaiting your run + merge) |
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
- ✅ 1.13 Profile: 100/100 UEs, testbed ≈ 425 MB; PR #2 merged with all 10 CI jobs green

## Phase 2 — Probe I: capture + PFCP

- ✅ 2.1 `PcapSource`: libpcap live (immediate mode, ns timestamps) and offline, BPF filters, clean SIGINT/SIGTERM stop
- ✅ 2.2 L2–L4: Ethernet (+VLAN/QinQ), Linux SLL/SLL2, raw IP; IPv4 (padding trim), IPv6 (+ext headers); UDP; TCP (identify); SCTP bundled DATA chunks
- ✅ 2.3 PFCP IE walker: grouped IEs (bounded depth), Node ID (IPv4/IPv6/FQDN), F-SEID, Cause, PDR/FAR groups and IDs, vendor IEs; User ID flagged only, never copied
- ✅ 2.4 Session table: CP↔UP SEID linking keyed by receiver, establishing→active→deleted, unknown-session flag (N4-01 signal), bounded capacity, stale-establishment expiry
- ✅ 2.5 Events: schema v1 + additive `pfcp` object; UUIDv4 (seedable), IP→NF map (testbed default or `--nf-map`), JSON Lines to stdout/file
- ✅ 2.6 Real-capture verification: 1,342 PFCP messages vs tshark, 0 mismatches; 24-packet fixture committed; contract test validates real probe output in Python
- ✅ 2.7 Bench ≈ 650k PFCP msgs/s on one 2.3 GHz core; 3 fuzzers, ~17M execs, 0 crashes (`docs/results/probe-phase2.md`)
- ✅ 2.8 Probe container (non-root caps: NET_RAW + NET_ADMIN only) runs live on `prahari-core`; smoke test check 7 verifies its events
- ⬜ 2.9 **You:** rebuild, smoke 7/7, PR, CI green (incl. `probe-contract`), merge, tag `phase-2`

## Phase 3 — Probe II: NGAP, NAS, SBI, Kafka (next)

- ⬜ 3.1 NGAP APER: NGAP-PDU choice, procedure code, criticality, ProtocolIE container; key IEs (RAN/AMF UE NGAP IDs, NAS-PDU, Global RAN Node ID, Cause)
- ⬜ 3.2 NAS-5GS: security header handling; plain messages (Registration Request/Accept, Deregistration, PDU Session Establishment); SUCI/5G-GUTI handling
- ⬜ 3.3 SUPI/SUCI pseudonymisation in C++ (HMAC-SHA256, key from env), byte-identical to `supi_hash` in Python
- ⬜ 3.4 SBI: TCP stream reassembly (per flow, bounded), HTTP/2 frames, HPACK via nghttp2, method/path/status, NF-service mapping
- ⬜ 3.5 UE correlation across N2 (NGAP IDs) and N4 (SEIDs) where the data allows
- ⬜ 3.6 Kafka producer (librdkafka, `prahari.events.v1`), backpressure and drop counters; Kafka (KRaft) in compose
- ⬜ 3.7 Prometheus metrics endpoint for the probe
- ⬜ 3.8 Real-capture tests vs tshark for NGAP/NAS/SBI; fuzz targets for each decoder; benchmark
