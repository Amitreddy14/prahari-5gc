# task.md — phases and tasks

Status: ✅ done · 🔄 in progress · ⬜ not started. Work one task at a time.

## Phase plan

| Phase | Name | Outcome | Status |
|---|---|---|---|
| 0 | Foundation | Docs, ADRs, threat model, probe + analytics skeletons, event contract, CI, dev container, preflight | 🔄 (awaiting your run + merge) |
| 1 | Testbed | Open5GS + UERANSIM from pinned source in Compose; N UEs register, open PDU sessions, ping through UPF; captures on N2/N4/SBI | ⬜ |
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
- ⬜ 0.10 **You:** run preflight on your laptop, push, open PR, CI green, merge, tag `phase-0`

## Phase 1 — Testbed (next)

- ⬜ 1.1 Dockerfiles: Open5GS v2.7.x and UERANSIM v3.2.x from pinned tags (multi-stage, non-root where possible)
- ⬜ 1.2 Compose: `core` network 172.22.0.0/24 with fixed NF IPs, MongoDB internal-only, health checks
- ⬜ 1.3 NF configs (AMF, SMF, UPF, NRF, AUSF, UDM, UDR, PCF, NSSF, BSF) for test PLMN 001/01
- ⬜ 1.4 Subscriber provisioning script (N test IMSIs, keys from env, never committed)
- ⬜ 1.5 gNB + UE configs; scale UEs by count
- ⬜ 1.6 Capture sidecar: tcpdump on the bridge, rotating pcaps for N2/N4/SBI
- ⬜ 1.7 Smoke test: all UEs registered, PDU sessions up, ping through `uesimtun0` to the UPF gateway
- ⬜ 1.8 Resource profile: RAM/CPU per NF at 10/50/100 UEs on your laptop
- ⬜ 1.9 Docs: testbed README, troubleshooting (SCTP, TUN, ports)
