# task.md — phases and tasks

Status: ✅ done · 🔄 in progress · ⬜ not started. Work one task at a time.

## Phase plan

| Phase | Name | Outcome | Status |
|---|---|---|---|
| 0 | Foundation | Docs, ADRs, threat model, probe + analytics skeletons, event contract, CI, dev container, preflight | ✅ tagged `phase-0` |
| 1 | Testbed | Open5GS + UERANSIM from pinned source in Compose; N UEs register, open PDU sessions, ping through UPF; captures on N2/N4/SBI | ✅ PR #2 merged, tagged `phase-1` |
| 2 | Probe I: capture + PFCP | libpcap live/offline, Ethernet/SLL/IPv4/IPv6/UDP/SCTP, full PFCP IE walk, JSONL output, real-capture tests vs tshark, throughput benchmark | ✅ PR #3 merged, tagged `phase-2` |
| 3a | Probe II: NGAP + NAS | NGAP APER + key IEs, NAS-5GS with per-UE NEA0 tracking, SUPI HMAC in C++, UE table, N2 fixture, fuzzers | ✅ PR #4 merged, tagged `phase-3a` |
| 3b | Probe III: SBI, Kafka, metrics | TCP reassembly, HTTP/2 + HPACK, 3GPP operation names, one UE pseudonym across N2/N4/SBI, Kafka producer + broker, Prometheus metrics | ✅ PR #5 merged, tagged `phase-3b` |
| 4a | Attacks I: injector, N4 + SBI, labels | Allowlisted injector, 8 N4/SBI scenarios validated on real Open5GS, run manifests, exact labeller, attacker container | ✅ |
| 4b | Attacks II: N2 + dataset | Rogue gNB, registration storm, forged release, malformed NGAP; benign generator; campaign runner; labelled runs → Parquet + dataset card | 🔄 (awaiting your run + merge) |
| 5a | Detection I: rules + harness | Identity-free behavioural rules, evaluation harness, measured results (8/9 attacks, P=1.00, 0% FP) | 🔄 (awaiting your merge) |
| 5b | Detection II: ML layers | Isolation Forest + sequence model + ensemble (9/9, F1 0.96); streaming scorer; cross-campaign-ready harness | 🔄 (awaiting your merge) |
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
- ✅ 2.9 Smoke 7/7 on the laptop; PR #3 merged with CI green (incl. `probe-contract`); tagged `phase-2`

## Phase 3a — Probe II: NGAP + NAS-5GS

- ✅ 3a.1 NGAP APER: PDU choice, procedure code + names (0–54), criticality, ProtocolIE container (≤ 256 IEs), class-2 direction
- ✅ 3a.2 NGAP IEs: RAN/AMF UE NGAP IDs (incl. 40-bit AMF ID), NAS-PDU, GlobalRANNodeID (gNB ID + bits + PLMN), RANNodeName (sanitised), UE-NGAP-IDs (114)
- ✅ 3a.3 NAS-5GS: security headers, 5GMM/5GSM names, Registration/Deregistration/Identity Response, SUCI, Security Mode Command algorithms, causes, UL/DL NAS Transport → inner 5GSM
- ✅ 3a.4 Per-UE NAS cipher tracking: NEA0 decoded, other ciphers reported as protected
- ✅ 3a.5 SUPI pseudonyms in C++ (OpenSSL HMAC-SHA256), identical to Python `supi_hash`; key from `PRAHARI_SUPI_KEY`, identities dropped without it
- ✅ 3a.6 UE table keyed (gNB IP, RAN-UE-NGAP-ID): AMF ID, pseudonym back-fill, release on UEContextReleaseComplete, bounded with idle expiry
- ✅ 3a.7 Schema v1 + additive `ngap` / `nas` objects; pydantic models; `ue.*` replaces `ue_seid`
- ✅ 3a.8 Real-capture verification: 2,682 NGAP + 1,342 PFCP messages vs tshark, 0 mismatches, 110 MSINs, 0 leaked; 16-frame N2 fixture committed
- ✅ 3a.9 Fuzzers `fuzz_ngap` + `fuzz_nas` seeded from real PDUs: 52.6M execs, 0 crashes; 75 tests on all presets; clang-tidy clean
- ✅ 3a.10 Bench ≈ 450–520k msgs/s on N2 and N4 (`docs/results/probe-phase3a.md`)
- ✅ 3a.11 Wiring: OpenSSL in CI + probe image, `PRAHARI_SUPI_KEY` via `.env`, smoke check 8 (N2 decode + no IMSI leak), Python contract test on the N2 fixture
- ✅ 3a.12 Smoke 8/8 on the laptop (10 N2 registrations, 10 pseudonyms, 0 IMSIs leaked); PR #4 merged with CI green; tagged `phase-3a`

## Phase 3b — Probe III: SBI, Kafka, metrics

- ✅ 3b.1 TCP reassembly from the SYN: reordering, retransmission/overlap trimming, wraparound, FIN/RST, port reuse; bounded per direction and per probe
- ✅ 3b.2 HTTP/2 frame parser (padding, CONTINUATION, SETTINGS table size, RST_STREAM) + nghttp2 HPACK inflater per direction; errors abandon the connection with one `malformed` event
- ✅ 3b.3 SBI: 45 named 3GPP service operations, method/path/status/service/content type, ProblemDetails cause; identity path segments replaced, queries dropped, bodies never emitted
- ✅ 3b.4 One pseudonym per UE across N2, N4 (PFCP User ID IE, kept per session) and SBI (path / request body / response body)
- ✅ 3b.5 Real-capture verification: 2,871 + 2,871 SBI, 1,091 PFCP, 280 NGAP vs tshark, 0 mismatches, every SUPI-path pseudonym checked by HMAC; 240 KB SBI fixture committed
- ✅ 3b.6 Kafka sink (librdkafka, idempotent, lz4, keyed by pseudonym, never blocks capture); KRaft broker + topic init in Compose; tested against librdkafka's mock cluster
- ✅ 3b.7 Prometheus `/metrics` (snapshot published by the capture thread, minimal server thread)
- ✅ 3b.8 Compose start order Kafka → probe/capture → NRF → NFs, so HPACK is decodable from the first byte
- ✅ 3b.9 Fuzzers `fuzz_http2`, `fuzz_sbi`, `fuzz_sbi_flow` (whole pipeline): 0 crashes; 118 tests on all presets; clang-tidy clean
- ✅ 3b.10 Bench ≈ 203k SBI / 371k N4 / 489k N2 msgs/s; faster SUPI hasher (pre-keyed EVP_MAC) (`docs/results/probe-phase3b.md`)
- ✅ 3b.11 ADR-0007; smoke checks 10 (SBI decode, privacy, N2↔SBI linking) and 11 (Kafka offsets, metrics)
- ✅ 3b.12 Smoke 10/10 on the laptop (real Kafka broker: 1,087 events delivered, 0 dropped); PR #5 merged; tagged `phase-3b`

## Phase 4a — Attacks I: injector, N4 + SBI, labels

- ✅ 4a.1 `attacks/` package (`prahari-attack`): list/describe/run, `--dry-run`, `--max-seconds`, manifests even on failure
- ✅ 4a.2 Guard: every socket checked against the constant 172.22.0.0/24 (targets and spoofed sources), narrowing only, `PRAHARI_LAB=1` interlock
- ✅ 4a.3 PFCP encoder (association, establishment, modification, deletion, heartbeats) cross-checked by the C++ probe; raw-socket spoofing with correct IP/UDP checksums
- ✅ 4a.4 h2c client on `h2` (flow control, unvalidated mode for fuzzing), bound to the attacker address
- ✅ 4a.5 N4-01..04 and SBI-01..04, each fired at real Open5GS v2.7.7 NFs; results incl. reproduced CVE-2026-106807 (`docs/results/attacks-phase4a.md`)
- ✅ 4a.6 Labeller (`prahari_analytics.labels`): attacker address + reserved PFCP sequence markers within run windows; overlap-safe; validated output
- ✅ 4a.7 Probe: capture drop counters (`/metrics`, `--stats`), 32 MiB capture buffer; `size_bytes` widened for large SBI bodies
- ✅ 4a.8 Attacker container (172.22.0.40, profile `attack`, NET_RAW only, not on `obs`); `scripts/attack-check.sh`; CI job `attacks`; ADR-0008
- ✅ 4a.9 Rebuilt probe, `attack-check.sh` 5/5, PR #6, CI green, merged, tagged `phase-4a`

## Phase 4b — Attacks II: N2 + dataset

- ✅ 4b.1 N2-01 registration storm and N2-02 rogue gNB (NGAP from the attacker's own SCTP association, identity forged at the NGAP layer, not the IP)
- ✅ 4b.2 N2-03 forged UE context release and N2-04 malformed NGAP fuzz; NGAP/NAS via pycrate over SCTP (PPID 60), wire-compatibility proven by byte-identical round-trip of the real testbed capture + probe `decode-ngap`/`decode-nas` cross-check
- ✅ 4b.3 Benign generator (`prahari_campaign.benign`): UE churn via `nr-cli` (PDU session establish/release, status polls)
- ✅ 4b.4 Campaign runner (`prahari-campaign`): benign traffic + a timed attack schedule, one `campaign.json` tying the run manifests together
- ✅ 4b.5 Dataset build (`prahari-dataset`): labelled events → typed Parquet (40 columns) + Markdown dataset card; `scripts/dataset-run.sh`; CI asserts a non-empty, attack-labelled Parquet
- ✅ 4b.6 ADR-0009; `docs/results/attacks-phase4b.md`; threat-model N2 note; probe 0.6.0, attacker 0.2.0, analytics 0.1.0, attacks 0.2.0
- ✅ 4b.7 Rebuilt, smoke 10/10, attack-check +N2 green, dataset-run built 12,015-row Parquet, PR #7 CI green, merged

## Phase 5a — Detection I: rules + evaluation harness

- ✅ 5a.1 Identity-free behavioural features (`detect/features.py`): per-event features + sliding-window rate/fan-out trackers; the source address is a grouping key, never a feature (the label is derived from it)
- ✅ 5a.2 Rules engine (`detect/rules.py`): `malformed_decode`, `pfcp_unknown_session`, `ngap_unknown_gnb`, `sbi_unknown_operation`, per-message-type `rate_*`; thresholds calibrated from benign only, causal (runs as a streaming detector unchanged)
- ✅ 5a.3 Evaluation harness (`detect/eval.py`, `prahari-detect`): calibrate on benign-train, measure FP on held-out benign; per-run detection + latency, per-attack recall, overall P/R/F1; Markdown results table
- ✅ 5a.4 Measured on `prahari-dataset-v1`: **8/9 attacks detected, precision 1.000, F1 0.644, 0% held-out FP**, ≤0.3 s latency; SBI-02 (rogue NF registration) is an honest behavioural blind spot (needs identity allowlisting). `docs/results/detection-phase5a.md`
- ⬜ 5a.5 **You:** branch, commit, PR, CI green, merge, tag `phase-5a`

## Phase 5b — Detection II: ML layers

- ✅ 5b.1 Isolation Forest (`detect/isoforest.py`) on windowed behavioural features (`detect/windows.py`); drops zero-variance-in-benign features (they give the forest no isolation power); batched causal scoring
- ✅ 5b.2 Sequence model (`detect/sequence.py`): per-interface benign message-transition (bigram) surprisal; novel message types flagged; names the improbable transition (Markov, not LSTM — honest on one campaign; ADR-0009 note)
- ✅ 5b.3 Ensemble (`detect/ensemble.py`): rules + IF + sequence, OR-fused, per-alert layer tag — **9/9 attacks, F1 0.959, catches SBI-02 rules missed**
- ✅ 5b.4 Streaming scorer (`detect/stream.py`, `prahari-detect-stream`): calibrate once, score a live JSONL/stdin stream, emit layer-tagged alerts
- ✅ 5b.5 Harness: per-layer comparison + `evaluate_cross` (cross-campaign splits, ready for more campaigns); `docs/results/detection-phase5b.md` with honest analysis (sequence score optimistic due to benign-vocabulary narrowness)
- ⬜ 5b.6 **You:** branch, commit, PR, CI green, merge, tag `phase-5b`
- ⬜ 5b.7 (optional, strengthens 5b) generate 2–3 more campaigns (varied benign seeds) and run the cross-campaign evaluation for a generalization number
