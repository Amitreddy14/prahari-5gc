# memory.md — running log

Newest first. Decisions, bugs, surprises and context that the code alone does not show.

## 2026-11-26 — Phase 4a (attack injector: N4 + SBI, labelling)

**Decisions** (ADR-0008)
- Phase 4 split: **4a** injector framework + N4/SBI attacks + labeller; **4b** N2 attacks, benign generator, Parquet dataset.
- Injector in Python (`attacks/`, `prahari-attack`), hand-built PFCP, `h2` for SBI. Guard: constant 172.22.0.0/24 allowlist on every socket (targets *and* spoofed sources), narrow-only, plus a `PRAHARI_LAB=1` interlock. Attacker container at 172.22.0.40 (reserved since Phase 0), profile `attack`, NET_RAW only, not on `obs`.
- Labels: attacker address or reserved PFCP sequence markers (0xA00000-0xFFFFFF) inside the run window (−1 s/+5 s); markers authoritative, else closest window. Attack *effects* in other NFs' traffic stay benign.
- Validated against real Open5GS v2.7.7 NFs run natively on loopback aliases (`/opt/open5gs`, the testbed's own yaml), probe on `lo`. No SCTP in the sandbox → N2 attacks wait for 4b.

**Findings (real NF behaviour)**
- UPF accepts association from any node; creates 100/100 rogue sessions in 1 s; does not check session ownership: spoofed-SMF scans delete (40/40 in 8.2 s) or DROP-rewrite every live session. SEIDs random but in ~1-4096.
- **UPF aborts under ~1,000 PFCP msg/s** (≥5.5 k msgs): timer pool (16,384) exhausted → `ogs_assert(new)` in `ogs_pfcp_xact_receive` = **CVE-2026-106807** (GHSA-96p4-93rj-w6w5), fixed on upstream main. Reproduced independently before looking it up. Injector defaults 500/s to stay below it.
- UPF does not implement CP-side Association Release ("Not implemented PFCP message type[9]").
- NRF: no auth; discovery filters by the *claimed* requester type (lie → full map in 2.2 s); rogue AUSF registered and discoverable; deregistered BSF hidden ~8 s until its heartbeat 404s and it re-registers. NRF survived 300 fuzz requests. Open5GS NFListRetrieval uses `_links.item` (singular).

**Bugs caught**
- Schema `size_bytes` ≤ 65,535 broke on a 70 KB SBI-04 body → widened to u32.
- Probe live capture silently lost packets in a long lab session (offline decode of tcpdump's copy was complete). Now: 32 MiB pcap buffer + `prahari_probe_capture_dropped_total`; re-test 0 drops on 4,096+4,096 burst. Root cause of the original loss not proven, but loss can no longer be silent.
- Injector sockets let the kernel pick the source (loopback → NRF's own IP): now bind the attacker address. Rogue PFCP node must listen on 8805 and answer heartbeats or the UPF splits replies/drops it.
- Labeller: margins overlapped between back-to-back runs → closest-window rule.


## 2026-11-26 — Phase 3b (probe: SBI, Kafka, metrics)

**Decisions** (ADR-0007)
- SBI decoded passively: own TCP reassembly + HTTP/2 frame parser, nghttp2 only for HPACK (one inflater per direction). Starts at a SYN; never resyncs mid-connection: HPACK dynamic-table references cannot be recovered, so a guess would be wrong output, not partial output.
- Observed: Open5GS keeps NF-to-NF connections open for the NF's life (NRF heartbeats: the whole 45-min capture). So Compose now starts Kafka → probe + capture → NRF → NFs; restarting only the probe blinds SBI until `down && up`. Smoke check 10 says so.
- Events named by 3GPP service operation (45 in a table; `nudr-dr` → DRQuery/DRCreate/…; fallback "METHOD service"). `sequence` = HTTP/2 stream ID; responses carry `message_code` = status and inherit the request's identity.
- Privacy: path identity segments → `{supi}`/`{suci}`/`{gpsi}`/`{nai}`, query dropped, bodies never emitted. Null-scheme SUCI in the AMF→UDM path (`suci-0-001-01-…-<MSIN>`) was a real leak source, now resolved to the IMSI and hashed.
- Cross-interface correlation is just the pseudonym: N2 (NAS SUCI), N4 (PFCP User ID IE, hashed at establishment and kept with the session), SBI (path → request body → response body). One key ⇒ one `supi_hash` per UE everywhere.
- Kafka: librdkafka, idempotent, lz4, keyed by `supi_hash` (per-UE ordering), drop-and-count when the local queue is full (capture never blocks). Single-node KRaft broker on a separate `obs` bridge 172.23.0.0/24: the attack injector (172.22.0.40, Phase 4) cannot reach the monitoring pipeline. Not persistent; JSONL is the record.
- Metrics: capture thread renders a Prometheus snapshot each second; a minimal server thread serves it on :9464. No counters shared across threads.

**Verified (sandbox)**
- Laptop capture (45 min, merged): 2,871 requests + 2,871 responses vs tshark, 0 mismatches; every SUPI-path request's pseudonym re-computed by HMAC in the cross-check; 10 IMSIs + 10 MSINs, 0 leaked. Same file: 1,091 PFCP, 280 NGAP, 0 mismatches.
- One UE traceable N2 → SBI (AUSF/UDM/UDR/PCF/BSF/SMF) → N4 → SBI from a single pseudonym.
- 118 tests on all presets; Kafka round-trip via librdkafka's in-process mock cluster (Apache mirrors and Maven are blocked in the sandbox); `/metrics` scraped over a real socket; clang-tidy clean.
- Fuzz: http2 1.25M, sbi_flow 90k (whole pipeline from synthetic Ethernet frames), sbi 846k (aborts if an identity survives in a path), frame 7.95M: 0 crashes.
- Bench (2.1 GHz, medians of 5): N2 489k, N4 372k, SBI 203k msgs/s.

**Bugs caught**
- `nghttp2_hd_inflate_del(nullptr)` segfaults (moved-from connection): guarded.
- A SYN for a flow still marked open was treated as a retransmission, so a reused port after a lost FIN would stay undecoded for 30 min. Now only a SYN repeating the original ISN is a retransmission.
- Bench replayed identical TCP sequence numbers into one pipeline (all "retransmissions"); now clears SBI flows per pass.
- One-shot OpenSSL `HMAC()` re-fetched and re-keyed per call: N4 pseudonyms cost 13%. Pre-keyed `EVP_MAC` + dup: 8% on N4, SBI +20%.
- KRaft `CLUSTER_ID` must be a 22-char base64 UUID, not a readable name.
- Planned Kafka at 172.22.0.40 collided with the injector's reserved address; moved to the `obs` network as Architecture.md always intended.
- Test assumptions corrected from data again: the N4 fixture's UEs are …010/…002/…008 (…008 is the N2 fixture UE); unkeyed N2 events in the fixture belong to other UEs bundled in the same SCTP packets.

**Testbed finding**
- At start-up 9/10 UEs' first authentication times out together (UDM→AUSF→AMF 504 at ~11.6 s); registration succeeds on retry ~20 s in. The re-registration wave has none. Baseline for Phase 5.


## 2026-11-26 — Phase 3a (probe: NGAP + NAS-5GS)

**Decisions**
- Phase 3 split in two: **3a** NGAP + NAS + SUPI pseudonyms (unlocks the N2 attacks: registration storm, rogue gNB); **3b** SBI/HTTP2 + Kafka + metrics.
- NGAP decoded with a hand-written APER reader for the parts we need (length determinants, sized unsigned ints with 2-bit prefix for RAN IDs and 3-bit for 40-bit AMF IDs, GNB-ID bit-string packing). No asn1c dependency; unknown IEs are kept raw.
- The testbed's Security Mode Command selects **NEA0** (enc 0, int 2), so after it every NAS message has security header 2/4 but a plaintext body. The probe stores the cipher per UE and decodes NEA0 bodies; any other cipher → `decoded: false`, never guessed.
- SUPI pseudonym = first 64 bits of `HMAC-SHA256(key, "imsi-<IMSI>")`, matching Python `supi_hash` on the same string. Key from `PRAHARI_SUPI_KEY` (≥ 16 bytes). **No key → identities dropped**, not hashed with a default key.
- UE table keyed on (gNB IP, RAN-UE-NGAP-ID); AMF ID linked later; pseudonym back-filled onto later messages; released on UEContextReleaseComplete.
- Schema v1 gains optional `ngap` and `nas` objects; `ue.*` (ran/amf IDs, supi_hash, seid, pdu_session_id) replaces the flat `ue_seid`. Still additive → still v1.
- Committed a second fixture, `n2-registration.pcap` (16 frames, 23 NGAP messages, one UE: IMSI 001010000000008). Its MSIN is in the fixture; the tests assert it never reaches probe output.
- Bench output now reports per *signalling* message (PFCP + NGAP); the old `ns_per_pfcp_msg` printed `inf` (invalid JSON) on an N2-only capture.

**Verified (sandbox)**
- 2,682 NGAP messages (1,966 frames) + 1,342 PFCP vs tshark: 0 mismatches. 110 SUCI MSINs checked: 0 in probe output. 0 NAS messages opaque.
- C++ and Python agree on the pseudonym (`1d99cf0c73e73e98` for the fixture UE with the test key).
- 75 C++ tests on GCC debug/release and Clang ASan+UBSan; clang-tidy clean on `src/`.
- `fuzz_ngap` 14.1M + `fuzz_nas` 38.5M execs (240 s each, seeded from real PDUs): 0 crashes.
- Bench ≈ 450–520k msgs/s on N2 and N4 fixtures (2.1 GHz Xeon; slower host than Phase 2's).
- New smoke check (N2 registrations ≥ UE count, no N2 decode errors, no opaque NAS, no raw IMSI in events, pseudonyms present when a key is set) dry-run on fixture output, including a planted-IMSI negative test.

**Bugs caught**
- tshark does not decode NEA0-"ciphered" NAS by default, which looked like probe mismatches; the oracle needs `-o nas-5gs.null_decipher:TRUE`.
- IE 114 (UE-NGAP-IDs, inside UEContextReleaseCommand) was first unhandled, so release messages lost their UE IDs.
- A test assumed the fixture UE was MSIN …02; the capture's UE is …08. Tests now take identities from the capture, not memory.
- clang-tidy: `x = *opt` into an optional (round trip) in the NGAP ID decode; `reinterpret_cast` for OpenSSL replaced with a byte copy.

## 2026-11-25 — Phase 2 (probe: capture + PFCP)

**Decisions**
- Real laptop captures drove the design: staged `testbed/captures/core-20261125T15{1133,2133}.pcap` (1,318 PFCP messages, 170 establishments, 80 deletions, 2,540 NGAP chunks).
- PFCP header SEID is always the **receiver's** SEID (observed and per 29.244): 50 carries CP SEID in its F-SEID, 51 returns UP SEID in its F-SEID, later requests use UP SEID, responses CP SEID. Session table keys on (receiver IP, SEID) for both sides.
- Schema v1 gained an optional `pfcp` object (cp_seid, up_seid, session_state, session_known, node_id, cause_code, ie_count, pdr_count, far_count). Additive, so still v1; `ue.seid` = UP SEID when known, else CP SEID.
- PFCP User ID IE (141) carries IMSI + IMEI: only flagged present, never copied; a test asserts no IMSI reaches events.
- FAR IDs also appear inside Create PDR as references; only FAR groups count as FARs.
- Event IDs: UUIDv4 from mt19937_64 (unique, not secret); `--seed` makes output reproducible for tests/datasets.
- Committed one 24-packet fixture (`probe/tests/data/n4-lifecycle.pcap`) with a README; `.gitignore` exception scoped to that folder; rule added to `rules.md`.
- Probe container: `cap_drop: ALL`, `cap_add: NET_RAW, NET_ADMIN`, `no-new-privileges`, host network on `prahari-core`, JSONL to `testbed/events/`.
- clang-tidy: disabled `cppcoreguidelines-owning-memory` (GSL-only) and `avoid-const-or-ref-data-members` (Pipeline's Sink& is deliberate); the rest fixed in code, with commented NOLINTs for bounded recursion and the signal-handler global.

**Verified (sandbox)**
- 1,342 PFCP messages vs tshark, field by field: 0 mismatches. SCTP NGAP chunk count identical (2,540).
- 1,056 live-capture events valid against JSON Schema + pydantic; 100 sessions active = 100 UEs; 20 `session_known:false` = 10 sessions created before the capture file began.
- 55 C++ tests pass under GCC debug/release and Clang ASan+UBSan; clang-tidy clean; 3 fuzzers ~17M execs, 0 crashes.
- Bench ≈ 650k PFCP msgs/s (1.5 µs/msg incl. JSON) on one 2.3 GHz Xeon core.

**Bugs caught**
- ASan: a test decoded a temporary buffer, then read the Packet's payload span after the buffer died. Test fixed; lifetime rule documented on `decode_frame`.
- `DLT_RAW` is 12 on Linux, so an explicit `case 12` duplicated it.
- tshark `-c 1` with `-Y` stops after one *read* packet, not one match; use `head` instead.

**Verified on the laptop**
- Probe container builds and captures live on Docker Desktop (host netns, bridge `prahari-core`): 269 N4 events, all 10 sessions seen going active.
- Smoke check 7 then failed on "1 of 269 events not decoded cleanly". That event was a **half-written last line** (`"decode_status":"` then EOF), not a decode error: stdio flushed its buffer mid-event while the smoke test read the file. Fix in the probe: `StreamSink` keeps its own buffer, stdio unbuffered, writes only whole lines (64 KB batches, plus a flush every 200 ms in live mode and on idle). New test asserts the file never ends mid-line after any write. Smoke test also counts only complete `{...}` lines.

## 2026-11-25 — Phase 1 (testbed)

**Decisions**
- Pinned Open5GS **v2.7.7** (commit 318eeb49) and UERANSIM **v3.2.8** (commit ca1a66ff), the latest 2.7.x / 3.2.x tags; Dockerfiles verify the commit after cloning.
- UERANSIM built with a direct CMake call: its makefile uses the CodeBlocks generator, which newer CMake drops.
- No SCP: every NF talks to the NRF directly (`client.nrf`), fewer containers, NF→NF SBI traffic for the attacks.
- Logs to stdout (no `logger.file`) so `docker compose logs` works.
- SMF runs without freeDiameter (5G-only); Open5GS logs a harmless "No diameter configuration" warning.
- NFs run as user `open5gs` with `no-new-privileges`; only UPF and UE get `NET_ADMIN` + `/dev/net/tun`.
- Capture sidecar uses `network_mode: host` and a named bridge (`prahari-core`): a container on the bridge only sees its own unicast traffic.
- UE pool 10.45.0.0/16 on the UPF's `ogstun`; smoke test pings 10.45.0.1 through `uesimtun0`.
- Provisioning is idempotent (`replaceOne` + upsert, unique index on `imsi`) and BigInt-based (15-digit IMSIs exceed 2^53).

**Verified in the build sandbox (Ubuntu 24.04, no SCTP, no IPv6)**
- Built Open5GS v2.7.7 (3.5 min) and UERANSIM v3.2.8 (3.2 min) natively from the pinned tags.
- Ran the real NFs with these exact configs on 172.22.0.x loopback aliases: NRF + AUSF/UDM/NSSF/BSF/SMF registered; SMF↔UPF **PFCP associated**; heartbeats flowing.
- AMF reached NGAP socket creation (then needs SCTP); UDR/PCF reached DB connect (then need MongoDB); gNB reached SCTP connect; UE reached socket setup (then needs IPv6). So every config parses.
- Captured the real PFCP exchange: probe decoder agreed with tshark on all 11 messages; two added as regression tests (18 tests total).
- `docker compose config` valid; missing `.env` fails with a clear message.

**Bugs / surprises**
- Provisioning from a high IMSI base rolled over into a different MNC (001019999999999 + 1 → 00102…). Now an explicit error.
- Docker Hub is blocked from the build sandbox, so the images themselves are first built on the dev laptop and in CI.
- **First laptop build ran 1h45m without finishing.** The `build:` section sat in the shared `x-open5gs` anchor, so Compose compiled Open5GS once per NF (about 10 parallel builds) plus UERANSIM, each with `-j$(nproc)`, inside 8 GB of WSL2: swap thrash. Fix: only `nrf` builds the Open5GS image, only `gnb` builds UERANSIM, everyone else uses `pull_policy: never`; compile jobs capped by `BUILD_JOBS` (default 4); README builds images one at a time. Same root cause produced `pull access denied for prahari/ueransim` (the `ue` service tried to pull before `gnb` had built it).
- With builds fixed, Open5GS compiled in 83 s on the laptop, then the `ldd` guard failed: 186 "not found" lines. Open5GS binaries have a RUNPATH but its `.so` files do not, so `ldd` on the libraries cannot find their siblings. Reproduced in the sandbox (186 → 0) and fixed by registering the lib dir in `/etc/ld.so.conf.d/open5gs.conf` + `ldconfig`. Lesson: the guard was never exercised before shipping; build-time checks need to be run too.

**Verified on the dev laptop (Docker Desktop 29.9.3, WSL2 8 GB), 2026-11-25**
- `scripts/smoke.sh` **6/6**: 13 services healthy; 10 subscribers provisioned; NG Setup over SCTP; 10/10 UEs registered with PDU sessions; ping UE → gNB → UPF (10.45.0.1); capture recorded N2=72, N4=68, SBI=760 packets.
- Internet egress through the UPF NAT also works.
- Capture via `network_mode: host` on bridge `prahari-core` works on Docker Desktop (the one piece the sandbox could not test).
- Gotcha: `bash` typed in PowerShell is WSL's bash (no Docker); run scripts from Git Bash or `& "C:\Program Files\Git\bin\bash.exe" ...`. `smoke.sh` now fails fast with that hint.
- Resource profile (`docs/results/testbed-profile.md`): **100/100 UEs registered**; whole testbed ≈ 425 MB RAM (MongoDB ≈ 190 MB, every NF < 45 MB, UE simulator 61 MB at 100 UEs), CPU near idle at steady state. Plenty of headroom for Phase 4 attack traffic on 8 GB WSL2.
- Bug: `grep -c` prints `0` and exits 1 on no match, so `... || echo 0` produced `"0\n0"` and `[: integer expression expected` in `profile.sh` (smoke.sh had the same pattern). Fixed with a shared `ue_tunnels()` helper (`|| true` inside the container, digits-only, default 0).

## 2026-11-25 — Phase 0

**Why this project exists.** Built for a C-DOT application: C-DOT ships India's
indigenous 4G/5G core (BSNL's Bharat 4G stack) and the TRINETRA AI security
platform. Its 5G core roles ask for C/C++ on Linux and IP networking, and its
security roles ask for AI applied to threat detection and agentic SOC work.
Prahari sits where those meet.

**Decisions**
- Name: Prahari-5GC. Repo: github.com/Amitreddy14/prahari-5gc.
- Core/RAN: Open5GS v2.7.x + UERANSIM v3.2.x, built from pinned tags (ADR-0001).
- Probe in C++20, passive only; tshark used only as a test oracle (ADR-0002).
- Event contract: JSON Lines on Kafka `prahari.events.v1`, JSON Schema as source of truth; `seid` as decimal string; SUPI → HMAC-SHA256 truncated to 64 bits (ADR-0003).
- Detection layered: rules → Isolation Forest → sequence model (ADR-0004).
- Runtime: Docker Desktop WSL2 with preflight; fallback WSL2 Ubuntu + Docker Engine, then Hyper-V VM (ADR-0005).
- LLM triage local via Ollama, advisory only (ADR-0006).
- Addressing: core bridge 172.22.0.0/24 because Open5GS's UE pool defaults to 10.45.0.0/16.
- Attack IDs: `N2-xx`, `N4-xx`, `SBI-xx`, `UE-xx`.

**Bugs / surprises**
- Attack-ID regex first written as `[A-Z]{2,5}-[0-9]{2}`, which rejects `N2-01` (digit in prefix). Caught by the contract test; now `^(N2|N4|SBI|UE)-[0-9]{2}$`.
- clang-tidy flagged `h.seid = *seid` (optional → value → optional round trip) and exception escape from `main`; both fixed.
- Clang ASan link needs `libclang-rt-18-dev` on Ubuntu 24.04; added to CI and the dev image.
- pydantic strict mode rejects `str` → `UUID`/IP in Python mode but accepts it in JSON mode; tests validate through JSON, which is the real Kafka path.

**Verified (in the cloud build environment, Ubuntu 24.04)**
- Probe: GCC 13 debug + release and Clang 18 ASan/UBSan builds, zero warnings with `-Werror`; 16/16 tests pass in all three; clang-tidy clean.
- PFCP fuzzer: ~3.5M executions in 30 s, no crashes.
- Analytics: ruff, ruff format, mypy --strict clean; 17/17 tests pass.

- Preflight on the dev laptop (Git Bash): SCTP OK, NET_ADMIN OK, but `/dev/net/tun` failed because MSYS path conversion rewrote `/dev/net/tun` into a Windows path. Fixed with `MSYS_NO_PATHCONV=1` in `check-host.sh`. Docker VM memory was 5 GiB; raised via `.wslconfig`.

- Preflight re-run after both fixes: **5/5 passed** (Docker 29.9.3; SCTP, TUN, NET_ADMIN OK; Docker VM 7 GiB visible with `.wslconfig` memory=8GB, processors=8, swap=4GB). Primary runtime confirmed: Docker Desktop on WSL2, no fallback needed.
