# memory.md — running log

Newest first. Decisions, bugs, surprises and context that the code alone does not show.

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
