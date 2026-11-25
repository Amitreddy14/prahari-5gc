# memory.md — running log

Newest first. Decisions, bugs, surprises and context that the code alone does not show.

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
