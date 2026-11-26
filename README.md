# Prahari-5GC

**Signalling-attack detection for 5G Standalone core networks.**
A private 5G testbed (Open5GS + UERANSIM), a passive C++20 probe that decodes the
core's control plane (NGAP, NAS-5GS, PFCP, HTTP/2 SBI), and an analytics layer
that detects attacks, measures its own robustness, and explains each alert in
terms of the 3GPP procedure being abused.

> Status: **Phase 3a (probe: NGAP + NAS-5GS on N2, PFCP on N4)**. See [`task.md`](task.md) for the
> roadmap, and [`docs/results/probe-phase3a.md`](docs/results/probe-phase3a.md) and
> [`probe-phase2.md`](docs/results/probe-phase2.md) for measured results.
> Results tables will appear here only when a committed script produces them.

```mermaid
flowchart LR
    T["5G SA testbed<br/>Open5GS + UERANSIM"] -- pcap --> P["prahari-probe<br/>C++20"]
    P -- "events (JSONL)" --> K[("Kafka")]
    K --> D["Detectors<br/>rules · IForest · sequence"]
    D --> L["LLM triage<br/>(local)"]
    D --> C["SOC console"]
    L --> C
```

## Why

5G cores are containerised network functions that trust each other's signalling.
An attacker inside that perimeter (a rogue gNB, a compromised NF, an exposed N4
link) can flood the AMF, delete users' sessions on the UPF, or register a fake NF
with the NRF. Prahari watches those interfaces and catches it. Full reasoning in
[`PRD.md`](PRD.md); attack catalogue in [`docs/threat-model.md`](docs/threat-model.md).

## Repository map

| Path | What |
|---|---|
| [`probe/`](probe) | C++20 passive probe: bounds-checked decoders, GoogleTest, libFuzzer |
| [`analytics/`](analytics) | Python: event contract, detectors, evaluation |
| [`schemas/`](schemas) | Event contract v1 (JSON Schema) + examples |
| [`docs/adr/`](docs/adr) | Architecture decision records |
| [`testbed/`](testbed) | Open5GS v2.7.7 + UERANSIM v3.2.8 in Compose, capture sidecar, smoke test |
| `attacks/`, `triage/`, `console/` | Arrive in Phases 4, 7, 8 |

## Quick start

Requirements: Docker Desktop (WSL2 backend) and VS Code with the Dev Containers extension.

1. **Check your machine can run a 5G core** (SCTP, TUN, NET_ADMIN, memory), from Git Bash or WSL:
   ```bash
   bash scripts/check-host.sh
   ```
2. **Open in the dev container**: VS Code → *Reopen in Container*. The toolchain matches CI.
3. **Build and test everything:**
   ```bash
   make check          # lint, probe (ASan + release), clang-tidy, analytics
   ```
4. **Start the 5G network** (first build ~10 min) and check it end to end:
   ```bash
   cd testbed && cp .env.example .env && docker compose up -d --build && bash scripts/smoke.sh
   ```
5. **Watch the probe decode live N2 and N4 traffic** from the running testbed:
   ```bash
   tail -f testbed/events/events.jsonl
   ```
   or run it on a capture file:
   ```bash
   ./probe/build/release/prahari-probe run --pcap probe/tests/data/n4-lifecycle.pcap --stats
   PRAHARI_SUPI_KEY=prahari-test-key-0123456789abcdef \
     ./probe/build/release/prahari-probe run --pcap probe/tests/data/n2-registration.pcap
   ```

### Measured so far

| What | Result |
|---|---|
| PFCP decoding vs tshark (1,342 real messages) | 0 mismatches |
| NGAP + NAS decoding vs tshark (2,682 real messages) | 0 mismatches |
| IMSIs leaked into probe output (110 UEs' SUCIs checked) | 0 |
| Probe throughput, one core, JSON included | ~650k PFCP msgs/s (2.3 GHz); ~450–520k N2/N4 msgs/s (2.1 GHz) |
| Fuzzing (5 targets, ~70M inputs) | 0 crashes |
| Testbed footprint at 100 UEs | ~425 MB RAM |

## Engineering standards

- Probe builds with `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow … -Werror` on GCC and Clang.
- Every decoder: spec-built vectors, every-prefix truncation tests, a fuzz target run in CI.
- Event schema checked from both languages; a test fails if they drift.
- Subscriber identities never leave the probe in clear (keyed HMAC).

## Scope and honesty

This is a laptop testbed with a simulated RAN and an open-source core, not
carrier-grade equipment. Attacks run only against the local testbed. Limits of
each result are documented next to the result.

## License

MIT. Open5GS (AGPL-3.0) and UERANSIM (GPL-3.0) are used as separate programs
over the network and are not linked into this code.
