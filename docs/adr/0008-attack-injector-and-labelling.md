# ADR-0008: Attack injector and ground-truth labelling

- Status: Accepted
- Date: 2026-11-26

## Context
Phase 4 needs attacks that real NFs actually process (not replayed captures), and
labels that are exact enough to measure detection: a label that is 2% wrong is a 2%
error floor on every metric. The injector is also the one component of Prahari that
sends hostile traffic, so it must be impossible to aim it outside the lab.

## Options
| Option | For | Against |
|---|---|---|
| **Python injector, hand-built PFCP, `h2` for SBI** | Small, readable, testable; every byte known; spoofing via raw sockets | Python speed (fine: the UPF falls over at 1,000 msg/s) |
| Scapy | Convenient packet crafting | Heavy, slow, implicit behaviour, its own PFCP layer to trust |
| Replaying captured attack pcaps | Deterministic | NFs do not react: no responses, no state changes, nothing to learn from |
| Labelling by time window only | Trivial | Benign traffic during a run is mislabelled; spoofed packets bear victims' addresses |

## Decision
- **Injector** in `attacks/` (`prahari-attack`): one scenario class per threat-model ID,
  parameters recorded, `--dry-run`, `--max-seconds`. Every socket comes from `guard.py`:
  destinations and spoofed sources must be inside the constant 172.22.0.0/24 (no flag
  widens it; runs may only narrow it to declared targets), and nothing is sent without
  `PRAHARI_LAB=1`. The attacker container (172.22.0.40, Compose profile `attack`,
  only `NET_RAW`) is on the core network but not on `obs`: attacks cannot touch Kafka.
- **Manifests**: each run writes JSON with its window, attacker address, spoofed
  addresses, outcome counts, and the PFCP sequence numbers it used, drawn from a
  reserved block (0xA00000-0xFFFFFF, random start per run).
- **Labels**: an event is an attack event if it is inside a run's window (1 s before,
  5 s after) and involves the attacker address or carries one of the run's PFCP
  sequence numbers. Markers are authoritative; otherwise the closest recorded window
  wins. Effects of an attack in other NFs' own traffic stay benign.
- **Safe defaults**: N4 rates default to 500/s, below the measured UPF crash threshold
  (CVE-2026-106807, ~1,000/s); destructive scenarios are never part of `attack-check.sh`.

## Consequences
- Labels are exact for direct attack messages, including spoofed ones, by construction.
- A future N2 injector (Phase 4b) labels by attacker address (its own SCTP association)
  in the same way; no schema change needed.
- Effects-based labels (e.g. "this benign registration failed because of the attack")
  are an evaluation concern, not a label, and are measured from outcomes.
