# prahari-attacks

Attack injector for the Prahari-5GC testbed: the scenarios of
[`docs/threat-model.md`](../docs/threat-model.md), each producing a **run manifest**
that labels the probe's events for the dataset.

## Lab use only

- Every packet goes through `guard.py`. Destinations, and any spoofed source address,
  must be inside the testbed network **172.22.0.0/24**. That bound is a constant: no
  flag, variable or file widens it. A run may only *narrow* it to its declared targets.
- Nothing is sent unless `PRAHARI_LAB=1` is set (the attacker container sets it).
- `--dry-run` validates parameters and targets and writes a manifest without sending.
- `--max-seconds` (default 600) hard-stops any run.

## Run it

The attacker container joins the core network at 172.22.0.40 (the address reserved for
it in Architecture.md). It is behind a Compose profile, so `docker compose up -d` never
starts it by accident.

```bash
cd testbed
docker compose --profile attack up -d --build attacker
docker compose exec attacker prahari-attack list
docker compose exec attacker prahari-attack describe N4-01
docker compose exec attacker prahari-attack run N4-01 --param seid_count=4096
```

Manifests land in `testbed/runs/` (git-ignored).

## Scenarios (Phase 4a)

| ID | Attack | What it sends | Default |
|---|---|---|---|
| N4-01 | PFCP session deletion | Session Deletion Requests over a SEID range, spoofed from the SMF | SEIDs 1-4096, 500/s |
| N4-02 | PFCP modification hijack | Session Modification Requests setting FARs to DROP | SEIDs 1-4096, FARs 1-2 |
| N4-03 | PFCP establishment flood | Rogue association, then Session Establishment Requests | 2000 at 200/s, cleaned up |
| N4-04 | Rogue PFCP association | Association Setup from an unknown node, or Release spoofed from the SMF | setup ×3 |
| SBI-01 | NRF reconnaissance | NFListRetrieval, NFDiscover for 20 NF types, every profile | 20 req/s |
| SBI-02 | Rogue NF registration | NFRegister of a fake AUSF at the attacker's address, heartbeats | deregisters at the end |
| SBI-03 | NF deregistration | DELETE (or PATCH SUSPENDED) of a real NF's profile | victim BSF |
| SBI-04 | SBI API fuzzing | Seeded malformed methods, paths, bodies; checks the NRF survives | 300 requests |

N2 attacks (rogue gNB, registration storm, forged release, malformed NGAP) arrive in
Phase 4b.

## Manifest → labels

Each run writes `runs/<run_id>.json`: attack ID, parameters, targets, start/end time,
spoofed addresses, outcome counts, and the PFCP sequence numbers it used (from a
reserved block, 0xA00000-0xFFFFFF). The labeller in `analytics/` marks an event as
part of a run when it falls inside the run's window and either involves 172.22.0.40 or
carries one of those sequence numbers: spoofed requests and the UPF's answers to the
real SMF are both attributed exactly.
