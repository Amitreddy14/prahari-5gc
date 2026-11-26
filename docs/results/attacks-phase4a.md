# Attack results — Phase 4a (injector, N4 and SBI attacks, labelling)

Every scenario was fired at **real Open5GS v2.7.7 NFs** (NRF, AUSF, UDM, NSSF, BSF, SMF,
UPF, built from the pinned tag) running natively on loopback aliases with the testbed's
own config files and addresses, with the Prahari probe capturing. No RAN in this lab
(no SCTP in the build sandbox), so the 10 "victim" sessions for N4-01/N4-02 were
created by the rogue node of N4-03; the laptop testbed has real UE sessions.
Recorded 2026-11-26.

## What each attack did

| ID | Attack | Result against Open5GS v2.7.7 | What it shows |
|---|---|---|---|
| SBI-01 | NRF reconnaissance | All 6 registered NFs mapped (addresses, services) in 2.2 s, 117 requests | Discovery is filtered by `allowedNfTypes` against the *claimed* requester type, which is unauthenticated: the scan simply claims AMF or PCF until it gets answers |
| SBI-02 | Rogue NF registration | NFRegister 201; the fake AUSF at 172.22.0.40 is returned by NFDiscover next to the real one | Anyone on the core network can insert an NF into discovery (no OAuth2/mTLS in the testbed) |
| SBI-03 | NF deregistration | Real BSF deregistered (204) and absent from discovery; the BSF noticed on its next heartbeat (404 after ~6 s) and re-registered after ~8 s | One request = ~8 s outage; repeating faster than the heartbeat keeps it down |
| SBI-04 | SBI fuzzing | 300 seeded malformed requests: 236 answered 4xx, 64 rejected at connection level; NRF still healthy after | NRF input validation held (too many query params, bad JSON, unknown versions all refused) |
| N4-04 | Rogue PFCP association | `setup`: **accepted** from an unknown node. `release` (spoofed from the SMF): ignored, "Not implemented PFCP message type[9]" | The UPF takes any peer as a control-plane node |
| N4-03 | Establishment flood | **100/100** rogue sessions created in 1 s after the rogue association; cleanup deletes them | UPF state can be allocated by anyone associated |
| N4-02 | Modification hijack | Spoofed as the SMF: FAR 1 set to DROP in every live session found by the scan (69 accepted; FAR 2 absent → MandatoryIeIncorrect) | The UPF does not check that the requester owns the session |
| N4-01 | Session deletion | Spoofed as the SMF, blind SEID scan 1-4096 at 500/s: **40/40 live sessions deleted in 8.2 s** | SEIDs are random but only from a ~4096 space (pool sized by `max.ue: 1024`) |

### Reproduced: CVE-2026-106807 (UPF crash under PFCP load)

Running N4-02 at 2,000 msg/s crashed the UPF. Characterised with spoofed N4-01
deletions of non-existent SEIDs (no sessions needed), restarting the UPF before each:

| Rate (spoofed SMF → UPF) | Messages | UPF |
|---|---|---|
| 500/s | 12,000 | alive |
| 1,000/s | 12,000 | **aborted** after 5,459 messages (~5.5 s) |
| 2,000/s | 12,000 | **aborted** |
| 3,000/s | 12,000 | **aborted** |

Each incoming PFCP request takes 3 timers for its retransmission holding period; the
timer pool (16,384, sized from `max.ue`) runs out, `ogs_pfcp_xact_remote_create()`
returns NULL, and `ogs_pfcp_xact_receive()` hits `ogs_assert(new)`: the whole UPF exits
and every PDU session with it. This matches the published
[CVE-2026-106807](https://feedly.com/cve/CVE-2026-106807) / GHSA-96p4-93rj-w6w5; upstream
`main` now returns an error instead of asserting. It was found here independently
before looking it up. The injector's N4 defaults (500/s) stay below the threshold so
ordinary runs do not take the testbed down; rates ≥ 1,000/s reproduce the CVE on purpose.

## Labelling

`python -m prahari_analytics.labels` joins probe events with run manifests: an event is
an attack event when it falls inside the run's window and involves the attacker address
(172.22.0.40) or carries one of the run's PFCP sequence numbers (reserved block
0xA00000-0xFFFFFF). On the lab capture (105,253 events, 23 runs):

- 64,377 spoofed requests bearing the **SMF's** address and 37,925 UPF answers sent to
  the real SMF were attributed to their runs by sequence marker alone.
- 0 attack-labelled events lack both the attacker address and a marker.
- Back-to-back runs (5 s apart) no longer steal each other's events: the closest
  recorded window wins, a marker always wins.
- Every labelled line validates against the schema and the strict pydantic model.

## Defects found and fixed along the way

| Where | Defect | Fix |
|---|---|---|
| Event contract | `size_bytes` capped at 65,535; an SBI-04 request with a 70 KB body broke validation | Raised to 2³²−1 (SBI bodies can be large) |
| Probe | Live capture silently lost packets in one long session (offline decode of the same packets was complete); libpcap's drop counters were not exposed | Kernel buffer raised from libpcap's 2 MiB default to 32 MiB; `prahari_probe_capture_dropped_total` and `--stats` now report drops. Re-test: 4,096 + 4,096 burst, 0 drops |
| Injector | SBI connections let the kernel pick the source address (on loopback: the NRF's own) | Bind the declared attacker address on every socket |
| Injector | Rogue PFCP node did not listen on 8805 or answer heartbeats; the UPF sent replies to 8805 and dropped the peer | Bind 8805, answer Heartbeat Requests like a real controller |
| Labeller | Overlapping run margins: the earliest run claimed the next run's events | Closest recorded window wins; sequence markers are authoritative |

## Tests

- Injector: 56 tests (allowlist incl. network/broadcast/obs/UE-pool refusals, spoofed-source
  refusal, IPv4/UDP checksums, PFCP round trip, every PFCP message decoded by the C++ probe,
  h2c against a local HTTP/2 server incl. flow control, CLI exit codes, dry runs).
- Labeller: 7 tests (attacker address, spoofed markers, windows, overlap, dry runs, partial lines).
- Probe: 119 tests on all presets (capture counters, metrics).

## Limits

- Validated against native NFs without a RAN; on the laptop testbed `attack-check.sh`
  runs the non-destructive scenarios end to end. Destructive runs (N4-01/N4-02) are
  dataset runs in Phase 4b.
- Labels mark attack *messages*; an attack's side effects in other NFs' traffic (e.g.
  the SMF re-associating after the UPF crash) stay benign in the labels and are
  measured separately in evaluation.
