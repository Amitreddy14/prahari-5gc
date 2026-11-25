# Probe results — Phase 2 (capture + PFCP)

All numbers below come from committed tools and real testbed captures
(Open5GS v2.7.7 + UERANSIM v3.2.8, 100 UEs), recorded 2026-11-25.

## Correctness against tshark

`probe/tools/crosscheck_tshark.py` compares every PFCP message field by field with
tshark 4.2: message type, sequence, endpoints, cause, Node ID, and how header SEID and
F-SEID map onto the probe's CP/UP SEIDs.

| Capture | PFCP messages | Mismatches |
|---|---|---|
| Laptop testbed, 10 → 50 → 100 UE runs (5.6 MB, 10 min) | 1,056 | **0** |
| Laptop testbed, smoke test window (0.8 MB) | 262 | **0** |
| `probe/tests/data/n4-lifecycle.pcap` fixture | 24 | **0** |

On the 5.6 MB capture the probe also counted 2,540 SCTP DATA chunks with PPID 60 (NGAP),
identical to tshark, ready for Phase 3.

## Contract

All 1,056 events from the 5.6 MB capture validate against `schemas/event.v1.schema.json`
and the strict pydantic models; event IDs are unique. Session table: 100 sessions active
at the end (matching 100 UEs); 20 events refer to sessions created before the file
started (10 deletion request/response pairs), correctly marked `session_known: false`.

## Throughput

`prahari-probe bench --pcap <5.6 MB capture> --filter "udp port 8805" --repeat 500`,
release build, **one core of an Intel Xeon @ 2.30 GHz** (cloud VM), full pipeline
including session table and JSON generation for every message:

| Run | PFCP msgs/s | ns/msg |
|---|---|---|
| 1 | 659,217 | 1,517 |
| 2 | 589,247 | 1,697 |
| 3 | 654,827 | 1,527 |

PRD target was ≥ 200k msgs/s. Run `make bench PCAP=...` on your own hardware to compare.

## Robustness

| Fuzzer | Executions (60 s) | Crashes |
|---|---|---|
| `fuzz_pfcp` (header) | 7,283,166 | 0 |
| `fuzz_pfcp_ie` (IE walker) | 5,483,779 | 0 |
| `fuzz_frame` (whole pipeline, 4 link types) | 4,154,668 | 0 |

All 55 unit/integration tests pass under GCC 13 (debug, release) and Clang 18 with
AddressSanitizer + UndefinedBehaviorSanitizer; clang-tidy clean.

## Limits

- PFCP only. NGAP/NAS (N2) and HTTP/2 SBI events arrive in Phase 3.
- IP fragments and fragmented SCTP DATA chunks are counted and skipped (none seen in the testbed).
- `session_known: false` is a signal only once the probe has seen the network from start;
  a probe started mid-stream will flag pre-existing sessions.
