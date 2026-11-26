# Probe results — Phase 3a (NGAP + NAS-5GS + SUPI pseudonyms)

Real testbed captures (Open5GS v2.7.7 + UERANSIM v3.2.8, 10 → 100 UEs, laptop,
2026-11-25) plus the committed fixtures. Recorded 2026-11-26.

## What the probe now decodes on N2

| Layer | Coverage |
|---|---|
| NGAP (APER) | NGAP-PDU choice, procedure code (names for 0–54), criticality, ProtocolIE container (≤ 256 IEs); class-1 vs class-2 direction |
| NGAP IEs | RAN-UE-NGAP-ID (85), AMF-UE-NGAP-ID (10, 40-bit), NAS-PDU (38), GlobalRANNodeID → gNB ID + bit length + PLMN (27), RANNodeName (82), UE-NGAP-IDs pair / AMF-only (114) |
| NAS-5GS | Security header types 0–4; 5GMM and 5GSM message names; Registration type; mobile identity type; SUCI null-scheme detection; Security Mode Command algorithms; 5GMM causes; UL/DL NAS Transport → inner 5GSM + PDU session ID |
| Ciphering | Per-UE NAS cipher learned from the Security Mode Command. NEA0 bodies are decoded; anything else is reported `decoded: false`, never guessed |
| Privacy | SUCI (null scheme) → IMSI → `HMAC-SHA256(key, "imsi-<IMSI>")`, first 64 bits as hex. Key from `PRAHARI_SUPI_KEY` (≥ 16 bytes); without a key, identities are **dropped**, not hashed with a default |
| UE table | Keyed by (gNB IP, RAN-UE-NGAP-ID); carries AMF ID, SUPI pseudonym, cipher; back-fills the pseudonym onto later messages; released on UEContextReleaseComplete; bounded, 1 h idle expiry |

## Correctness against tshark

`probe/tools/crosscheck_tshark.py` runs the probe and tshark 4.2 (with
`nas-5gs.null_decipher:TRUE`) on the same file and compares, per frame: every NGAP
message's procedure code and PDU type, RAN/AMF UE NGAP IDs, gNB ID and PLMN, and NAS
message types. It also greps the probe's whole output for every SUCI MSIN tshark saw.

| Capture | NGAP messages (frames) | PFCP messages | Mismatches | MSINs checked / leaked |
|---|---|---|---|---|
| Laptop testbed, 10 → 50 → 100 UE runs + smoke window | 2,682 (1,966) | 1,342 | **0** | 110 / **0** |
| `probe/tests/data/n2-registration.pcap` fixture | 23 (16) | 0 | **0** | 1 / **0** |
| `probe/tests/data/n4-lifecycle.pcap` fixture | 0 | 24 | **0** | — |

Zero NAS messages were left opaque: all of them were NEA0 after the Security Mode
Command, and the probe tracked that per UE.

C++ and Python produce the same pseudonym for the fixture UE
(`imsi-001010000000008` → `1d99cf0c73e73e98` with the test key); the Python contract
test asserts it on real probe output.

## Throughput

`prahari-probe bench --pcap <fixture> --repeat 20000`, release build, one core of an
**Intel Xeon @ 2.10 GHz** (cloud VM, 2 vCPU). Full pipeline: L2–L4, decode, session /
UE tables, SUPI HMAC, JSON for every message.

| Fixture | Run 1 | Run 2 | Run 3 | ns/msg |
|---|---|---|---|---|
| N4 (`n4-lifecycle`) msgs/s | 471,526 | 463,389 | 454,510 | ≈ 2,100–2,200 |
| N2 (`n2-registration`) msgs/s | 518,257 | 495,782 | 465,582 | ≈ 1,900–2,150 |

This host is slower than the Phase 2 host (2.3 GHz) and the fixtures are small, so
compare runs on the same machine only. PRD target is ≥ 200k msgs/s.

## Robustness

| Fuzzer | Seeds | Executions (240 s) | Crashes |
|---|---|---|---|
| `fuzz_ngap` (APER + IE walk, NAS-PDUs fed onward to NAS) | 23 real NGAP PDUs | 14,116,444 | 0 |
| `fuzz_nas` (first byte picks cipher state: none / NEA0 / NEA2) | 32 real NAS PDUs | 38,474,687 | 0 |

75 C++ tests pass under GCC 13 (debug, release) and Clang 18 with ASan + UBSan;
clang-tidy clean on `src/`. CI runs all five fuzzers for 30 s each.

## Limits

- SBI (HTTP/2), Kafka and Prometheus metrics arrive in Phase 3b.
- NAS ciphered with NEA1/2/3 is reported as protected, not decoded; the testbed uses NEA0.
- SUCI with a protection scheme (profile A/B) cannot be resolved to a SUPI by a passive
  probe; such UEs get no pseudonym until a 5G-GUTI-based mapping is added.
- N2↔N4 correlation (NGAP IDs ↔ SEIDs) needs SBI (SMF↔AMF) data and lands with 3b.
