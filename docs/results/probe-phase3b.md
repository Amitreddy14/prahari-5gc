# Probe results — Phase 3b (SBI over HTTP/2, Kafka, metrics)

Real testbed traffic (Open5GS v2.7.7 + UERANSIM v3.2.8, 10 UEs, laptop, 2026-11-26):
five rotated captures merged into one 45-minute file covering start-up, registration,
PDU sessions, and a full deregister/re-register wave. Recorded 2026-11-26.

## What the probe now decodes on SBI

| Layer | Coverage |
|---|---|
| TCP | Per-flow reassembly from the SYN: reordering, retransmission and overlap trimming, FIN/RST, serial-number wraparound, port reuse; bounded (256 KiB and 128 pending segments per direction, 1 MiB look-ahead, 4096 flows, 30 min idle) |
| HTTP/2 | Connection preface, all frame types, padding, CONTINUATION, SETTINGS header-table size, RST_STREAM; 1 MiB frame cap, 64 KiB header blocks, 1024 streams per connection |
| HPACK | nghttp2's inflater, one per direction (dynamic tables stay in sync even for untracked streams) |
| SBI | 3GPP service-operation names for 45 operations across NRF, AUSF, UDM, UDR, SMF, AMF, PCF, BSF, NSSF; method, sanitised path, status, service, content type; ProblemDetails cause |
| Privacy | Path identity segments → `{supi}` / `{suci}` / `{gpsi}` / `{nai}`, query dropped; bodies never emitted. IMSI from path, request body or response body is HMAC-pseudonymised |
| Correlation | One key, one pseudonym per UE on N2 (NAS SUCI), N4 (PFCP User ID IE, kept per session) and SBI; responses inherit their request's identity |

## Correctness against tshark

`probe/tools/crosscheck_tshark.py` now also compares SBI as multisets per connection
side: each request's (stream, method, sanitised path), each final response's
(stream, status), and for every request whose raw path holds a SUPI, that the event's
`supi_hash` equals the HMAC the tool computes itself.

| Capture | PFCP | NGAP (frames) | SBI req / resp | Mismatches | Identities checked / leaked |
|---|---|---|---|---|---|
| Laptop testbed, 45 min, all three interfaces | 1,091 | 280 (209) | 2,871 / 2,871 | **0** | 10 IMSIs + 10 MSINs / **0** |
| `sbi-registration.pcap` fixture | 0 | 0 | 320 / 320 | **0** | 10 / **0** |
| `n2-registration.pcap` fixture | 0 | 23 (16) | 0 | **0** | 1 / **0** |
| `n4-lifecycle.pcap` fixture | 24 | 0 | 0 | **0** | — |

All 5,742 SBI events decoded cleanly: 0 HTTP/2 or HPACK errors, 0 TCP gaps, 0 segments
mid-stream. Every one of the 65 distinct operations in the capture got a 3GPP name.

## One UE, three interfaces

With one key, each of the 10 UEs carries one pseudonym across interfaces (28 N2 + 110 SBI
+ 10 N4 events each). One UE's first 20 seconds, from events alone:

```
     0.0 ms  N2   gNB->AMF   InitialUEMessage (Registration Request, SUCI)
     3.0 ms  SBI  AMF->AUSF  Authenticate
     4.9 ms  SBI  AUSF->UDM  GenerateAuthData
 10006.4 ms  SBI  AUSF->AMF  Authenticate 504        <- UDM did not answer within 10 s
 20054.6 ms  SBI  AUSF->AMF  AuthenticateConfirm 200  (after the retry)
 20056.7 ms  SBI  AMF->UDM   Amf3GppAccessRegistration
 20063.7 ms  SBI  AMF->PCF   AMPolicyCreate
 20068.1 ms  N2   AMF->gNB   InitialContextSetupRequest
 20276.4 ms  SBI  AMF->SMF   CreateSMContext
 20284.0 ms  SBI  PCF->BSF   PcfBindingRegister
 20287.7 ms  N4   SMF->UPF   SessionEstablishmentRequest
 20292.8 ms  SBI  SMF->AMF   N1N2MessageTransfer
```

A finding about the testbed itself: at start-up, 9 of the 10 UEs' first
authentication times out together (UDM to AUSF, then AUSF to AMF: 18 × 504, all
about 11.6 s into the capture), and registration completes only on the retry, about
20 s in. The re-registration wave later has no timeouts. That start-up baseline matters
for the Phase 5 detectors.

## Throughput

`prahari-probe bench --pcap <fixture>`, release build, one core of an **Intel Xeon @
2.10 GHz** (cloud VM, 2 vCPU, noisy neighbours). Five runs each, median shown. Full
pipeline including pseudonyms and JSON for every message.

| Fixture | Median msgs/s | Range | ns/msg |
|---|---|---|---|
| N2 (`n2-registration`) | 489,337 | 461k–500k | 2,044 |
| N4 (`n4-lifecycle`) | 371,568 | 366k–391k | 2,691 |
| SBI (`sbi-registration`), TCP + HTTP/2 + HPACK | 203,313 | 195k–211k | 4,919 |

PRD target was ≥ 200k msgs/s overall; the testbed peaks at a few hundred msgs/s.

Two measured changes along the way:
- One-shot OpenSSL `HMAC()` re-fetched the algorithm and re-keyed on every call. The
  hasher now keys an `EVP_MAC` context once and clones it: SBI went from ≈165k to
  ≈203k msgs/s.
- N4 events now carry the pseudonym. An interleaved A/B (7 runs each) put that at about
  8% of N4 throughput (median 384k with, 417k without).

## Robustness

| Fuzzer | Seeds | Executions | Crashes |
|---|---|---|---|
| `fuzz_http2` (frames + HPACK, both directions, arbitrary chunking) | 11 real connections | 1,254,518 (240 s) | 0 |
| `fuzz_sbi_flow` (Ethernet/IPv4/TCP frames through the whole pipeline) | 11 real segment sequences | 90,233 (240 s) | 0 |
| `fuzz_sbi` (path sanitising, naming, body scans; aborts if an identity survives in a path) | 68 real paths and bodies | 845,725 (150 s) | 0 |
| `fuzz_frame` (re-run: TCP header now parsed) | 6 | 7,950,983 (150 s) | 0 |

118 C++ tests pass under GCC 13 (debug, release) and Clang 18 with ASan + UBSan,
including a Kafka round trip through librdkafka's in-process mock cluster (23 events
produced, acknowledged, consumed, keyed by pseudonym into one partition) and a real
socket scrape of `/metrics`. clang-tidy clean. CI runs all eight fuzzers.

## Limits

- **Probe restarts lose SBI** for connections already open (HPACK). Compose starts the
  probe before the core; after restarting only the probe, run `docker compose down && up -d`.
- Cleartext SBI only. TLS-protected SBI needs key logging or an SCP (Phase 9 topic).
- Only the first 16 KiB of each body is scanned for identities.
- The Kafka broker in the testbed is single-node and not persistent; the JSONL file is
  the durable record.
- Throughput was measured on small fixtures in a loop, not on a saturated live link.
