# ADR-0007: Passive SBI decoding and Kafka transport

- Status: Accepted
- Date: 2026-11-26

## Context
Phase 3b adds the Service Based Interface: NF-to-NF HTTP/2 on TCP 7777, cleartext
(h2c with prior knowledge) in the Open5GS testbed. Four facts from the laptop
captures shaped the design:

1. Open5GS opens one HTTP/2 connection per NF pair and keeps it for the NF's whole
   life (NRF heartbeat connections lasted the full 45-minute capture).
2. HTTP/2 headers are HPACK-compressed with a per-connection, per-direction dynamic
   table. After the first few requests almost every header is a table reference, so a
   decoder that missed the start of a connection cannot recover it.
3. Paths and bodies carry identities: `/nudm-sdm/v2/imsi-…`, null-scheme SUCIs with
   the MSIN in clear, and SUPIs in JSON bodies.
4. The PFCP User ID IE carries the IMSI, so N4 can be tied to the same UE.

## Options
| Option | For | Against |
|---|---|---|
| **Own TCP reassembly + frame parser, nghttp2's HPACK inflater only** | Bounded, fuzzable, no full HTTP/2 state machine on a passive tap; nghttp2 is mature and already a dependency | Must see each connection from its SYN |
| nghttp2 session API (client/server callbacks) | Full protocol handling | Built for an endpoint, not a tap: it would send frames, enforce flow control, reject legal one-sided views |
| Run tshark/libwireshark | Broad protocol coverage | Heavy, GPL linkage, hard to bound or fuzz, slower |
| Heuristic resync mid-connection | Survives probe restarts | HPACK references cannot be resolved: output would be wrong, not partial |

## Decision
- **SBI**: per-flow TCP reassembly with hard bounds (256 KiB / 128 pending segments per
  direction, 1 MiB look-ahead, 4096 flows, 30 min idle expiry); decoding starts only at a
  SYN. Our own HTTP/2 frame parser (padding, CONTINUATION, SETTINGS table size, 1 MiB
  frame cap, 1024 streams per connection); header blocks go to `nghttp2_hd_inflate`,
  one inflater per direction. Any framing or HPACK error abandons that connection and
  emits one `decode_status: malformed` event. Connections seen mid-stream are counted
  (`sbi_midstream_segments`), never guessed at.
- **Start order**: Compose starts Kafka, then probe and capture, then the NRF, then the
  other NFs, so the probe sees every SBI connection open.
- **Privacy**: SBI paths keep their shape with identity segments replaced
  (`{supi}`, `{suci}`, `{gpsi}`, `{nai}`) and the query string dropped. Bodies are never
  emitted; only the IMSI (path, request body, then response body), the PDU session ID,
  and a ProblemDetails `cause` are extracted. The PFCP User ID IMSI is hashed at
  session establishment and the pseudonym kept with the session. One HMAC key, so a UE
  has the same `supi_hash` on N2, N4 and SBI.
- **Naming**: events are named by 3GPP service operation (TS 29.5xx), e.g.
  `NFDiscover`, `CreateSMContext`, `N1N2MessageTransfer`; unknown ones fall back to
  `"<METHOD> <service>"`.
- **Kafka**: librdkafka producer, idempotent (acks=all), lz4, keyed by `supi_hash` so a
  UE's events stay ordered in one partition. Produce never blocks capture: a full local
  queue drops and counts. Single-node KRaft broker on its own `obs` bridge
  (172.23.0.0/24), unreachable from the core network and so from the attack injector;
  not persistent, the JSONL file stays the durable record. Topic `prahari.events.v1`, 3 partitions, created explicitly.
- **Metrics**: Prometheus text on `/metrics` from a minimal single-threaded server that
  serves a snapshot published by the capture thread (no shared counters).

## Consequences
- Restarting only the probe loses SBI decoding for already-open connections until the
  NFs reconnect; the smoke test says so and the fix is `docker compose down && up`.
- TLS-protected SBI (production networks) would need key logging or decryption at an
  SCP; out of scope for the testbed, noted for Phase 9 (PQC TLS on SBI).
- Body inspection is limited to the first 16 KiB of each message.
