# ADR-0002: A passive probe written in C++20

- Status: Accepted
- Date: 2026-11-25

## Context
Something must turn raw packets on N2/N4/SBI into structured events. It parses
attacker-controlled bytes at high rates, so it must be fast and memory-safe in practice.

## Options
| Option | For | Against |
|---|---|---|
| **Custom C++20 probe on libpcap** | Line-rate, full control over decoding and correlation; C/C++ on Linux is what telecom core teams (incl. C-DOT) build in | We own the decoders, so we must fuzz them |
| tshark/Wireshark dissectors piped to Python | Complete protocol coverage instantly | Slow, heavy, hard to correlate state; becomes a wrapper project, not engineering |
| Python (scapy/pycrate) | Quick to write | Orders of magnitude slower; not credible for a probe |
| Inline (proxy) placement | Could block attacks | Can break the core; out of scope (PRD) |

## Decision
A passive C++20 probe using libpcap for capture, our own decoders for PFCP and
NGAP top-level/IEs we need, nghttp2's HPACK for SBI headers, and librdkafka for export.
Decoders go through a bounds-checked `ByteReader` and return `Result<T>`. Every
decoder has a libFuzzer target in CI. tshark is used only as a **test oracle**.

## Consequences
- Strict compiler warnings, ASan/UBSan and clang-tidy gate every PR.
- NGAP's ASN.1 APER is only decoded as far as we need (procedure code, criticality, IE list, key IEs); full ASN.1 is a non-goal.
- Encrypted NAS (after Security Mode Command) is opaque to us; detection relies on the NGAP layer and plain NAS messages. This is a stated limit.
