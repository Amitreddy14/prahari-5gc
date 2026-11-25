# ADR-0003: Event contract is JSON Lines on Kafka, defined by JSON Schema

- Status: Accepted
- Date: 2026-11-25

## Context
The C++ probe and the Python analytics must agree on what an event is, evolve
safely, and be debuggable by eye during development.

## Options
| Option | For | Against |
|---|---|---|
| **JSON Lines + JSON Schema** | Human-readable; schema-validated on both sides; trivial to replay from files | Larger and slower than binary |
| Protobuf / FlatBuffers | Compact and fast | Codegen in two languages; harder to inspect; premature before we measure |
| Direct function calls (one process) | Fastest | Couples C++ and Python; no replay, no fan-out |

## Decision
`schemas/event.v1.schema.json` (Draft 2020-12) is the source of truth. The probe
emits one JSON object per Kafka record on `prahari.events.v1`; it can also write
the same lines to a file for offline datasets. Python mirrors it with strict
pydantic models and a test fails if fields drift. `seid` is a decimal string
because u64 exceeds JSON's safe integer range.

Privacy: permanent identities never leave the probe in clear. SUPI is replaced by
the first 64 bits of HMAC-SHA256(key, SUPI); the key comes from the environment.

## Consequences
- If Phase 3 benchmarks show JSON is the bottleneck, we add a binary `v2` on a new topic; `v1` remains.
- Breaking changes always bump the version and topic.
