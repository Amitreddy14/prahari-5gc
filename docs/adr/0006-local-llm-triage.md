# ADR-0006: LLM triage runs locally and is advisory only

- Status: Accepted
- Date: 2026-11-25

## Context
Phase 7 adds an agent that explains alerts. Its input is network metadata from a
(simulated) operator network, and its output reaches an analyst.

## Decision
- Default backend: a local model served by Ollama on the RTX 4060 (a 7–8B instruct model, quantised). A hosted API is an optional, explicit opt-in via config.
- Grounding: a small knowledge base of 3GPP procedure notes written by us (not copied spec text), retrieved per alert.
- Output: JSON validated against a schema (summary, procedure, evidence event IDs, impact, suggested next step, confidence). Invalid output is rejected and shown as "triage unavailable".
- Safety: the agent has no tools that act on the network. Alert fields are inserted as data, never as instructions.

## Consequences
- Summaries are slower than a hosted frontier model but nothing leaves the machine.
- We evaluate faithfulness (does it cite the right procedure and evidence) on a fixed, hand-labelled alert set.
